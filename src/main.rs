#![forbid(unsafe_code)]

mod config;
mod limits;
mod protocol;
mod recovery_prototype;
mod storage;

use std::env;
use std::future::IntoFuture;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, FromRequest, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use limits::{LimitError, RateLimiter};
use protocol::{
    ApiError, BackupStream, DELETE_ACTION, DESCRIPTOR_VERSION, DeleteRequest, DescriptorApiError,
    DescriptorLookupRequest, DescriptorLookupResponse, DescriptorRecordView, FETCH_ACTION,
    FetchRequest, FetchResponse, MutationResponse, RateLimitKind, SMALL_BODY_LIMIT_BYTES,
    STORE_ACTION, StoreDescriptorRequest, StoreDescriptorResponse, StoreRequest, VERSION,
    canonical_lookup_tokens, compute_etag, decode_canonical_hex, decode_ciphertext,
    decode_descriptor_ciphertext, decode_descriptor_cursor, decode_descriptor_hex,
    encode_descriptor_cursor, private_no_store, unix_time, validate_descriptor_version,
    validate_generation, validate_version, verify_descriptor_signature, verify_request_signature,
};
use sha2::{Digest, Sha256};
use storage::{
    CallError, DescriptorLookupBounds, DescriptorLookupCursor, DescriptorMetricsSnapshot,
    DescriptorStoreOutcome, MutationOutcome, Storage, StorageConfig, StorageMetricsSnapshot,
    StorageOwner,
};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;

const REQUEST_TOTALS: usize = 15;
// Not configurable: the checked Nginx configuration overwrites exactly this header.
const SOURCE_IDENTITY_HEADER: &str = "x-real-ip";

#[derive(Clone)]
struct AppState {
    recovery: Option<recovery_prototype::RecoveryPolicy>,
    storage: Storage,
    limiter: RateLimiter,
    fetch_in_flight: Arc<Semaphore>,
    store_in_flight: Arc<Semaphore>,
    delete_in_flight: Arc<Semaphore>,
    descriptor_store_in_flight: Arc<Semaphore>,
    descriptor_lookup_in_flight: Arc<Semaphore>,
    accepted_ciphertext_bytes: usize,
    accepted_descriptor_ciphertext_bytes: usize,
    descriptor_lookup_bounds: DescriptorLookupBounds,
    saturation_retry_after_secs: u64,
    admission_retry_after_secs: u64,
    request_totals: Arc<RequestTotals>,
    descriptor_totals: Arc<DescriptorTotals>,
}

struct RequestTotals {
    counts: [AtomicU64; REQUEST_TOTALS],
    interval: Duration,
}

#[derive(Clone, Copy)]
enum RequestOperation {
    Fetch,
    Store,
    Delete,
}

impl RequestTotals {
    fn new(interval: Duration) -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            interval,
        }
    }

    fn record<T>(&self, operation: RequestOperation, result: &Result<T, ApiError>) {
        let index = match result {
            Ok(_) => 0,
            Err(ApiError::InvalidRequest(_)) => 1,
            Err(ApiError::Authentication) => 2,
            Err(ApiError::HeadConflict) => 3,
            Err(ApiError::BlobTooLarge) => 4,
            Err(ApiError::RateLimited { .. }) => 5,
            Err(ApiError::Capacity) => 6,
            Err(ApiError::Internal) => 7,
        };
        let _ = self.counts[index].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(1))
        });
        if let Err(ApiError::RateLimited { kind, .. }) = result {
            let subtype = match kind {
                RateLimitKind::Npub => 8,
                RateLimitKind::Overflow => 9,
                RateLimitKind::Saturation => 10,
                RateLimitKind::Admission => 11,
            };
            let _ =
                self.counts[subtype].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_add(1))
                });
        }
        let operation_index = match operation {
            RequestOperation::Fetch => 12,
            RequestOperation::Store => 13,
            RequestOperation::Delete => 14,
        };
        let _ = self.counts[operation_index].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_add(1)),
        );
    }

    fn take(&self) -> [u64; REQUEST_TOTALS] {
        std::array::from_fn(|index| self.counts[index].swap(0, Ordering::Relaxed))
    }

    fn emit(&self, storage: StorageMetricsSnapshot) {
        let counts = self.take();
        tracing::info!(
            event = "wallet_backup_request_totals",
            interval_seconds = self.interval.as_secs(),
            success = counts[0],
            backup_invalid_request = counts[1],
            backup_auth_error = counts[2],
            backup_head_conflict = counts[3],
            backup_blob_too_large = counts[4],
            rate_limited = counts[5],
            backup_capacity_exceeded = counts[6],
            internal_error = counts[7],
            rate_limited_npub = counts[8],
            rate_limited_overflow = counts[9],
            rate_limited_saturation = counts[10],
            rate_limited_admission = counts[11],
            fetch_requests = counts[12],
            store_requests = counts[13],
            delete_requests = counts[14],
            new_heads_admitted = storage.new_heads_admitted,
            new_allocation_bytes_admitted = storage.new_allocation_bytes_admitted,
            existing_head_growth_bytes_admitted = storage.existing_head_growth_bytes_admitted,
            current_heads = storage.current_heads,
            current_live_bytes = storage.current_live_bytes,
            "wallet backup request totals"
        );
    }
}

const DESCRIPTOR_TOTALS: usize = 15;

struct DescriptorTotals {
    counts: [AtomicU64; DESCRIPTOR_TOTALS],
    interval: Duration,
}

#[derive(Clone, Copy)]
enum DescriptorOperation {
    Store,
    Lookup,
}

impl DescriptorTotals {
    fn new(interval: Duration) -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            interval,
        }
    }

    fn record<T>(&self, operation: DescriptorOperation, result: &Result<T, DescriptorApiError>) {
        let index = match result {
            Ok(_) => 0,
            Err(DescriptorApiError::InvalidRequest(_)) => 1,
            Err(DescriptorApiError::Authentication) => 2,
            Err(DescriptorApiError::RecordConflict) => 3,
            Err(DescriptorApiError::PublisherQuota) => 4,
            Err(DescriptorApiError::BlobTooLarge) => 5,
            Err(DescriptorApiError::RateLimited { .. }) => 6,
            Err(DescriptorApiError::Capacity) => 7,
            Err(DescriptorApiError::Internal) => 8,
        };
        bump(&self.counts[index]);
        if let Err(DescriptorApiError::RateLimited { kind, .. }) = result {
            let subtype = match kind {
                RateLimitKind::Npub => 9,
                RateLimitKind::Overflow => 10,
                RateLimitKind::Saturation => 11,
                RateLimitKind::Admission => 12,
            };
            bump(&self.counts[subtype]);
        }
        let operation_index = match operation {
            DescriptorOperation::Store => 13,
            DescriptorOperation::Lookup => 14,
        };
        bump(&self.counts[operation_index]);
    }

    fn take(&self) -> [u64; DESCRIPTOR_TOTALS] {
        std::array::from_fn(|index| self.counts[index].swap(0, Ordering::Relaxed))
    }

    fn emit(&self, storage: DescriptorMetricsSnapshot) {
        let counts = self.take();
        tracing::info!(
            event = "descriptor_backup_request_totals",
            interval_seconds = self.interval.as_secs(),
            success = counts[0],
            descriptor_invalid_request = counts[1],
            descriptor_auth_error = counts[2],
            descriptor_record_conflict = counts[3],
            descriptor_publisher_quota = counts[4],
            descriptor_blob_too_large = counts[5],
            rate_limited = counts[6],
            descriptor_capacity_exceeded = counts[7],
            internal_error = counts[8],
            rate_limited_npub = counts[9],
            rate_limited_overflow = counts[10],
            rate_limited_saturation = counts[11],
            rate_limited_admission = counts[12],
            store_requests = counts[13],
            lookup_requests = counts[14],
            records_admitted = storage.records_admitted,
            record_bytes_admitted = storage.record_bytes_admitted,
            current_records = storage.current_records,
            current_bytes = storage.current_bytes,
            "descriptor backup request totals"
        );
    }
}

fn bump(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if let Err(error) = init_logging() {
        eprintln!("startup failed: {error}");
        return ExitCode::FAILURE;
    }
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(event = "process_failed", reason = %error, "backup server failed");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let mut arguments = env::args_os();
    drop(arguments.next());
    let command = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(usage)?;
    match command.as_str() {
        "serve" => {
            if arguments.next().is_some() {
                return Err(usage());
            }
            serve(config::Config::from_env()?).await
        }
        "import-recovery" => {
            let source = next_path(&mut arguments)?;
            if arguments.next().is_some() {
                return Err(usage());
            }
            let config = config::Config::from_env()?;
            let policy = config
                .recovery
                .clone()
                .ok_or("import requires recovery configuration")?;
            let owner = StorageOwner::start(storage_config(&config))?;
            let result = owner.client().import_recovery(source, policy).await;
            owner.shutdown().await?;
            let report = result.map_err(|_| "recovery import failed; verify the offline source, configured origin/publisher and destination capacity; target records must be empty or identical")?;
            println!(
                "imported recovery: records={} bytes={} recovery_sha256={}",
                report.recovery_records, report.recovery_bytes, report.recovery_sha256
            );
            Ok(())
        }
        "verify-backup" => {
            let path = next_path(&mut arguments)?;
            if arguments.next().is_some() {
                return Err(usage());
            }
            let report = storage::verify_backup(&path)?;
            println!(
                "verified backup: heads={} live_bytes={} descriptor_records={} descriptor_bytes={} recovery_records={} recovery_bytes={} recovery_sha256={} aggregate_sha256={}",
                report.heads,
                report.live_bytes,
                report.descriptor_records,
                report.descriptor_bytes,
                report.recovery_records,
                report.recovery_bytes,
                report.recovery_sha256,
                report.aggregate_sha256
            );
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: backup-server serve | verify-backup <absolute-path> | import-recovery <absolute-offline-source>".to_owned()
}

fn next_path(arguments: &mut impl Iterator<Item = std::ffi::OsString>) -> Result<PathBuf, String> {
    arguments.next().map(PathBuf::from).ok_or_else(usage)
}

fn init_logging() -> Result<(), String> {
    let level = match config::log_level()?.as_str() {
        "error" => tracing::Level::ERROR,
        "warn" => tracing::Level::WARN,
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => return Err("BACKUP_SERVER_LOG must be error, warn, info, debug, or trace".to_owned()),
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .try_init()
        .map_err(|_| "failed to initialize logging".to_owned())
}

fn storage_config(config: &config::Config) -> StorageConfig {
    StorageConfig {
        path: config.db_path.clone(),
        queue_depth: config.storage_queue_depth,
        busy_timeout: config.busy_timeout,
        max_live_bytes: config.max_live_bytes,
        max_heads: config.max_heads,
        max_descriptor_records: config.max_descriptor_records,
        max_descriptor_records_per_publisher: config.max_descriptor_records_per_publisher,
        admission: config.admission,
    }
}

async fn serve(config: config::Config) -> Result<(), String> {
    let limiter = RateLimiter::new(config.limiter)?;
    let request_totals = Arc::new(RequestTotals::new(config.request_totals_interval));
    let descriptor_totals = Arc::new(DescriptorTotals::new(config.request_totals_interval));
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|_| "failed to bind loopback listener".to_owned())?;
    let owner = StorageOwner::start(storage_config(&config))?;
    let storage = owner.client();
    let state = AppState {
        recovery: config.recovery.clone(),
        storage: storage.clone(),
        limiter,
        fetch_in_flight: Arc::new(Semaphore::new(config.fetch_max_in_flight)),
        store_in_flight: Arc::new(Semaphore::new(config.store_max_in_flight)),
        delete_in_flight: Arc::new(Semaphore::new(config.delete_max_in_flight)),
        descriptor_store_in_flight: Arc::new(Semaphore::new(config.descriptor_store_max_in_flight)),
        descriptor_lookup_in_flight: Arc::new(Semaphore::new(
            config.descriptor_lookup_max_in_flight,
        )),
        accepted_ciphertext_bytes: config.accepted_ciphertext_bytes,
        accepted_descriptor_ciphertext_bytes: config.accepted_descriptor_ciphertext_bytes,
        descriptor_lookup_bounds: DescriptorLookupBounds {
            record_cap: config.descriptor_lookup_record_cap,
            byte_budget: config.descriptor_lookup_max_bytes,
        },
        saturation_retry_after_secs: config.saturation_retry_after_secs,
        admission_retry_after_secs: config.admission_retry_after_secs,
        request_totals: Arc::clone(&request_totals),
        descriptor_totals: Arc::clone(&descriptor_totals),
    };
    let router = router(
        state,
        config.store_body_limit_bytes,
        config.descriptor_store_body_limit_bytes,
    );
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let cleanup = tokio::spawn(cleanup_loop(
        storage.clone(),
        shutdown_receiver.clone(),
        config.cleanup_interval,
        config.tombstone_retention,
        config.cleanup_batch_size,
    ));
    let totals = tokio::spawn(request_totals_loop(
        request_totals,
        descriptor_totals,
        storage,
        shutdown_receiver.clone(),
    ));
    let server = axum::serve(listener, router)
        .with_graceful_shutdown(wait_for_shutdown(shutdown_receiver))
        .into_future();
    tokio::pin!(server);
    let server_result = tokio::select! {
        result = &mut server => result.map_err(|_| "HTTP server failed".to_owned()),
        signal = shutdown_signal() => {
            let notified = shutdown_sender
                .send(true)
                .map_err(|_| "failed to signal graceful shutdown".to_owned());
            let drained = match tokio::time::timeout(config.shutdown_timeout, &mut server).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err("HTTP server failed during shutdown".to_owned()),
                Err(_) => Err("HTTP graceful shutdown timed out".to_owned()),
            };
            signal.and(notified).and(drained)
        }
    };
    if !*shutdown_sender.borrow() && shutdown_sender.send(true).is_err() {
        tracing::warn!(
            event = "maintenance_stop_failed",
            "maintenance task stop signal failed"
        );
    }
    let (cleanup_result, totals_result) = tokio::join!(
        stop_task("cleanup", config.shutdown_timeout, cleanup),
        stop_task("request totals", config.shutdown_timeout, totals)
    );
    cleanup_result?;
    totals_result?;
    tokio::time::timeout(config.shutdown_timeout, owner.shutdown())
        .await
        .map_err(|_| "SQLite shutdown timed out".to_owned())??;
    server_result
}

async fn stop_task(
    name: &'static str,
    timeout: Duration,
    mut task: JoinHandle<()>,
) -> Result<(), String> {
    match tokio::time::timeout(timeout, &mut task).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(format!("{name} task failed")),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(format!("{name} task shutdown timed out"))
        }
    }
}

fn router(
    state: AppState,
    store_body_limit_bytes: usize,
    descriptor_store_body_limit_bytes: usize,
) -> Router {
    Router::new()
        .route(
            "/api/v1/wallet-backups/fetch",
            post(fetch).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/v1/wallet-backups",
            put(store).layer(DefaultBodyLimit::max(store_body_limit_bytes)),
        )
        .route(
            "/api/v1/wallet-backups",
            delete(delete_backup).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/v1/descriptor-backups",
            post(store_descriptor).layer(DefaultBodyLimit::max(descriptor_store_body_limit_bytes)),
        )
        .route(
            "/api/v1/descriptor-backups/lookup",
            post(lookup_descriptors).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT_BYTES)),
        )
        .route("/healthz", get(health))
        .route(
            "/api/v1/arkade-recovery-records",
            post(store_recovery).layer(DefaultBodyLimit::max(192 * 1024)),
        )
        .route(
            "/api/v1/arkade-recovery-records/fetch",
            post(fetch_recovery).layer(DefaultBodyLimit::max(4096)),
        )
        .with_state(state)
}

fn recovery_storage_error(error: CallError) -> recovery_prototype::Error {
    recovery_prototype::Error(match error {
        CallError::QueueFull => StatusCode::TOO_MANY_REQUESTS,
        CallError::Unavailable | CallError::Storage => StatusCode::SERVICE_UNAVAILABLE,
    })
}

async fn store_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, recovery_prototype::Error> {
    use recovery_prototype::Error;
    let policy = state.recovery.clone().ok_or(Error(StatusCode::NOT_FOUND))?;
    let _permit = state
        .store_in_flight
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::TOO_MANY_REQUESTS))?;
    source_identity(&headers).map_err(|_| Error(StatusCode::BAD_REQUEST))?;
    let Json(request) = Json::<recovery_prototype::StoreRequest>::from_request(request, &state)
        .await
        .map_err(|e| Error(e.status()))?;
    let clock = unix_time().map_err(|_| Error(StatusCode::INTERNAL_SERVER_ERROR))?;
    recovery_prototype::validate_store(&policy, &request, clock)?;
    let author = decode_canonical_hex::<32>(&request.grant.owner, "invalid recovery owner")
        .map_err(|_| Error(StatusCode::BAD_REQUEST))?;
    state
        .limiter
        .check_recovery_store_npub(&author)
        .map_err(|_| Error(StatusCode::TOO_MANY_REQUESTS))?;
    let receipt = state
        .storage
        .store_recovery(policy, request, clock)
        .await
        .map_err(recovery_storage_error)??;
    Ok(private_no_store(Json(receipt).into_response()))
}

async fn fetch_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, recovery_prototype::Error> {
    use recovery_prototype::Error;
    state
        .recovery
        .as_ref()
        .ok_or(Error(StatusCode::NOT_FOUND))?;
    let _permit = state
        .fetch_in_flight
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::TOO_MANY_REQUESTS))?;
    source_identity(&headers).map_err(|_| Error(StatusCode::BAD_REQUEST))?;
    let Json(request) = Json::<recovery_prototype::FetchRequest>::from_request(request, &state)
        .await
        .map_err(|e| Error(e.status()))?;
    let clock = unix_time().map_err(|_| Error(StatusCode::INTERNAL_SERVER_ERROR))?;
    recovery_prototype::validate_fetch(&request, clock)?;
    let owner = request.owner.clone();
    let page = state
        .storage
        .fetch_recovery(request, clock)
        .await
        .map_err(recovery_storage_error)??;
    let author = decode_canonical_hex::<32>(&owner, "invalid recovery owner")
        .map_err(|_| Error(StatusCode::BAD_REQUEST))?;
    if !page.records.is_empty() {
        state
            .limiter
            .check_recovery_fetch_npub(&author)
            .map_err(|_| Error(StatusCode::TOO_MANY_REQUESTS))?;
    }
    Ok(private_no_store(Json(page).into_response()))
}

async fn wait_for_shutdown(mut receiver: watch::Receiver<bool>) {
    while !*receiver.borrow() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
}

async fn shutdown_signal() -> Result<(), String> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "failed to install SIGTERM handler".to_owned())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map_err(|_| "failed to receive SIGINT".to_owned())?;
        }
        value = terminate.recv() => {
            if value.is_none() {
                return Err("SIGTERM handler stopped".to_owned());
            }
        }
    }
    Ok(())
}

async fn cleanup_loop(
    storage: Storage,
    mut shutdown: watch::Receiver<bool>,
    interval: std::time::Duration,
    retention: std::time::Duration,
    batch_size: u64,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                let result = unix_time()
                    .and_then(|now| i64::try_from(now).map_err(|_| ApiError::Internal))
                    .and_then(|now| {
                        let retention = i64::try_from(retention.as_secs())
                            .map_err(|_| ApiError::Internal)?;
                        now.checked_sub(retention).ok_or(ApiError::Internal)
                    });
                if let Ok(cutoff) = result {
                    match storage.cleanup(cutoff, batch_size).await {
                        Ok(removed) if removed > 0 => tracing::info!(
                            event = "wallet_backup_tombstones_cleaned",
                            removed,
                            "expired wallet backup tombstones removed"
                        ),
                        Ok(_) => {}
                        Err(_) => tracing::error!(
                            event = "wallet_backup_tombstone_cleanup_failed",
                            "wallet backup tombstone cleanup failed"
                        ),
                    }
                } else {
                    tracing::error!(
                        event = "wallet_backup_clock_failed",
                        "system clock is unavailable"
                    );
                }
            }
        }
    }
}

async fn request_totals_loop(
    totals: Arc<RequestTotals>,
    descriptor_totals: Arc<DescriptorTotals>,
    storage: Storage,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(totals.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                totals.emit(storage.metrics_snapshot());
                descriptor_totals.emit(storage.descriptor_metrics_snapshot());
                let recovery = storage.recovery_metrics_snapshot();
                tracing::info!(event = "recovery_storage_totals", records_admitted = recovery.records_admitted, bytes_admitted = recovery.record_bytes_admitted, current_records = recovery.current_records, current_bytes = recovery.current_bytes, "recovery storage totals");
            }
        }
    }
}

async fn health(State(state): State<AppState>) -> StatusCode {
    if state.storage.is_alive() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn json_request<T>(request: Request, state: &AppState) -> Result<T, ApiError>
where
    T: serde::de::DeserializeOwned,
{
    match Json::<T>::from_request(request, state).await {
        Ok(Json(value)) => Ok(value),
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            Err(ApiError::BlobTooLarge)
        }
        Err(_) => Err(ApiError::InvalidRequest(
            "Wallet backup request body is invalid.",
        )),
    }
}

/// Requires exactly one parseable proxy-supplied source header, failing
/// closed otherwise; per-source rate limiting itself happens in Nginx.
fn source_identity(headers: &HeaderMap) -> Result<IpAddr, ApiError> {
    let mut values = headers.get_all(SOURCE_IDENTITY_HEADER).iter();
    let first = values.next().ok_or(ApiError::InvalidRequest(
        "Wallet backup source identity is invalid.",
    ))?;
    if values.next().is_some() {
        return Err(ApiError::InvalidRequest(
            "Wallet backup source identity is invalid.",
        ));
    }
    first
        .to_str()
        .ok()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .ok_or(ApiError::InvalidRequest(
            "Wallet backup source identity is invalid.",
        ))
}

fn map_limit(error: LimitError) -> ApiError {
    match error {
        LimitError::Exceeded {
            retry_after_secs,
            kind,
        } => ApiError::RateLimited {
            retry_after_secs,
            kind,
        },
        LimitError::Unavailable => ApiError::Internal,
    }
}

fn map_storage(error: CallError, saturation_retry_after_secs: u64) -> ApiError {
    match error {
        CallError::QueueFull => ApiError::RateLimited {
            retry_after_secs: saturation_retry_after_secs,
            kind: RateLimitKind::Saturation,
        },
        CallError::Unavailable | CallError::Storage => ApiError::Internal,
    }
}

fn now_i64() -> Result<i64, ApiError> {
    i64::try_from(unix_time()?).map_err(|_| ApiError::Internal)
}

async fn fetch(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
    let result = fetch_inner(&state, &headers, request).await;
    state
        .request_totals
        .record(RequestOperation::Fetch, &result);
    result
}

async fn fetch_inner(
    state: &AppState,
    headers: &HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
    let permit = Arc::clone(&state.fetch_in_flight)
        .try_acquire_owned()
        .map_err(|_| ApiError::RateLimited {
            retry_after_secs: state.saturation_retry_after_secs,
            kind: RateLimitKind::Saturation,
        })?;
    source_identity(headers)?;
    let request: FetchRequest = json_request(request, state).await?;
    validate_version(request.version)?;
    let author = decode_canonical_hex::<32>(
        &request.npub,
        "Wallet backup public key must be 64 lowercase hexadecimal characters.",
    )?;
    verify_request_signature(
        FETCH_ACTION,
        request.stream,
        &request.npub,
        0,
        None,
        None,
        0,
        request.timestamp,
        &request.signature,
        unix_time()?,
    )?;
    let head = state
        .storage
        .fetch(author)
        .await
        .map_err(|error| map_storage(error, state.saturation_retry_after_secs))?;
    if head.is_some() {
        state.limiter.check_fetch_npub(&author).map_err(map_limit)?;
    }
    let response = match head {
        None => FetchResponse {
            version: VERSION,
            found: false,
            generation: 0,
            etag: None,
            ciphertext: None,
            ciphertext_sha256: None,
            ciphertext_bytes: None,
            updated_at: None,
        },
        Some(head) => {
            let generation = u64::try_from(head.generation).map_err(|_| ApiError::Internal)?;
            let hash = head.ciphertext_sha256.map(hex::encode);
            let etag = hex::encode(compute_etag(
                BackupStream::WalletBackup,
                &request.npub,
                generation,
                hash.as_deref(),
            ));
            let bytes = head
                .ciphertext
                .as_ref()
                .map(|value| u64::try_from(value.len()).map_err(|_| ApiError::Internal))
                .transpose()?;
            FetchResponse {
                version: VERSION,
                found: head.ciphertext.is_some(),
                generation,
                etag: Some(etag),
                ciphertext: head.ciphertext.map(|value| BASE64_STANDARD.encode(value)),
                ciphertext_sha256: hash,
                ciphertext_bytes: bytes,
                updated_at: Some(head.updated_at),
            }
        }
    };
    drop(permit);
    Ok(private_no_store(Json(response).into_response()))
}

async fn store(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
    let result = store_inner(&state, &headers, request).await;
    state
        .request_totals
        .record(RequestOperation::Store, &result);
    result
}

#[allow(clippy::too_many_lines)]
async fn store_inner(
    state: &AppState,
    headers: &HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
    let permit = Arc::clone(&state.store_in_flight)
        .try_acquire_owned()
        .map_err(|_| ApiError::RateLimited {
            retry_after_secs: state.saturation_retry_after_secs,
            kind: RateLimitKind::Saturation,
        })?;
    source_identity(headers)?;
    let request: StoreRequest = json_request(request, state).await?;
    validate_version(request.version)?;
    let generation = validate_generation(request.generation)?;
    let author = decode_canonical_hex::<32>(
        &request.npub,
        "Wallet backup public key must be 64 lowercase hexadecimal characters.",
    )?;
    let expected_etag = request
        .expected_etag
        .as_deref()
        .map(|value| decode_canonical_hex::<32>(value, "Wallet backup ETag is invalid."))
        .transpose()?;
    let declared_hash = decode_canonical_hex::<32>(
        &request.ciphertext_sha256,
        "Wallet backup ciphertext hash is invalid.",
    )?;
    verify_request_signature(
        STORE_ACTION,
        request.stream,
        &request.npub,
        request.generation,
        request.expected_etag.as_deref(),
        Some(&request.ciphertext_sha256),
        request.ciphertext_bytes,
        request.timestamp,
        &request.signature,
        unix_time()?,
    )?;
    if request.ciphertext_bytes
        > u64::try_from(state.accepted_ciphertext_bytes).map_err(|_| ApiError::Internal)?
    {
        return Err(ApiError::BlobTooLarge);
    }
    state
        .limiter
        .check_mutation_npub(&author)
        .map_err(map_limit)?;
    let ciphertext = decode_ciphertext(&request.ciphertext, state.accepted_ciphertext_bytes)?;
    let actual_bytes = u64::try_from(ciphertext.len()).map_err(|_| ApiError::Internal)?;
    if request.ciphertext_bytes != actual_bytes {
        return Err(ApiError::InvalidRequest(
            "Wallet backup ciphertext byte count does not match.",
        ));
    }
    let actual_hash: [u8; 32] = Sha256::digest(&ciphertext).into();
    if actual_hash != declared_hash {
        return Err(ApiError::InvalidRequest(
            "Wallet backup ciphertext hash does not match.",
        ));
    }
    let requested_etag = compute_etag(
        request.stream,
        &request.npub,
        request.generation,
        Some(&request.ciphertext_sha256),
    );
    let outcome = state
        .storage
        .store(
            request.npub,
            author,
            generation,
            expected_etag,
            requested_etag,
            ciphertext,
            declared_hash,
            now_i64()?,
        )
        .await
        .map_err(|error| map_storage(error, state.saturation_retry_after_secs))?;
    match outcome {
        MutationOutcome::Applied | MutationOutcome::ExactRetry => {}
        MutationOutcome::HeadConflict => return Err(ApiError::HeadConflict),
        MutationOutcome::CapacityExceeded => return Err(ApiError::Capacity),
        MutationOutcome::AdmissionLimited => {
            return Err(ApiError::RateLimited {
                retry_after_secs: state.admission_retry_after_secs,
                kind: RateLimitKind::Admission,
            });
        }
    }
    drop(permit);
    Ok(private_no_store(
        Json(MutationResponse {
            version: VERSION,
            generation: request.generation,
            etag: hex::encode(requested_etag),
        })
        .into_response(),
    ))
}

async fn delete_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
    let result = delete_inner(&state, &headers, request).await;
    state
        .request_totals
        .record(RequestOperation::Delete, &result);
    result
}

async fn delete_inner(
    state: &AppState,
    headers: &HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
    let permit = Arc::clone(&state.delete_in_flight)
        .try_acquire_owned()
        .map_err(|_| ApiError::RateLimited {
            retry_after_secs: state.saturation_retry_after_secs,
            kind: RateLimitKind::Saturation,
        })?;
    source_identity(headers)?;
    let request: DeleteRequest = json_request(request, state).await?;
    validate_version(request.version)?;
    let generation = validate_generation(request.generation)?;
    let author = decode_canonical_hex::<32>(
        &request.npub,
        "Wallet backup public key must be 64 lowercase hexadecimal characters.",
    )?;
    let expected_etag =
        decode_canonical_hex::<32>(&request.expected_etag, "Wallet backup ETag is invalid.")?;
    verify_request_signature(
        DELETE_ACTION,
        request.stream,
        &request.npub,
        request.generation,
        Some(&request.expected_etag),
        None,
        0,
        request.timestamp,
        &request.signature,
        unix_time()?,
    )?;
    state
        .limiter
        .check_mutation_npub(&author)
        .map_err(map_limit)?;
    let tombstone_etag = compute_etag(request.stream, &request.npub, request.generation, None);
    let outcome = state
        .storage
        .delete(
            request.npub,
            author,
            generation,
            expected_etag,
            tombstone_etag,
            now_i64()?,
        )
        .await
        .map_err(|error| map_storage(error, state.saturation_retry_after_secs))?;
    match outcome {
        MutationOutcome::Applied | MutationOutcome::ExactRetry => {}
        MutationOutcome::HeadConflict => return Err(ApiError::HeadConflict),
        MutationOutcome::CapacityExceeded | MutationOutcome::AdmissionLimited => {
            return Err(ApiError::Internal);
        }
    }
    drop(permit);
    Ok(private_no_store(
        Json(MutationResponse {
            version: VERSION,
            generation: request.generation,
            etag: hex::encode(tombstone_etag),
        })
        .into_response(),
    ))
}

async fn descriptor_json_request<T>(
    request: Request,
    state: &AppState,
) -> Result<T, DescriptorApiError>
where
    T: serde::de::DeserializeOwned,
{
    match Json::<T>::from_request(request, state).await {
        Ok(Json(value)) => Ok(value),
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            Err(DescriptorApiError::BlobTooLarge)
        }
        Err(_) => Err(DescriptorApiError::InvalidRequest(
            "Descriptor backup request body is invalid.",
        )),
    }
}

fn descriptor_source_identity(headers: &HeaderMap) -> Result<IpAddr, DescriptorApiError> {
    source_identity(headers).map_err(|_| {
        DescriptorApiError::InvalidRequest("Descriptor backup source identity is invalid.")
    })
}

fn map_descriptor_limit(error: LimitError) -> DescriptorApiError {
    match error {
        LimitError::Exceeded {
            retry_after_secs,
            kind,
        } => DescriptorApiError::RateLimited {
            retry_after_secs,
            kind,
        },
        LimitError::Unavailable => DescriptorApiError::Internal,
    }
}

fn map_descriptor_storage(
    error: CallError,
    saturation_retry_after_secs: u64,
) -> DescriptorApiError {
    match error {
        CallError::QueueFull => DescriptorApiError::RateLimited {
            retry_after_secs: saturation_retry_after_secs,
            kind: RateLimitKind::Saturation,
        },
        CallError::Unavailable | CallError::Storage => DescriptorApiError::Internal,
    }
}

fn descriptor_now_i64() -> Result<i64, DescriptorApiError> {
    unix_time()
        .map_err(|_| DescriptorApiError::Internal)
        .and_then(|now| i64::try_from(now).map_err(|_| DescriptorApiError::Internal))
}

async fn store_descriptor(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, DescriptorApiError> {
    let result = store_descriptor_inner(&state, &headers, request).await;
    state
        .descriptor_totals
        .record(DescriptorOperation::Store, &result);
    result
}

async fn store_descriptor_inner(
    state: &AppState,
    headers: &HeaderMap,
    request: Request,
) -> Result<Response, DescriptorApiError> {
    let permit = Arc::clone(&state.descriptor_store_in_flight)
        .try_acquire_owned()
        .map_err(|_| DescriptorApiError::RateLimited {
            retry_after_secs: state.saturation_retry_after_secs,
            kind: RateLimitKind::Saturation,
        })?;
    descriptor_source_identity(headers)?;
    let request: StoreDescriptorRequest = descriptor_json_request(request, state).await?;
    validate_descriptor_version(request.version)?;
    let publisher = decode_descriptor_hex::<32>(
        &request.npub,
        "Descriptor backup public key must be 64 lowercase hexadecimal characters.",
    )?;
    let declared_hash = decode_descriptor_hex::<32>(
        &request.ciphertext_sha256,
        "Descriptor backup ciphertext hash is invalid.",
    )?;
    let tokens = canonical_lookup_tokens(&request.lookup_tokens)?;
    verify_descriptor_signature(
        &request.npub,
        &request.ciphertext_sha256,
        request.ciphertext_bytes,
        &request.lookup_tokens,
        request.timestamp,
        &request.signature,
        unix_time().map_err(|_| DescriptorApiError::Internal)?,
    )?;
    if request.ciphertext_bytes
        > u64::try_from(state.accepted_descriptor_ciphertext_bytes)
            .map_err(|_| DescriptorApiError::Internal)?
    {
        return Err(DescriptorApiError::BlobTooLarge);
    }
    state
        .limiter
        .check_descriptor_store_npub(&publisher)
        .map_err(map_descriptor_limit)?;
    let ciphertext = decode_descriptor_ciphertext(
        &request.ciphertext,
        state.accepted_descriptor_ciphertext_bytes,
    )?;
    let actual_bytes = u64::try_from(ciphertext.len()).map_err(|_| DescriptorApiError::Internal)?;
    if request.ciphertext_bytes != actual_bytes {
        return Err(DescriptorApiError::InvalidRequest(
            "Descriptor backup ciphertext byte count does not match.",
        ));
    }
    if actual_bytes == 0 {
        return Err(DescriptorApiError::InvalidRequest(
            "Descriptor backup ciphertext must not be empty.",
        ));
    }
    let actual_hash: [u8; 32] = Sha256::digest(&ciphertext).into();
    if actual_hash != declared_hash {
        return Err(DescriptorApiError::InvalidRequest(
            "Descriptor backup ciphertext hash does not match.",
        ));
    }
    let outcome = state
        .storage
        .store_descriptor(
            publisher,
            declared_hash,
            ciphertext,
            tokens,
            descriptor_now_i64()?,
        )
        .await
        .map_err(|error| map_descriptor_storage(error, state.saturation_retry_after_secs))?;
    let created_at = match outcome {
        DescriptorStoreOutcome::Created { created_at }
        | DescriptorStoreOutcome::ExactRetry { created_at } => created_at,
        DescriptorStoreOutcome::Conflict => return Err(DescriptorApiError::RecordConflict),
        DescriptorStoreOutcome::PublisherQuotaExceeded => {
            return Err(DescriptorApiError::PublisherQuota);
        }
        DescriptorStoreOutcome::CapacityExceeded => return Err(DescriptorApiError::Capacity),
        DescriptorStoreOutcome::AdmissionLimited => {
            return Err(DescriptorApiError::RateLimited {
                retry_after_secs: state.admission_retry_after_secs,
                kind: RateLimitKind::Admission,
            });
        }
    };
    drop(permit);
    Ok(private_no_store(
        Json(StoreDescriptorResponse {
            version: DESCRIPTOR_VERSION,
            ciphertext_sha256: request.ciphertext_sha256,
            created_at,
        })
        .into_response(),
    ))
}

async fn lookup_descriptors(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, DescriptorApiError> {
    let result = lookup_descriptors_inner(&state, &headers, request).await;
    state
        .descriptor_totals
        .record(DescriptorOperation::Lookup, &result);
    result
}

/// Knowing a lookup token is the read capability, so this route is
/// deliberately unauthenticated. It never returns a publisher identity or a
/// token, and a reader gains no authority to change anything.
async fn lookup_descriptors_inner(
    state: &AppState,
    headers: &HeaderMap,
    request: Request,
) -> Result<Response, DescriptorApiError> {
    let permit = Arc::clone(&state.descriptor_lookup_in_flight)
        .try_acquire_owned()
        .map_err(|_| DescriptorApiError::RateLimited {
            retry_after_secs: state.saturation_retry_after_secs,
            kind: RateLimitKind::Saturation,
        })?;
    descriptor_source_identity(headers)?;
    let request: DescriptorLookupRequest = descriptor_json_request(request, state).await?;
    validate_descriptor_version(request.version)?;
    let tokens = canonical_lookup_tokens(&request.lookup_tokens)?;
    let cursor = match request.cursor.as_deref() {
        Some(value) => {
            let (created_at, record_id) = decode_descriptor_cursor(value)?;
            Some(DescriptorLookupCursor {
                created_at,
                record_id,
            })
        }
        None => None,
    };
    state
        .limiter
        .check_descriptor_lookup(&tokens)
        .map_err(map_descriptor_limit)?;
    let outcome = state
        .storage
        .lookup_descriptors(tokens, state.descriptor_lookup_bounds, cursor)
        .await
        .map_err(|error| map_descriptor_storage(error, state.saturation_retry_after_secs))?;
    let mut records = Vec::with_capacity(outcome.records.len());
    for record in outcome.records {
        records.push(DescriptorRecordView {
            ciphertext_bytes: u64::try_from(record.ciphertext.len())
                .map_err(|_| DescriptorApiError::Internal)?,
            ciphertext: BASE64_STANDARD.encode(record.ciphertext),
            ciphertext_sha256: hex::encode(record.ciphertext_sha256),
            created_at: record.created_at,
        });
    }
    drop(permit);
    Ok(private_no_store(
        Json(DescriptorLookupResponse {
            version: DESCRIPTOR_VERSION,
            next_cursor: outcome
                .next
                .map(|cursor| encode_descriptor_cursor(cursor.created_at, cursor.record_id)),
            records,
        })
        .into_response(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::HeaderValue;
    use config::{AdmissionBucketConfig, AdmissionConfig, LimiterConfig, WindowLimit};
    use protocol::{
        ABSOLUTE_MAX_CIPHERTEXT_BYTES, ABSOLUTE_MAX_DESCRIPTOR_CIPHERTEXT_BYTES,
        ABSOLUTE_MAX_DESCRIPTOR_STORE_BODY_BYTES, ABSOLUTE_MAX_STORE_BODY_BYTES,
        DESCRIPTOR_STORE_ACTION, build_descriptor_signing_message, build_signing_message,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use std::fs;
    use std::io::{self, Write};
    use std::sync::Mutex;
    use std::time::Duration;
    use tower::ServiceExt;

    #[derive(Clone)]
    struct TestLogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for TestLogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut output = self
                .0
                .lock()
                .map_err(|_| io::Error::other("test log lock poisoned"))?;
            output.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(serde::Deserialize)]
    struct TamperFixture {
        npub: String,
        tamper_cases: Vec<TamperCase>,
        test_only_secret_key: String,
    }

    #[derive(serde::Deserialize)]
    struct TamperCase {
        expected_code: String,
        field: String,
    }

    fn test_admission() -> AdmissionConfig {
        let byte_bucket = AdmissionBucketConfig {
            capacity: 16 * 1024 * 1024,
            refill: 16 * 1024 * 1024,
            refill_interval: Duration::from_secs(60),
        };
        AdmissionConfig {
            new_heads: AdmissionBucketConfig {
                capacity: 100,
                refill: 100,
                refill_interval: Duration::from_secs(60),
            },
            total_growth_bytes: byte_bucket,
        }
    }

    fn test_limiter() -> LimiterConfig {
        let limit = WindowLimit {
            requests: 100,
            window: Duration::from_secs(60),
        };
        LimiterConfig {
            recovery_fetch_npub: WindowLimit {
                requests: 2500,
                window: Duration::from_secs(3600),
            },
            recovery_store_npub: WindowLimit {
                requests: 256,
                window: Duration::from_secs(3600),
            },
            max_subjects: 16,
            overflow: limit,
            overflow_retry_after_secs: 900,
            prune_interval: Duration::from_secs(60),
            fetch_npub: limit,
            mutation_npub: limit,
            descriptor_store_npub: limit,
            descriptor_lookup: limit,
        }
    }

    fn test_router(state: AppState) -> Router {
        router(
            state,
            ABSOLUTE_MAX_STORE_BODY_BYTES,
            ABSOLUTE_MAX_DESCRIPTOR_STORE_BODY_BYTES,
        )
    }

    fn test_state(name: &str) -> Result<(PathBuf, StorageOwner, AppState), String> {
        test_state_with_capacity(name, 1024)
    }

    fn test_state_with_capacity(
        name: &str,
        capacity: u64,
    ) -> Result<(PathBuf, StorageOwner, AppState), String> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|_| "randomness unavailable".to_owned())?;
        let directory =
            env::temp_dir().join(format!("backup-server-{name}-{}", hex::encode(random)));
        fs::create_dir(&directory).map_err(|_| "failed to create test directory".to_owned())?;
        let owner = StorageOwner::start(StorageConfig {
            path: directory.join("backup.sqlite3"),
            queue_depth: 8,
            busy_timeout: Duration::from_secs(1),
            max_live_bytes: capacity,
            max_heads: 4,
            max_descriptor_records: 16,
            max_descriptor_records_per_publisher: 4,
            admission: {
                let mut admission = test_admission();
                admission.total_growth_bytes.capacity = capacity;
                admission.total_growth_bytes.refill = capacity;
                admission
            },
        })?;
        let state = AppState {
            recovery: None,
            storage: owner.client(),
            limiter: RateLimiter::new(test_limiter())?,
            fetch_in_flight: Arc::new(Semaphore::new(4)),
            store_in_flight: Arc::new(Semaphore::new(4)),
            delete_in_flight: Arc::new(Semaphore::new(4)),
            descriptor_store_in_flight: Arc::new(Semaphore::new(4)),
            descriptor_lookup_in_flight: Arc::new(Semaphore::new(4)),
            accepted_ciphertext_bytes: ABSOLUTE_MAX_CIPHERTEXT_BYTES,
            accepted_descriptor_ciphertext_bytes: ABSOLUTE_MAX_DESCRIPTOR_CIPHERTEXT_BYTES,
            descriptor_lookup_bounds: DescriptorLookupBounds {
                record_cap: 32,
                byte_budget: 512 * 1024,
            },
            saturation_retry_after_secs: 5,
            admission_retry_after_secs: 900,
            request_totals: Arc::new(RequestTotals::new(Duration::from_secs(60))),
            descriptor_totals: Arc::new(DescriptorTotals::new(Duration::from_secs(60))),
        };
        Ok((directory, owner, state))
    }

    fn replace_json_field(
        body: &mut serde_json::Value,
        field: &str,
        value: serde_json::Value,
    ) -> Result<(), String> {
        let object = body
            .as_object_mut()
            .ok_or_else(|| "test body is not an object".to_owned())?;
        if object.insert(field.to_owned(), value).is_none() {
            return Err("test body field is missing".to_owned());
        }
        Ok(())
    }

    fn nginx_return_body(config: &str, status: u16) -> Result<&str, String> {
        let marker = format!("return {status} '");
        let (_, remainder) = config
            .split_once(&marker)
            .ok_or_else(|| format!("nginx {status} response is missing"))?;
        remainder
            .split_once("';")
            .map(|(body, _)| body)
            .ok_or_else(|| format!("nginx {status} response is unterminated"))
    }

    fn nginx_exact_location<'a>(config: &'a str, path: &str) -> Result<&'a str, String> {
        let marker = format!("location = {path} {{");
        let (_, remainder) = config
            .split_once(&marker)
            .ok_or_else(|| format!("nginx location {path} is missing"))?;
        remainder
            .split_once("\n}")
            .map(|(body, _)| body)
            .ok_or_else(|| format!("nginx location {path} is unterminated"))
    }

    fn nginx_named_location<'a>(config: &'a str, name: &str) -> Result<&'a str, String> {
        let marker = format!("location @{name} {{");
        let (_, remainder) = config
            .split_once(&marker)
            .ok_or_else(|| format!("nginx location @{name} is missing"))?;
        remainder
            .split_once("\n}")
            .map(|(body, _)| body)
            .ok_or_else(|| format!("nginx location @{name} is unterminated"))
    }

    fn recovery_fixture_key(value: &serde_json::Value, name: &str) -> Result<Keypair, String> {
        let encoded = value["public_test_keys"][name]
            .as_str()
            .ok_or("missing public test key")?;
        let bytes: [u8; 32] = hex::decode(encoded)
            .map_err(|_| "invalid test hex")?
            .try_into()
            .map_err(|_| "invalid test key length")?;
        Ok(Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array(bytes).map_err(|_| "invalid test key")?,
        ))
    }

    async fn recovery_http(
        state: AppState,
        path: &str,
        body: serde_json::Value,
        source_header: bool,
    ) -> Result<Response, String> {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json");
        if source_header {
            request = request.header("x-real-ip", "192.0.2.3");
        }
        let request = request
            .body(Body::from(body.to_string()))
            .map_err(|_| "bad test request")?;
        test_router(state)
            .oneshot(request)
            .await
            .map_err(|_| "test router failed".to_owned())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn integrated_recovery_uses_shared_storage_and_preserves_historical_fetch()
    -> Result<(), String> {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/recovery-wire-v1.json"))
                .map_err(|_| "bad fixture")?;
        let mut request: recovery_prototype::StoreRequest =
            serde_json::from_value(fixture["store"].clone()).map_err(|_| "bad store fixture")?;
        let policy = recovery_prototype::RecoveryPolicy {
            origin: request.grant.origin.clone(),
            publisher: request.grant.publisher.clone(),
            max_records: 1,
            max_bytes: request.ciphertext_bytes,
        };
        let (directory, owner, mut state) =
            test_state_with_capacity("integrated-recovery", 16 * 1024)?;
        state.recovery = Some(policy.clone());
        let stored = state
            .storage
            .store_recovery(policy, request.clone(), 100)
            .await
            .map_err(|e| format!("{e:?}"))?
            .map_err(|e| format!("{e:?}"))?;
        let clock = unix_time().map_err(|_| "clock")?;
        let publisher = recovery_fixture_key(&fixture, "publisher_private_key")?;
        let nostr = recovery_fixture_key(&fixture, "nostr_private_key")?;
        request.timestamp = clock;
        request.signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&recovery_prototype::store_digest(&request), &publisher)
            .to_string();
        let body = serde_json::to_value(&request).map_err(|_| "encode store")?;
        // Retrying a stored record is permitted after expiry and at exact capacity.
        let response = recovery_http(
            state.clone(),
            "/api/v1/arkade-recovery-records",
            body.clone(),
            true,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["cache-control"],
            "private, no-store, max-age=0"
        );
        let response = recovery_http(
            state.clone(),
            "/api/v1/arkade-recovery-records",
            body.clone(),
            false,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let mut disabled = state.clone();
        disabled.recovery = None;
        assert_eq!(
            recovery_http(disabled, "/api/v1/arkade-recovery-records", body, true)
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
        let mut fetch = recovery_prototype::FetchRequest {
            owner: request.grant.owner.clone(),
            after: 0,
            snapshot: 0,
            timestamp: clock,
            signature: String::new(),
        };
        fetch.signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&recovery_prototype::fetch_digest(&fetch), &nostr)
            .to_string();
        let response = recovery_http(
            state.clone(),
            "/api/v1/arkade-recovery-records/fetch",
            serde_json::to_value(&fetch).map_err(|_| "encode fetch")?,
            true,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .map_err(|_| "read response")?;
        let page: recovery_prototype::Page =
            serde_json::from_slice(&bytes).map_err(|_| "decode response")?;
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].id, stored.id);
        assert_eq!(page.records[0].ciphertext, request.ciphertext);
        assert_eq!(page.next_after, None);
        fetch.signature = "0".repeat(128);
        assert_eq!(
            recovery_http(
                state.clone(),
                "/api/v1/arkade-recovery-records/fetch",
                serde_json::to_value(&fetch).map_err(|_| "encode fetch")?,
                true
            )
            .await?
            .status(),
            StatusCode::UNAUTHORIZED
        );
        request.ciphertext = BASE64_STANDARD.encode(b"new record after expiry");
        request.ciphertext_sha256 = hex::encode(Sha256::digest(b"new record after expiry"));
        request.ciphertext_bytes =
            u64::try_from(b"new record after expiry".len()).map_err(|_| "length")?;
        request.signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&recovery_prototype::store_digest(&request), &publisher)
            .to_string();
        assert_eq!(
            recovery_http(
                state,
                "/api/v1/arkade-recovery-records",
                serde_json::to_value(&request).map_err(|_| "encode store")?,
                true
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
        owner.shutdown().await?;
        let report = storage::verify_backup(&directory.join("backup.sqlite3"))?;
        assert_eq!(report.recovery_records, 1);
        assert_eq!(
            report.recovery_bytes,
            fixture["store"]["ciphertext_bytes"]
                .as_u64()
                .ok_or("fixture length")?
        );
        fs::remove_dir_all(directory).map_err(|_| "cleanup failed")?;
        Ok(())
    }

    async fn send_test_json(
        state: AppState,
        method: &'static str,
        body: serde_json::Value,
    ) -> Result<(StatusCode, String), String> {
        let request = Request::builder()
            .method(method)
            .uri("/api/v1/wallet-backups")
            .header("content-type", "application/json")
            .header("x-real-ip", "192.0.2.3")
            .body(Body::from(body.to_string()))
            .map_err(|_| "failed to build tamper request".to_owned())?;
        let response = test_router(state)
            .oneshot(request)
            .await
            .map_err(|_| "tamper router failed".to_owned())?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4096)
            .await
            .map_err(|_| "failed to read tamper response".to_owned())?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| "invalid tamper response JSON".to_owned())?;
        let code = value
            .get("code")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "tamper response code is missing".to_owned())?
            .to_owned();
        Ok((status, code))
    }

    #[test]
    fn source_identity_uses_only_bare_single_x_real_ip() -> Result<(), String> {
        let mut headers = HeaderMap::new();
        assert!(source_identity(&headers).is_err());
        headers.append("x-real-ip", HeaderValue::from_static("127.0.0.1"));
        headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
        headers.append("forwarded", HeaderValue::from_static("for=198.51.100.7"));
        assert_eq!(source_identity(&headers), Ok(IpAddr::from([127, 0, 0, 1])));
        headers.append("x-real-ip", HeaderValue::from_static("127.0.0.2"));
        assert!(source_identity(&headers).is_err());

        for invalid in [
            "203.0.113.5, 198.51.100.7",
            "203.0.113.5:443",
            "[2001:db8::1]",
        ] {
            let mut headers = HeaderMap::new();
            let value = invalid
                .parse::<HeaderValue>()
                .map_err(|_| "invalid test header".to_owned())?;
            headers.insert(SOURCE_IDENTITY_HEADER, value);
            assert!(source_identity(&headers).is_err(), "{invalid}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_source_identity_is_rejected_by_http_contract() -> Result<(), String> {
        let (directory, owner, state) = test_state("duplicate-source")?;
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/v1/wallet-backups/fetch")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .map_err(|_| "failed to build duplicate-source request".to_owned())?;
        request.headers_mut().append(
            SOURCE_IDENTITY_HEADER,
            HeaderValue::from_static("192.0.2.1"),
        );
        request.headers_mut().append(
            SOURCE_IDENTITY_HEADER,
            HeaderValue::from_static("192.0.2.2"),
        );
        let response = test_router(state)
            .oneshot(request)
            .await
            .map_err(|_| "duplicate-source router failed".to_owned())?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1024)
            .await
            .map_err(|_| "failed to read duplicate-source response".to_owned())?;
        let expected = to_bytes(
            ApiError::InvalidRequest("Wallet backup source identity is invalid.")
                .into_response()
                .into_body(),
            1024,
        )
        .await
        .map_err(|_| "failed to read expected source response".to_owned())?;
        assert_eq!(body, expected);
        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn absent_fetches_do_not_allocate_npub_limiter_entries() -> Result<(), String> {
        let (directory, owner, mut state) = test_state("absent-fetch-limiter")?;
        let mut policy = test_limiter();
        policy.max_subjects = 1;
        policy.overflow = WindowLimit {
            requests: 1,
            window: Duration::from_secs(60),
        };
        policy.overflow_retry_after_secs = 23;
        state.limiter = RateLimiter::new(policy)?;

        let secp = Secp256k1::new();
        let timestamp = unix_time().map_err(|_| "clock unavailable".to_owned())?;
        for key_byte in 1_u8..=3 {
            let secret = SecretKey::from_byte_array([key_byte; 32])
                .map_err(|_| "invalid test secret".to_owned())?;
            let keypair = Keypair::from_secret_key(&secp, &secret);
            let npub = keypair.x_only_public_key().0.to_string();
            let message = build_signing_message(
                FETCH_ACTION,
                BackupStream::WalletBackup,
                &npub,
                0,
                None,
                None,
                0,
                timestamp,
            );
            let digest: [u8; 32] = Sha256::digest(message).into();
            let signature = secp.sign_schnorr_no_aux_rand(&digest, &keypair).to_string();
            let body = serde_json::json!({
                "version": 1,
                "stream": "wallet_backup",
                "npub": npub,
                "timestamp": timestamp,
                "signature": signature
            });
            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/wallet-backups/fetch")
                .header("content-type", "application/json")
                .header("x-real-ip", "192.0.2.20")
                .body(Body::from(body.to_string()))
                .map_err(|_| "failed to build absent-fetch request".to_owned())?;
            let response = test_router(state.clone())
                .oneshot(request)
                .await
                .map_err(|_| "absent-fetch router failed".to_owned())?;
            assert_eq!(response.status(), StatusCode::OK);
            let response_body: serde_json::Value = serde_json::from_slice(
                &to_bytes(response.into_body(), 4096)
                    .await
                    .map_err(|_| "failed to read absent-fetch response".to_owned())?,
            )
            .map_err(|_| "invalid absent-fetch response JSON".to_owned())?;
            assert_eq!(
                response_body
                    .get("found")
                    .and_then(serde_json::Value::as_bool),
                Some(false)
            );
        }

        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[test]
    fn request_totals_have_fixed_exact_outcomes() {
        let interval = Duration::from_secs(60);
        let totals = RequestTotals::new(interval);
        let outcomes = [
            Ok(()),
            Err(ApiError::InvalidRequest("test")),
            Err(ApiError::Authentication),
            Err(ApiError::HeadConflict),
            Err(ApiError::BlobTooLarge),
            Err(ApiError::RateLimited {
                retry_after_secs: 1,
                kind: RateLimitKind::Npub,
            }),
            Err(ApiError::Capacity),
            Err(ApiError::Internal),
            Err(ApiError::RateLimited {
                retry_after_secs: 1,
                kind: RateLimitKind::Overflow,
            }),
            Err(ApiError::RateLimited {
                retry_after_secs: 1,
                kind: RateLimitKind::Saturation,
            }),
            Err(ApiError::RateLimited {
                retry_after_secs: 1,
                kind: RateLimitKind::Admission,
            }),
        ];
        for (index, outcome) in outcomes.into_iter().enumerate() {
            let operation = match index / 4 {
                0 => RequestOperation::Fetch,
                1 => RequestOperation::Store,
                _ => RequestOperation::Delete,
            };
            totals.record(operation, &outcome);
        }
        assert_eq!(totals.take(), [1, 1, 1, 1, 1, 4, 1, 1, 1, 1, 1, 1, 4, 4, 3]);
        assert_eq!(totals.take(), [0; REQUEST_TOTALS]);
        assert_eq!(totals.interval, interval);
    }

    #[tokio::test]
    async fn request_aggregate_is_bounded_and_private() -> Result<(), String> {
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&output);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_target(false)
            .with_writer(move || TestLogWriter(Arc::clone(&writer)))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let (directory, owner, state) = test_state("request-totals")?;
        let totals = Arc::clone(&state.request_totals);
        let storage = state.storage.clone();
        let canary = "request-canary-must-not-be-logged";
        let request = Request::builder()
            .method("PUT")
            .uri("/api/v1/wallet-backups")
            .header("content-type", "application/json")
            .header("x-real-ip", "192.0.2.4")
            .body(Body::from(format!(r#"{{"value":"{canary}""#)))
            .map_err(|_| "failed to build canary request".to_owned())?;
        let response = test_router(state)
            .oneshot(request)
            .await
            .map_err(|_| "canary router failed".to_owned())?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        totals.emit(storage.metrics_snapshot());
        let logs = {
            let bytes = output
                .lock()
                .map_err(|_| "test log lock poisoned".to_owned())?
                .clone();
            String::from_utf8(bytes).map_err(|_| "test log is not UTF-8".to_owned())?
        };
        assert!(logs.contains("wallet_backup_request_totals"));
        assert!(logs.contains("backup_invalid_request=1"));
        assert!(logs.contains("store_requests=1"));
        assert!(logs.contains("current_heads=0"));
        assert!(!logs.contains(canary));

        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn store_in_flight_limit_does_not_affect_fetch() -> Result<(), String> {
        let (directory, owner, state) = test_state("in-flight")?;
        let held = Arc::clone(&state.store_in_flight)
            .acquire_many_owned(4)
            .await
            .map_err(|_| "failed to hold in-flight permits".to_owned())?;
        let (status, code) = send_test_json(
            state.clone(),
            "PUT",
            serde_json::json!({"request": "must not be admitted"}),
        )
        .await?;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(code, "RateLimited");

        let fetch_request = Request::builder()
            .method("POST")
            .uri("/api/v1/wallet-backups/fetch")
            .header("content-type", "application/json")
            .header("x-real-ip", "192.0.2.9")
            .body(Body::from("{}"))
            .map_err(|_| "failed to build fetch-lane request".to_owned())?;
        let fetch_response = test_router(state)
            .oneshot(fetch_request)
            .await
            .map_err(|_| "fetch-lane router failed".to_owned())?;
        assert_eq!(fetch_response.status(), StatusCode::BAD_REQUEST);
        drop(held);
        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn http_body_ceilings_reject_one_byte_over() -> Result<(), String> {
        let (directory, owner, state) = test_state("body-limits")?;
        for (method, uri, limit) in [
            (
                "POST",
                "/api/v1/wallet-backups/fetch",
                SMALL_BODY_LIMIT_BYTES,
            ),
            (
                "PUT",
                "/api/v1/wallet-backups",
                ABSOLUTE_MAX_STORE_BODY_BYTES,
            ),
        ] {
            let at_limit = Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .header("x-real-ip", "192.0.2.5")
                .body(Body::from(vec![b' '; limit]))
                .map_err(|_| "failed to build boundary request".to_owned())?;
            let at_limit_response = test_router(state.clone())
                .oneshot(at_limit)
                .await
                .map_err(|_| "boundary router failed".to_owned())?;
            assert_eq!(at_limit_response.status(), StatusCode::BAD_REQUEST);

            let over_limit = Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .header("x-real-ip", "192.0.2.5")
                .body(Body::from(vec![b' '; limit + 1]))
                .map_err(|_| "failed to build over-limit request".to_owned())?;
            let over_limit_response = test_router(state.clone())
                .oneshot(over_limit)
                .await
                .map_err(|_| "over-limit router failed".to_owned())?;
            assert_eq!(over_limit_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }
        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn maintenance_tasks_drain_or_are_aborted_at_deadline() -> Result<(), String> {
        stop_task(
            "completed test",
            Duration::from_secs(1),
            tokio::spawn(async {}),
        )
        .await?;

        let blocked = tokio::spawn(std::future::pending());
        assert_eq!(
            stop_task("blocked test", Duration::from_millis(1), blocked).await,
            Err("blocked test task shutdown timed out".to_owned())
        );
        Ok(())
    }

    #[tokio::test]
    async fn ingress_error_bodies_match_application() -> Result<(), String> {
        let backup_config = include_str!("../deploy/nginx/backup-server.conf");
        let fence_config = include_str!("../deploy/nginx/mutation-fence.conf");
        let cases = [
            (
                ApiError::InvalidRequest("Wallet backup request body is invalid."),
                400,
                backup_config,
            ),
            (ApiError::BlobTooLarge, 413, backup_config),
            (
                ApiError::RateLimited {
                    retry_after_secs: 60,
                    kind: RateLimitKind::Saturation,
                },
                429,
                backup_config,
            ),
            (ApiError::Capacity, 503, fence_config),
        ];
        for (error, status, config) in cases {
            let response = error.into_response();
            assert_eq!(response.status().as_u16(), status);
            if status == 429 {
                assert_eq!(
                    response.headers().get("retry-after"),
                    Some(&HeaderValue::from_static("60"))
                );
            }
            assert_eq!(
                response.headers().get("cache-control"),
                Some(&HeaderValue::from_static("private, no-store, max-age=0"))
            );
            assert_eq!(
                response.headers().get("pragma"),
                Some(&HeaderValue::from_static("no-cache"))
            );
            let body = to_bytes(response.into_body(), 1024)
                .await
                .map_err(|_| "failed to read application error response".to_owned())?;
            assert_eq!(body.as_ref(), nginx_return_body(config, status)?.as_bytes());
        }
        Ok(())
    }

    #[test]
    fn nginx_backup_routes_keep_all_admission_bounds() -> Result<(), String> {
        let locations = include_str!("../deploy/nginx/backup-server.conf");
        let zones = include_str!("../deploy/nginx/backup-server-http.conf");
        let server = include_str!("../deploy/nginx/backup-server-server.conf");
        let mutation_fence = include_str!("../deploy/nginx/mutation-fence.conf");
        for directive in [
            "client_body_timeout 15s;",
            "send_timeout 15s;",
            "keepalive_timeout 15s;",
            "keepalive_requests 100;",
            "limit_req zone=backup_req_ip burst=20 nodelay;",
            "limit_conn backup_conn_ip 8;",
            "limit_req_status 429;",
            "limit_conn_status 429;",
            "limit_req_log_level info;",
            "limit_conn_log_level info;",
            "error_page 413 = @backup_blob_too_large;",
            "error_page 429 = @backup_rate_limited;",
            "proxy_set_header Connection \"\";",
            "proxy_set_header X-Real-IP $remote_addr;",
            "proxy_set_header X-Forwarded-For \"\";",
            "proxy_set_header Forwarded \"\";",
            "proxy_request_buffering on;",
            "proxy_buffering on;",
            "proxy_max_temp_file_size 4m;",
            "proxy_intercept_errors off;",
        ] {
            assert_eq!(
                locations
                    .lines()
                    .filter(|line| line.trim() == directive)
                    .count(),
                2,
                "{directive}"
            );
        }
        assert_eq!(
            locations
                .lines()
                .filter(|line| line.trim() == "client_max_body_size 8k;")
                .count(),
            1
        );
        assert_eq!(
            locations
                .lines()
                .filter(|line| line.trim() == "client_max_body_size 1536k;")
                .count(),
            1
        );
        assert_eq!(
            locations
                .lines()
                .filter(|line| {
                    matches!(
                        line.trim(),
                        "limit_req zone=backup_fetch_all burst=20 nodelay;"
                            | "limit_req zone=backup_mutation_all burst=15 nodelay;"
                    )
                })
                .count(),
            2
        );
        for directive in [
            "limit_req_zone $binary_remote_addr zone=backup_req_ip:1m rate=5r/s;",
            "limit_req_zone $server_name zone=backup_fetch_all:1m rate=6r/m;",
            "limit_req_zone $server_name zone=backup_mutation_all:1m rate=30r/m;",
            "limit_conn_zone $binary_remote_addr zone=backup_conn_ip:1m;",
        ] {
            assert!(zones.contains(directive), "{directive}");
        }
        assert!(server.contains("client_header_timeout 10s;"));
        assert!(server.contains("reset_timedout_connection on;"));
        assert!(locations.contains("add_header Retry-After \"60\" always;"));
        for location in [
            nginx_exact_location(locations, "/api/v1/wallet-backups/fetch")?,
            nginx_exact_location(locations, "/api/v1/wallet-backups")?,
            nginx_exact_location(mutation_fence, "/api/v1/wallet-backups")?,
        ] {
            for directive in ["access_log off;", "error_log stderr crit;"] {
                assert!(location.lines().any(|line| line.trim() == directive));
            }
            for directive in [
                "proxy_set_header X-Real-IP $remote_addr;",
                "proxy_set_header X-Forwarded-For \"\";",
                "proxy_set_header Forwarded \"\";",
            ] {
                assert!(location.lines().any(|line| line.trim() == directive));
            }
        }
        for location in [
            nginx_named_location(locations, "backup_rate_limited")?,
            nginx_named_location(locations, "backup_blob_too_large")?,
        ] {
            for directive in ["access_log off;", "error_log stderr crit;"] {
                assert!(location.lines().any(|line| line.trim() == directive));
            }
        }
        Ok(())
    }

    #[test]
    fn nginx_fetch_capacity_is_isolated_from_mutations() -> Result<(), String> {
        let config = include_str!("../deploy/nginx/backup-server.conf");
        let zones = include_str!("../deploy/nginx/backup-server-http.conf");
        for zone in ["backup_fetch_conn_all", "backup_mutation_conn_all"] {
            assert!(zones.contains(&format!("zone={zone}:1m;")));
        }
        let fetch = nginx_exact_location(config, "/api/v1/wallet-backups/fetch")?;
        assert!(fetch.contains("limit_conn backup_fetch_conn_all 96;"));
        assert!(!fetch.contains("backup_mutation_conn_all"));
        let mutation = nginx_exact_location(config, "/api/v1/wallet-backups")?;
        assert!(mutation.contains("limit_conn backup_mutation_conn_all 32;"));
        assert!(!mutation.contains("backup_fetch_conn_all"));
        Ok(())
    }

    #[test]
    fn nginx_backup_routes_require_bounded_fixed_length_bodies() -> Result<(), String> {
        let config = include_str!("../deploy/nginx/backup-server.conf");
        for path in ["/api/v1/wallet-backups/fetch", "/api/v1/wallet-backups"] {
            let location = nginx_exact_location(config, path)?;
            for directive in [
                "if ($http_content_length = \"\") { return 400; }",
                "if ($http_transfer_encoding != \"\") { return 400; }",
                "error_page 400 = @backup_invalid_request;",
                "proxy_request_buffering on;",
            ] {
                assert!(
                    location.lines().any(|line| line.trim() == directive),
                    "{path}: {directive}"
                );
            }
        }
        let rejection = nginx_named_location(config, "backup_invalid_request")?;
        for directive in ["internal;", "access_log off;", "error_log stderr crit;"] {
            assert!(rejection.lines().any(|line| line.trim() == directive));
        }
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn signed_store_and_fetch_match_http_contract() -> Result<(), String> {
        let (directory, owner, state) = test_state("http")?;
        let secp = Secp256k1::new();
        let secret =
            SecretKey::from_byte_array([1_u8; 32]).map_err(|_| "invalid test secret".to_owned())?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let npub = keypair.x_only_public_key().0.to_string();
        let timestamp = unix_time().map_err(|_| "clock unavailable".to_owned())?;
        let ciphertext = "AAECAw==";
        let ciphertext_hash = "054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8";
        let store_message = build_signing_message(
            STORE_ACTION,
            BackupStream::WalletBackup,
            &npub,
            1,
            None,
            Some(ciphertext_hash),
            4,
            timestamp,
        );
        let store_digest: [u8; 32] = Sha256::digest(store_message).into();
        let store_signature = secp
            .sign_schnorr_no_aux_rand(&store_digest, &keypair)
            .to_string();
        let store_body = serde_json::json!({
            "version": 1,
            "stream": "wallet_backup",
            "npub": npub,
            "generation": 1,
            "expected_etag": null,
            "ciphertext": ciphertext,
            "ciphertext_sha256": ciphertext_hash,
            "ciphertext_bytes": 4,
            "timestamp": timestamp,
            "signature": store_signature
        });
        let store_request = Request::builder()
            .method("PUT")
            .uri("/api/v1/wallet-backups")
            .header("content-type", "application/json")
            .header("x-real-ip", "192.0.2.1")
            .body(Body::from(store_body.to_string()))
            .map_err(|_| "failed to build store request".to_owned())?;
        let store_response = test_router(state.clone())
            .oneshot(store_request)
            .await
            .map_err(|_| "store router failed".to_owned())?;
        assert_eq!(store_response.status(), StatusCode::OK);
        assert_eq!(
            store_response.headers().get("cache-control"),
            Some(&HeaderValue::from_static("private, no-store, max-age=0"))
        );
        assert!(
            store_response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
        let store_json: serde_json::Value = serde_json::from_slice(
            &to_bytes(store_response.into_body(), 4096)
                .await
                .map_err(|_| "failed to read store response".to_owned())?,
        )
        .map_err(|_| "invalid store response JSON".to_owned())?;
        assert_eq!(
            store_json
                .get("generation")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );

        let fetch_message = build_signing_message(
            FETCH_ACTION,
            BackupStream::WalletBackup,
            &npub,
            0,
            None,
            None,
            0,
            timestamp,
        );
        let fetch_digest: [u8; 32] = Sha256::digest(fetch_message).into();
        let fetch_signature = secp
            .sign_schnorr_no_aux_rand(&fetch_digest, &keypair)
            .to_string();
        let fetch_body = serde_json::json!({
            "version": 1,
            "stream": "wallet_backup",
            "npub": npub,
            "timestamp": timestamp,
            "signature": fetch_signature
        });
        let fetch_request = Request::builder()
            .method("POST")
            .uri("/api/v1/wallet-backups/fetch")
            .header("content-type", "application/json")
            .header("x-real-ip", "192.0.2.1")
            .body(Body::from(fetch_body.to_string()))
            .map_err(|_| "failed to build fetch request".to_owned())?;
        let fetch_response = test_router(state)
            .oneshot(fetch_request)
            .await
            .map_err(|_| "fetch router failed".to_owned())?;
        assert_eq!(fetch_response.status(), StatusCode::OK);
        let fetch_json: serde_json::Value = serde_json::from_slice(
            &to_bytes(fetch_response.into_body(), 4096)
                .await
                .map_err(|_| "failed to read fetch response".to_owned())?,
        )
        .map_err(|_| "invalid fetch response JSON".to_owned())?;
        assert_eq!(
            fetch_json.get("found").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            fetch_json
                .get("ciphertext")
                .and_then(serde_json::Value::as_str),
            Some(ciphertext)
        );
        assert_eq!(
            fetch_json
                .get("ciphertext_sha256")
                .and_then(serde_json::Value::as_str),
            Some(ciphertext_hash)
        );
        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn store_signature_precedes_payload_semantics() -> Result<(), String> {
        let (directory, owner, state) = test_state("precedence")?;
        let timestamp = unix_time().map_err(|_| "clock unavailable".to_owned())?;
        let npub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let oversized = serde_json::json!({
            "version": 1,
            "stream": "wallet_backup",
            "npub": npub,
            "generation": 1,
            "expected_etag": null,
            "ciphertext": "",
            "ciphertext_sha256": hash,
            "ciphertext_bytes": ABSOLUTE_MAX_CIPHERTEXT_BYTES + 1,
            "timestamp": timestamp,
            "signature": "00".repeat(64)
        });
        let oversized_request = Request::builder()
            .method("PUT")
            .uri("/api/v1/wallet-backups")
            .header("content-type", "application/json")
            .header("x-real-ip", "192.0.2.2")
            .body(Body::from(oversized.to_string()))
            .map_err(|_| "failed to build oversized request".to_owned())?;
        let oversized_response = test_router(state.clone())
            .oneshot(oversized_request)
            .await
            .map_err(|_| "oversized router failed".to_owned())?;
        assert_eq!(oversized_response.status(), StatusCode::UNAUTHORIZED);

        let secp = Secp256k1::new();
        let mut secret_bytes = [0_u8; 32];
        secret_bytes[31] = 1;
        let secret = SecretKey::from_byte_array(secret_bytes)
            .map_err(|_| "invalid test secret".to_owned())?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let oversized_message = build_signing_message(
            STORE_ACTION,
            BackupStream::WalletBackup,
            npub,
            1,
            None,
            Some(hash),
            u64::try_from(ABSOLUTE_MAX_CIPHERTEXT_BYTES)
                .map_err(|_| "test ciphertext limit is out of range".to_owned())?
                + 1,
            timestamp,
        );
        let oversized_digest: [u8; 32] = Sha256::digest(oversized_message).into();
        let oversized_signature = secp
            .sign_schnorr_no_aux_rand(&oversized_digest, &keypair)
            .to_string();
        let mut signed_oversized = oversized;
        replace_json_field(
            &mut signed_oversized,
            "signature",
            serde_json::Value::String(oversized_signature),
        )?;
        let signed_oversized_request = Request::builder()
            .method("PUT")
            .uri("/api/v1/wallet-backups")
            .header("content-type", "application/json")
            .header("x-real-ip", "192.0.2.2")
            .body(Body::from(signed_oversized.to_string()))
            .map_err(|_| "failed to build signed oversized request".to_owned())?;
        let signed_oversized_response = test_router(state.clone())
            .oneshot(signed_oversized_request)
            .await
            .map_err(|_| "signed oversized router failed".to_owned())?;
        assert_eq!(
            signed_oversized_response.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );

        let malformed = serde_json::json!({
            "version": 1,
            "stream": "wallet_backup",
            "npub": npub,
            "generation": 1,
            "expected_etag": null,
            "ciphertext": "not-base64",
            "ciphertext_sha256": hash,
            "ciphertext_bytes": 1,
            "timestamp": timestamp,
            "signature": "00".repeat(64)
        });
        let malformed_request = Request::builder()
            .method("PUT")
            .uri("/api/v1/wallet-backups")
            .header("content-type", "application/json")
            .header("x-real-ip", "192.0.2.2")
            .body(Body::from(malformed.to_string()))
            .map_err(|_| "failed to build malformed request".to_owned())?;
        let malformed_response = test_router(state)
            .oneshot(malformed_request)
            .await
            .map_err(|_| "malformed router failed".to_owned())?;
        assert_eq!(malformed_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            malformed_response.headers().get("cache-control"),
            Some(&HeaderValue::from_static("private, no-store, max-age=0"))
        );
        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn tamper_matrix_matches_http_errors() -> Result<(), String> {
        let fixture: TamperFixture =
            serde_json::from_str(include_str!("../tests/fixtures/wallet-backup-v1.json"))
                .map_err(|_| "invalid tamper fixture".to_owned())?;
        let secret_bytes: [u8; 32] = hex::decode(&fixture.test_only_secret_key)
            .map_err(|_| "invalid fixture secret".to_owned())?
            .try_into()
            .map_err(|_| "invalid fixture secret".to_owned())?;
        let secp = Secp256k1::new();
        let secret = SecretKey::from_byte_array(secret_bytes)
            .map_err(|_| "invalid fixture secret".to_owned())?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        assert_eq!(keypair.x_only_public_key().0.to_string(), fixture.npub);

        let (directory, owner, state) = test_state("tamper")?;
        let ciphertext = [0_u8, 1, 2, 3];
        let ciphertext_hash = hex::encode(Sha256::digest(ciphertext));
        let timestamp = unix_time().map_err(|_| "clock unavailable".to_owned())?;
        let baseline_message = build_signing_message(
            STORE_ACTION,
            BackupStream::WalletBackup,
            &fixture.npub,
            1,
            None,
            Some(&ciphertext_hash),
            4,
            timestamp,
        );
        let baseline_digest: [u8; 32] = Sha256::digest(baseline_message).into();
        let baseline_signature = secp
            .sign_schnorr_no_aux_rand(&baseline_digest, &keypair)
            .to_string();
        let baseline = serde_json::json!({
            "version": 1,
            "stream": "wallet_backup",
            "npub": fixture.npub.clone(),
            "generation": 1,
            "expected_etag": null,
            "ciphertext": BASE64_STANDARD.encode(ciphertext),
            "ciphertext_sha256": ciphertext_hash,
            "ciphertext_bytes": 4,
            "timestamp": timestamp,
            "signature": baseline_signature,
        });

        for tamper in fixture.tamper_cases {
            let expected_status = match tamper.expected_code.as_str() {
                "BackupInvalidRequest" => StatusCode::BAD_REQUEST,
                "BackupAuthError" => StatusCode::UNAUTHORIZED,
                _ => return Err("fixture contains an unknown error code".to_owned()),
            };
            let (method, body) = if tamper.field == "action" {
                let expected_etag = "11".repeat(32);
                let message = build_signing_message(
                    STORE_ACTION,
                    BackupStream::WalletBackup,
                    &fixture.npub,
                    1,
                    Some(&expected_etag),
                    None,
                    0,
                    timestamp,
                );
                let digest: [u8; 32] = Sha256::digest(message).into();
                let signature = secp.sign_schnorr_no_aux_rand(&digest, &keypair).to_string();
                (
                    "DELETE",
                    serde_json::json!({
                        "version": 1,
                        "stream": "wallet_backup",
                        "npub": fixture.npub.clone(),
                        "generation": 1,
                        "expected_etag": expected_etag,
                        "timestamp": timestamp,
                        "signature": signature,
                    }),
                )
            } else {
                let mut body = baseline.clone();
                match tamper.field.as_str() {
                    "stream" => {
                        replace_json_field(
                            &mut body,
                            "stream",
                            serde_json::Value::String("keychain_manifest".to_owned()),
                        )?;
                    }
                    "generation" => {
                        replace_json_field(&mut body, "generation", serde_json::Value::from(2))?;
                    }
                    "expected_etag" => {
                        replace_json_field(
                            &mut body,
                            "expected_etag",
                            serde_json::Value::String("22".repeat(32)),
                        )?;
                    }
                    "ciphertext_sha256" => {
                        let tampered_hash = "33".repeat(32);
                        let message = build_signing_message(
                            STORE_ACTION,
                            BackupStream::WalletBackup,
                            &fixture.npub,
                            1,
                            None,
                            Some(&tampered_hash),
                            4,
                            timestamp,
                        );
                        let digest: [u8; 32] = Sha256::digest(message).into();
                        replace_json_field(
                            &mut body,
                            "ciphertext_sha256",
                            serde_json::Value::String(tampered_hash),
                        )?;
                        replace_json_field(
                            &mut body,
                            "signature",
                            serde_json::Value::String(
                                secp.sign_schnorr_no_aux_rand(&digest, &keypair).to_string(),
                            ),
                        )?;
                    }
                    "ciphertext_bytes" => {
                        let message = build_signing_message(
                            STORE_ACTION,
                            BackupStream::WalletBackup,
                            &fixture.npub,
                            1,
                            None,
                            Some(&ciphertext_hash),
                            5,
                            timestamp,
                        );
                        let digest: [u8; 32] = Sha256::digest(message).into();
                        replace_json_field(
                            &mut body,
                            "ciphertext_bytes",
                            serde_json::Value::from(5),
                        )?;
                        replace_json_field(
                            &mut body,
                            "signature",
                            serde_json::Value::String(
                                secp.sign_schnorr_no_aux_rand(&digest, &keypair).to_string(),
                            ),
                        )?;
                    }
                    "timestamp" => {
                        replace_json_field(
                            &mut body,
                            "timestamp",
                            serde_json::Value::from(
                                timestamp
                                    .checked_add(1)
                                    .ok_or_else(|| "test timestamp overflow".to_owned())?,
                            ),
                        )?;
                    }
                    "signature" => {
                        let signature =
                            body.get("signature")
                                .and_then(serde_json::Value::as_str)
                                .ok_or_else(|| "baseline signature is missing".to_owned())?;
                        let mut bytes = signature.as_bytes().to_vec();
                        let first = bytes
                            .first_mut()
                            .ok_or_else(|| "baseline signature is empty".to_owned())?;
                        *first = if *first == b'0' { b'1' } else { b'0' };
                        let signature = String::from_utf8(bytes)
                            .map_err(|_| "tampered signature is not UTF-8".to_owned())?;
                        replace_json_field(
                            &mut body,
                            "signature",
                            serde_json::Value::String(signature),
                        )?;
                    }
                    _ => return Err("fixture contains an unknown tamper field".to_owned()),
                }
                ("PUT", body)
            };
            let (status, code) = send_test_json(state.clone(), method, body).await?;
            assert_eq!(status, expected_status, "{}", tamper.field);
            assert_eq!(code, tamper.expected_code, "{}", tamper.field);
        }

        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[derive(serde::Deserialize)]
    struct DescriptorTamperFixture {
        ciphertext: String,
        ciphertext_bytes: u64,
        ciphertext_sha256: String,
        lookup_tokens: Vec<String>,
        tamper_cases: Vec<TamperCase>,
        vectors: Vec<DescriptorFixtureVector>,
    }

    #[derive(serde::Deserialize)]
    struct DescriptorFixtureVector {
        npub: String,
        test_only_secret_key: String,
    }

    const DESCRIPTOR_STORE_PATH: &str = "/api/v1/descriptor-backups";
    const DESCRIPTOR_LOOKUP_PATH: &str = "/api/v1/descriptor-backups/lookup";

    fn descriptor_fixture() -> Result<DescriptorTamperFixture, String> {
        serde_json::from_str(include_str!("../tests/fixtures/descriptor-backup-v1.json"))
            .map_err(|_| "invalid descriptor fixture".to_owned())
    }

    fn fixture_keypair(secret_hex: &str) -> Result<Keypair, String> {
        let bytes: [u8; 32] = hex::decode(secret_hex)
            .map_err(|_| "invalid fixture secret".to_owned())?
            .try_into()
            .map_err(|_| "invalid fixture secret".to_owned())?;
        let secret =
            SecretKey::from_byte_array(bytes).map_err(|_| "invalid fixture secret".to_owned())?;
        Ok(Keypair::from_secret_key(&Secp256k1::new(), &secret))
    }

    fn descriptor_token(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn signed_descriptor_body(
        keypair: &Keypair,
        ciphertext: &[u8],
        tokens: &[String],
        timestamp: u64,
    ) -> Result<serde_json::Value, String> {
        let npub = keypair.x_only_public_key().0.to_string();
        let hash = hex::encode(Sha256::digest(ciphertext));
        let bytes =
            u64::try_from(ciphertext.len()).map_err(|_| "test ciphertext overflow".to_owned())?;
        let message = build_descriptor_signing_message(
            DESCRIPTOR_STORE_ACTION,
            &npub,
            &hash,
            bytes,
            tokens,
            timestamp,
        );
        let digest: [u8; 32] = Sha256::digest(message).into();
        let signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&digest, keypair)
            .to_string();
        Ok(serde_json::json!({
            "version": 1,
            "npub": npub,
            "ciphertext": BASE64_STANDARD.encode(ciphertext),
            "ciphertext_sha256": hash,
            "ciphertext_bytes": bytes,
            "lookup_tokens": tokens,
            "timestamp": timestamp,
            "signature": signature,
        }))
    }

    async fn send_descriptor(
        state: AppState,
        path: &'static str,
        body: &serde_json::Value,
    ) -> Result<(StatusCode, serde_json::Value), String> {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("x-real-ip", "192.0.2.11")
            .body(Body::from(body.to_string()))
            .map_err(|_| "failed to build descriptor request".to_owned())?;
        let response = test_router(state)
            .oneshot(request)
            .await
            .map_err(|_| "descriptor router failed".to_owned())?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .map_err(|_| "failed to read descriptor response".to_owned())?;
        let value = serde_json::from_slice(&bytes)
            .map_err(|_| "invalid descriptor response JSON".to_owned())?;
        Ok((status, value))
    }

    fn response_code(value: &serde_json::Value) -> Result<&str, String> {
        value
            .get("code")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "descriptor response code is missing".to_owned())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn signed_descriptor_store_and_lookup_match_http_contract() -> Result<(), String> {
        let (directory, owner, state) = test_state("descriptor-http")?;
        let fixture = descriptor_fixture()?;
        let publisher = fixture
            .vectors
            .first()
            .ok_or_else(|| "fixture vector is missing".to_owned())?;
        let keypair = fixture_keypair(&publisher.test_only_secret_key)?;
        let timestamp = unix_time().map_err(|_| "clock unavailable".to_owned())?;
        let ciphertext = (0_u8..32).collect::<Vec<_>>();
        let body =
            signed_descriptor_body(&keypair, &ciphertext, &fixture.lookup_tokens, timestamp)?;

        let (status, stored) = send_descriptor(state.clone(), DESCRIPTOR_STORE_PATH, &body).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            stored
                .get("ciphertext_sha256")
                .and_then(serde_json::Value::as_str),
            Some(fixture.ciphertext_sha256.as_str())
        );
        let created_at = stored
            .get("created_at")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| "created_at is missing".to_owned())?;

        // Idempotent retry: same answer, same creation time.
        let (retry_status, retried) =
            send_descriptor(state.clone(), DESCRIPTOR_STORE_PATH, &body).await?;
        assert_eq!(retry_status, StatusCode::OK);
        assert_eq!(
            retried
                .get("created_at")
                .and_then(serde_json::Value::as_i64),
            Some(created_at)
        );

        for token in &fixture.lookup_tokens {
            let lookup = serde_json::json!({"version": 1, "lookup_tokens": [token]});
            let (lookup_status, found) =
                send_descriptor(state.clone(), DESCRIPTOR_LOOKUP_PATH, &lookup).await?;
            assert_eq!(lookup_status, StatusCode::OK);
            assert!(
                found
                    .get("next_cursor")
                    .is_some_and(serde_json::Value::is_null)
            );
            let records = found
                .get("records")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| "records are missing".to_owned())?;
            assert_eq!(records.len(), 1);
            let record = records
                .first()
                .ok_or_else(|| "record is missing".to_owned())?;
            assert_eq!(
                record.get("ciphertext").and_then(serde_json::Value::as_str),
                Some(fixture.ciphertext.as_str())
            );
            assert_eq!(
                record
                    .get("ciphertext_bytes")
                    .and_then(serde_json::Value::as_u64),
                Some(fixture.ciphertext_bytes)
            );
            // A reader never learns who published, or which other tokens exist.
            let serialized = found.to_string();
            assert!(!serialized.contains(&publisher.npub));
            for other in &fixture.lookup_tokens {
                assert!(!serialized.contains(other.as_str()));
            }
        }

        let unknown = serde_json::json!({
            "version": 1,
            "lookup_tokens": [descriptor_token(0xfe)]
        });
        let (unknown_status, empty) =
            send_descriptor(state.clone(), DESCRIPTOR_LOOKUP_PATH, &unknown).await?;
        assert_eq!(unknown_status, StatusCode::OK);
        assert_eq!(
            empty
                .get("records")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        // A different token set under the same record identity is refused.
        let mut conflicting = fixture.lookup_tokens.clone();
        conflicting.pop();
        let conflict_body = signed_descriptor_body(&keypair, &ciphertext, &conflicting, timestamp)?;
        let (conflict_status, conflict) =
            send_descriptor(state.clone(), DESCRIPTOR_STORE_PATH, &conflict_body).await?;
        assert_eq!(conflict_status, StatusCode::CONFLICT);
        assert_eq!(response_code(&conflict)?, "DescriptorRecordConflict");

        // A second publisher publishes under the same tokens without changing
        // the first publisher's record.
        let second = fixture
            .vectors
            .get(1)
            .ok_or_else(|| "second fixture vector is missing".to_owned())?;
        let other = fixture_keypair(&second.test_only_secret_key)?;
        let other_ciphertext = vec![0xab_u8; 48];
        let other_body =
            signed_descriptor_body(&other, &other_ciphertext, &fixture.lookup_tokens, timestamp)?;
        let (other_status, _) =
            send_descriptor(state.clone(), DESCRIPTOR_STORE_PATH, &other_body).await?;
        assert_eq!(other_status, StatusCode::OK);
        let first_token = fixture
            .lookup_tokens
            .first()
            .ok_or_else(|| "fixture token is missing".to_owned())?;
        let lookup = serde_json::json!({"version": 1, "lookup_tokens": [first_token]});
        let (_, both) = send_descriptor(state.clone(), DESCRIPTOR_LOOKUP_PATH, &lookup).await?;
        let records = both
            .get("records")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "records are missing".to_owned())?;
        assert_eq!(records.len(), 2);
        let original_still_present = records.iter().any(|record| {
            record.get("ciphertext").and_then(serde_json::Value::as_str)
                == Some(fixture.ciphertext.as_str())
        });
        assert!(original_still_present);

        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    /// Two publishers under one token with a one-record page: the older record
    /// is reachable only by following the cursor, and the cursor is opaque.
    #[tokio::test]
    async fn descriptor_lookup_pages_through_history_by_cursor() -> Result<(), String> {
        let (directory, owner, mut state) = test_state("descriptor-paging")?;
        state.descriptor_lookup_bounds = DescriptorLookupBounds {
            record_cap: 1,
            byte_budget: 1 << 20,
        };
        let fixture = descriptor_fixture()?;
        let timestamp = unix_time().map_err(|_| "clock unavailable".to_owned())?;
        for (index, vector) in fixture.vectors.iter().take(2).enumerate() {
            let keypair = fixture_keypair(&vector.test_only_secret_key)?;
            let ciphertext = vec![u8::try_from(index).unwrap_or(0); 32 + index];
            let body =
                signed_descriptor_body(&keypair, &ciphertext, &fixture.lookup_tokens, timestamp)?;
            let (status, _) = send_descriptor(state.clone(), DESCRIPTOR_STORE_PATH, &body).await?;
            assert_eq!(status, StatusCode::OK);
        }
        let token = fixture
            .lookup_tokens
            .first()
            .ok_or_else(|| "fixture token is missing".to_owned())?;

        let lookup = serde_json::json!({"version": 1, "lookup_tokens": [token]});
        let (status, first) =
            send_descriptor(state.clone(), DESCRIPTOR_LOOKUP_PATH, &lookup).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            first
                .get("records")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        let cursor = first
            .get("next_cursor")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "a truncated page must carry a cursor".to_owned())?
            .to_owned();
        // The cursor names a position, never a publisher or a token.
        for vector in &fixture.vectors {
            assert!(!cursor.contains(&vector.npub));
        }
        for other in &fixture.lookup_tokens {
            assert!(!cursor.contains(other.as_str()));
        }

        let next = serde_json::json!({"version": 1, "lookup_tokens": [token], "cursor": cursor});
        let (next_status, second) =
            send_descriptor(state.clone(), DESCRIPTOR_LOOKUP_PATH, &next).await?;
        assert_eq!(next_status, StatusCode::OK);
        assert_eq!(
            second
                .get("records")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        assert!(
            second
                .get("next_cursor")
                .is_some_and(serde_json::Value::is_null)
        );
        assert_ne!(first.get("records"), second.get("records"));

        // A malformed cursor is a bad request, never a silent restart from
        // the newest page.
        let forged =
            serde_json::json!({"version": 1, "lookup_tokens": [token], "cursor": "not-base64!"});
        let (forged_status, forged_body) =
            send_descriptor(state.clone(), DESCRIPTOR_LOOKUP_PATH, &forged).await?;
        assert_eq!(forged_status, StatusCode::BAD_REQUEST);
        assert_eq!(response_code(&forged_body)?, "DescriptorInvalidRequest");

        // Unknown fields are still refused, cursor or no cursor.
        let unknown = serde_json::json!({"version": 1, "lookup_tokens": [token], "page": cursor});
        let (unknown_status, _) =
            send_descriptor(state.clone(), DESCRIPTOR_LOOKUP_PATH, &unknown).await?;
        assert_eq!(unknown_status, StatusCode::BAD_REQUEST);

        // Possessing a cursor does not grant the original token's read access.
        let unrelated = serde_json::json!({
            "version": 1, "lookup_tokens": [descriptor_token(0xfe)], "cursor": cursor
        });
        let (unrelated_status, unrelated_body) =
            send_descriptor(state.clone(), DESCRIPTOR_LOOKUP_PATH, &unrelated).await?;
        assert_eq!(unrelated_status, StatusCode::OK);
        assert_eq!(unrelated_body.get("records"), Some(&serde_json::json!([])));
        assert_eq!(
            unrelated_body.get("next_cursor"),
            Some(&serde_json::Value::Null)
        );

        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn descriptor_tamper_matrix_matches_http_errors() -> Result<(), String> {
        let (directory, owner, state) = test_state("descriptor-tamper")?;
        let fixture = descriptor_fixture()?;
        let publisher = fixture
            .vectors
            .first()
            .ok_or_else(|| "fixture vector is missing".to_owned())?;
        let keypair = fixture_keypair(&publisher.test_only_secret_key)?;
        assert_eq!(keypair.x_only_public_key().0.to_string(), publisher.npub);
        let timestamp = unix_time().map_err(|_| "clock unavailable".to_owned())?;
        let ciphertext = (0_u8..32).collect::<Vec<_>>();
        let baseline =
            signed_descriptor_body(&keypair, &ciphertext, &fixture.lookup_tokens, timestamp)?;

        for tamper in &fixture.tamper_cases {
            let expected_status = match tamper.expected_code.as_str() {
                "DescriptorInvalidRequest" => StatusCode::BAD_REQUEST,
                "DescriptorAuthError" => StatusCode::UNAUTHORIZED,
                _ => return Err("fixture contains an unknown error code".to_owned()),
            };
            let mut body = baseline.clone();
            match tamper.field.as_str() {
                "version" => {
                    replace_json_field(&mut body, "version", serde_json::Value::from(2))?;
                }
                "npub" => {
                    let other = fixture
                        .vectors
                        .get(1)
                        .ok_or_else(|| "second fixture vector is missing".to_owned())?;
                    replace_json_field(
                        &mut body,
                        "npub",
                        serde_json::Value::String(other.npub.clone()),
                    )?;
                }
                "ciphertext_sha256" => {
                    let tampered = "33".repeat(32);
                    let re_signed = signed_descriptor_body(
                        &keypair,
                        &ciphertext,
                        &fixture.lookup_tokens,
                        timestamp,
                    )?;
                    let message = build_descriptor_signing_message(
                        DESCRIPTOR_STORE_ACTION,
                        &publisher.npub,
                        &tampered,
                        fixture.ciphertext_bytes,
                        &fixture.lookup_tokens,
                        timestamp,
                    );
                    let digest: [u8; 32] = Sha256::digest(message).into();
                    body = re_signed;
                    replace_json_field(
                        &mut body,
                        "ciphertext_sha256",
                        serde_json::Value::String(tampered),
                    )?;
                    replace_json_field(
                        &mut body,
                        "signature",
                        serde_json::Value::String(
                            Secp256k1::new()
                                .sign_schnorr_no_aux_rand(&digest, &keypair)
                                .to_string(),
                        ),
                    )?;
                }
                "ciphertext_bytes" => {
                    let message = build_descriptor_signing_message(
                        DESCRIPTOR_STORE_ACTION,
                        &publisher.npub,
                        &fixture.ciphertext_sha256,
                        fixture.ciphertext_bytes + 1,
                        &fixture.lookup_tokens,
                        timestamp,
                    );
                    let digest: [u8; 32] = Sha256::digest(message).into();
                    replace_json_field(
                        &mut body,
                        "ciphertext_bytes",
                        serde_json::Value::from(fixture.ciphertext_bytes + 1),
                    )?;
                    replace_json_field(
                        &mut body,
                        "signature",
                        serde_json::Value::String(
                            Secp256k1::new()
                                .sign_schnorr_no_aux_rand(&digest, &keypair)
                                .to_string(),
                        ),
                    )?;
                }
                "lookup_tokens_order" => {
                    let mut reversed = fixture.lookup_tokens.clone();
                    reversed.reverse();
                    replace_json_field(
                        &mut body,
                        "lookup_tokens",
                        serde_json::Value::from(reversed),
                    )?;
                }
                "lookup_tokens_member" => {
                    let mut swapped = fixture.lookup_tokens.clone();
                    let last = swapped
                        .last_mut()
                        .ok_or_else(|| "fixture token is missing".to_owned())?;
                    *last = descriptor_token(0xff);
                    replace_json_field(
                        &mut body,
                        "lookup_tokens",
                        serde_json::Value::from(swapped),
                    )?;
                }
                "timestamp" => {
                    replace_json_field(
                        &mut body,
                        "timestamp",
                        serde_json::Value::from(
                            timestamp
                                .checked_add(1)
                                .ok_or_else(|| "test timestamp overflow".to_owned())?,
                        ),
                    )?;
                }
                "signature" => {
                    replace_json_field(
                        &mut body,
                        "signature",
                        serde_json::Value::String("00".repeat(64)),
                    )?;
                }
                _ => return Err("fixture contains an unknown tamper field".to_owned()),
            }
            let (status, value) =
                send_descriptor(state.clone(), DESCRIPTOR_STORE_PATH, &body).await?;
            assert_eq!(status, expected_status, "{}", tamper.field);
            assert_eq!(
                response_code(&value)?,
                tamper.expected_code,
                "{}",
                tamper.field
            );
        }

        // Malformed hex and out-of-range token counts are refused before any
        // signature work.
        for tokens in [
            serde_json::json!([]),
            serde_json::json!(["not-hex"]),
            serde_json::json!([descriptor_token(1), descriptor_token(1)]),
            serde_json::Value::from((0_u8..=16).map(descriptor_token).collect::<Vec<_>>()),
        ] {
            let mut body = baseline.clone();
            replace_json_field(&mut body, "lookup_tokens", tokens)?;
            let (status, value) =
                send_descriptor(state.clone(), DESCRIPTOR_STORE_PATH, &body).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(response_code(&value)?, "DescriptorInvalidRequest");
            let mut lookup = serde_json::json!({"version": 1, "lookup_tokens": []});
            replace_json_field(
                &mut lookup,
                "lookup_tokens",
                body.get("lookup_tokens")
                    .cloned()
                    .ok_or_else(|| "tokens are missing".to_owned())?,
            )?;
            let (lookup_status, lookup_value) =
                send_descriptor(state.clone(), DESCRIPTOR_LOOKUP_PATH, &lookup).await?;
            assert_eq!(lookup_status, StatusCode::BAD_REQUEST);
            assert_eq!(response_code(&lookup_value)?, "DescriptorInvalidRequest");
        }

        // A stale timestamp fails authentication even with a valid signature.
        let expired_request = signed_descriptor_body(
            &keypair,
            &ciphertext,
            &fixture.lookup_tokens,
            timestamp.saturating_sub(protocol::TIMESTAMP_WINDOW_SECS + 1),
        )?;
        let (expired_status, expired_value) =
            send_descriptor(state.clone(), DESCRIPTOR_STORE_PATH, &expired_request).await?;
        assert_eq!(expired_status, StatusCode::UNAUTHORIZED);
        assert_eq!(response_code(&expired_value)?, "DescriptorAuthError");

        // Ciphertext that does not match its signed length or hash is refused.
        let mut mismatched = baseline.clone();
        replace_json_field(
            &mut mismatched,
            "ciphertext",
            serde_json::Value::String(BASE64_STANDARD.encode([1_u8, 2, 3])),
        )?;
        let (mismatched_status, mismatched_value) =
            send_descriptor(state.clone(), DESCRIPTOR_STORE_PATH, &mismatched).await?;
        assert_eq!(mismatched_status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response_code(&mismatched_value)?,
            "DescriptorInvalidRequest"
        );

        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn descriptor_requests_never_log_tokens_or_publishers() -> Result<(), String> {
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&output);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_target(false)
            .with_writer(move || TestLogWriter(Arc::clone(&writer)))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let (directory, owner, state) = test_state("descriptor-logs")?;
        let fixture = descriptor_fixture()?;
        let publisher = fixture
            .vectors
            .first()
            .ok_or_else(|| "fixture vector is missing".to_owned())?;
        let keypair = fixture_keypair(&publisher.test_only_secret_key)?;
        let timestamp = unix_time().map_err(|_| "clock unavailable".to_owned())?;
        let ciphertext = (0_u8..32).collect::<Vec<_>>();
        let body =
            signed_descriptor_body(&keypair, &ciphertext, &fixture.lookup_tokens, timestamp)?;
        let (status, _) = send_descriptor(state.clone(), DESCRIPTOR_STORE_PATH, &body).await?;
        assert_eq!(status, StatusCode::OK);
        let lookup = serde_json::json!({
            "version": 1,
            "lookup_tokens": fixture.lookup_tokens.clone()
        });
        let (lookup_status, _) =
            send_descriptor(state.clone(), DESCRIPTOR_LOOKUP_PATH, &lookup).await?;
        assert_eq!(lookup_status, StatusCode::OK);

        state
            .descriptor_totals
            .emit(state.storage.descriptor_metrics_snapshot());
        state.request_totals.emit(state.storage.metrics_snapshot());
        let logs = {
            let bytes = output
                .lock()
                .map_err(|_| "test log lock poisoned".to_owned())?
                .clone();
            String::from_utf8(bytes).map_err(|_| "test log is not UTF-8".to_owned())?
        };
        assert!(logs.contains("descriptor_backup_request_totals"));
        assert!(logs.contains("store_requests=1"));
        assert!(logs.contains("lookup_requests=1"));
        assert!(logs.contains("current_records=1"));
        assert!(!logs.contains(&publisher.npub));
        assert!(!logs.contains(&fixture.ciphertext_sha256));
        assert!(!logs.contains(&fixture.ciphertext));
        for token in &fixture.lookup_tokens {
            assert!(!logs.contains(token.as_str()));
        }
        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[test]
    fn descriptor_totals_have_fixed_exact_outcomes() {
        let totals = DescriptorTotals::new(Duration::from_secs(60));
        let outcomes = [
            Ok(()),
            Err(DescriptorApiError::InvalidRequest("test")),
            Err(DescriptorApiError::Authentication),
            Err(DescriptorApiError::RecordConflict),
            Err(DescriptorApiError::PublisherQuota),
            Err(DescriptorApiError::BlobTooLarge),
            Err(DescriptorApiError::RateLimited {
                retry_after_secs: 1,
                kind: RateLimitKind::Npub,
            }),
            Err(DescriptorApiError::Capacity),
            Err(DescriptorApiError::Internal),
            Err(DescriptorApiError::RateLimited {
                retry_after_secs: 1,
                kind: RateLimitKind::Overflow,
            }),
            Err(DescriptorApiError::RateLimited {
                retry_after_secs: 1,
                kind: RateLimitKind::Saturation,
            }),
            Err(DescriptorApiError::RateLimited {
                retry_after_secs: 1,
                kind: RateLimitKind::Admission,
            }),
        ];
        for (index, outcome) in outcomes.into_iter().enumerate() {
            let operation = if index % 2 == 0 {
                DescriptorOperation::Store
            } else {
                DescriptorOperation::Lookup
            };
            totals.record(operation, &outcome);
        }
        assert_eq!(totals.take(), [1, 1, 1, 1, 1, 1, 4, 1, 1, 1, 1, 1, 1, 6, 6]);
        assert_eq!(totals.take(), [0; DESCRIPTOR_TOTALS]);
    }

    #[tokio::test]
    async fn descriptor_body_ceilings_reject_one_byte_over() -> Result<(), String> {
        let (directory, owner, state) = test_state("descriptor-body-limits")?;
        for (uri, limit) in [
            (
                DESCRIPTOR_STORE_PATH,
                ABSOLUTE_MAX_DESCRIPTOR_STORE_BODY_BYTES,
            ),
            (DESCRIPTOR_LOOKUP_PATH, SMALL_BODY_LIMIT_BYTES),
        ] {
            let at_limit = Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("x-real-ip", "192.0.2.12")
                .body(Body::from(vec![b' '; limit]))
                .map_err(|_| "failed to build boundary request".to_owned())?;
            let at_limit_response = test_router(state.clone())
                .oneshot(at_limit)
                .await
                .map_err(|_| "boundary router failed".to_owned())?;
            assert_eq!(at_limit_response.status(), StatusCode::BAD_REQUEST);

            let over_limit = Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("x-real-ip", "192.0.2.12")
                .body(Body::from(vec![b' '; limit + 1]))
                .map_err(|_| "failed to build over-limit request".to_owned())?;
            let over_limit_response = test_router(state.clone())
                .oneshot(over_limit)
                .await
                .map_err(|_| "over-limit router failed".to_owned())?;
            assert_eq!(over_limit_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }

        // Missing source identity fails closed on both descriptor routes.
        for uri in [DESCRIPTOR_STORE_PATH, DESCRIPTOR_LOOKUP_PATH] {
            let request = Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .map_err(|_| "failed to build anonymous request".to_owned())?;
            let response = test_router(state.clone())
                .oneshot(request)
                .await
                .map_err(|_| "anonymous router failed".to_owned())?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        // The frozen wallet backup routes are unchanged by the new paths.
        let wallet = Request::builder()
            .method("POST")
            .uri(DESCRIPTOR_STORE_PATH)
            .header("content-type", "application/json")
            .header("x-real-ip", "192.0.2.12")
            .body(Body::from("{}"))
            .map_err(|_| "failed to build descriptor request".to_owned())?;
        let response = test_router(state.clone())
            .oneshot(wallet)
            .await
            .map_err(|_| "descriptor router failed".to_owned())?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 4096)
            .await
            .map_err(|_| "failed to read descriptor response".to_owned())?;
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| "invalid descriptor response JSON".to_owned())?;
        assert_eq!(response_code(&value)?, "DescriptorInvalidRequest");

        owner.shutdown().await?;
        fs::remove_dir_all(directory).map_err(|_| "failed to clean test directory".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn descriptor_ingress_error_bodies_match_application() -> Result<(), String> {
        let config = include_str!("../deploy/nginx/descriptor-backup.conf");
        let cases = [
            (
                DescriptorApiError::InvalidRequest("Descriptor backup request body is invalid."),
                400,
            ),
            (DescriptorApiError::BlobTooLarge, 413),
            (
                DescriptorApiError::RateLimited {
                    retry_after_secs: 60,
                    kind: RateLimitKind::Saturation,
                },
                429,
            ),
        ];
        for (error, status) in cases {
            let response = error.into_response();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(
                response.headers().get("cache-control"),
                Some(&HeaderValue::from_static("private, no-store, max-age=0"))
            );
            let body = to_bytes(response.into_body(), 1024)
                .await
                .map_err(|_| "failed to read descriptor error response".to_owned())?;
            assert_eq!(body.as_ref(), nginx_return_body(config, status)?.as_bytes());
        }
        Ok(())
    }

    #[test]
    fn nginx_recovery_routes_keep_all_admission_bounds() -> Result<(), String> {
        let config = include_str!("../deploy/nginx/recovery-backup.conf");
        let zones = include_str!("../deploy/nginx/backup-server-http.conf");
        for (path, operation, size, concurrency) in [
            ("/api/v1/arkade-recovery-records", "store", "192k", 8),
            ("/api/v1/arkade-recovery-records/fetch", "fetch", "4k", 24),
        ] {
            let location = nginx_exact_location(config, path)?;
            for directive in [
                "access_log off;".to_owned(),
                "error_log stderr crit;".to_owned(),
                "proxy_set_header X-Real-IP $remote_addr;".to_owned(),
                "proxy_set_header X-Forwarded-For \"\";".to_owned(),
                "proxy_set_header Forwarded \"\";".to_owned(),
                "proxy_request_buffering on;".to_owned(),
                "proxy_intercept_errors off;".to_owned(),
                "if ($http_content_length = \"\") { return 400; }".to_owned(),
                "if ($http_transfer_encoding != \"\") { return 400; }".to_owned(),
                "proxy_read_timeout 15s;".to_owned(),
                format!("client_max_body_size {size};"),
                format!("limit_req zone=recovery_{operation}_all burst=64 nodelay;"),
                format!("limit_conn recovery_{operation}_conn_all {concurrency};"),
            ] {
                assert!(
                    location.lines().any(|line| line.trim() == directive),
                    "{path}: {directive}"
                );
            }
            assert!(zones.contains(&format!("zone=recovery_{operation}_all:")));
            assert!(zones.contains(&format!("zone=recovery_{operation}_conn_all:")));
        }
        Ok(())
    }

    #[test]
    fn nginx_descriptor_routes_keep_all_admission_bounds() -> Result<(), String> {
        let locations = include_str!("../deploy/nginx/descriptor-backup.conf");
        let zones = include_str!("../deploy/nginx/backup-server-http.conf");
        for directive in [
            "limit_req_zone $binary_remote_addr zone=descriptor_req_ip:1m rate=5r/s;",
            "limit_req_zone $server_name zone=descriptor_store_all:1m rate=30r/m;",
            "limit_req_zone $server_name zone=descriptor_lookup_all:1m rate=60r/m;",
            "limit_conn_zone $binary_remote_addr zone=descriptor_conn_ip:1m;",
            "limit_conn_zone $server_name zone=descriptor_store_conn_all:1m;",
            "limit_conn_zone $server_name zone=descriptor_lookup_conn_all:1m;",
        ] {
            assert!(zones.contains(directive), "{directive}");
        }
        for path in [DESCRIPTOR_STORE_PATH, DESCRIPTOR_LOOKUP_PATH] {
            let location = nginx_exact_location(locations, path)?;
            for directive in [
                "access_log off;",
                "error_log stderr crit;",
                "if ($http_content_length = \"\") { return 400; }",
                "if ($http_transfer_encoding != \"\") { return 400; }",
                "limit_conn descriptor_conn_ip 8;",
                "limit_req_status 429;",
                "limit_conn_status 429;",
                "error_page 400 = @descriptor_invalid_request;",
                "error_page 413 = @descriptor_blob_too_large;",
                "error_page 429 = @descriptor_rate_limited;",
                "proxy_set_header X-Real-IP $remote_addr;",
                "proxy_set_header X-Forwarded-For \"\";",
                "proxy_set_header Forwarded \"\";",
                "proxy_request_buffering on;",
                "proxy_intercept_errors off;",
            ] {
                assert!(
                    location.lines().any(|line| line.trim() == directive),
                    "{path}: {directive}"
                );
            }
        }
        let store = nginx_exact_location(locations, DESCRIPTOR_STORE_PATH)?;
        assert!(store.contains("client_max_body_size 96k;"));
        assert!(store.contains("limit_conn descriptor_store_conn_all 32;"));
        assert!(!store.contains("descriptor_lookup_conn_all"));
        let lookup = nginx_exact_location(locations, DESCRIPTOR_LOOKUP_PATH)?;
        assert!(lookup.contains("client_max_body_size 8k;"));
        assert!(lookup.contains("limit_conn descriptor_lookup_conn_all 96;"));
        assert!(!lookup.contains("descriptor_store_conn_all"));
        for name in [
            "descriptor_invalid_request",
            "descriptor_rate_limited",
            "descriptor_blob_too_large",
        ] {
            let named = nginx_named_location(locations, name)?;
            for directive in ["internal;", "access_log off;", "error_log stderr crit;"] {
                assert!(named.lines().any(|line| line.trim() == directive), "{name}");
            }
        }
        Ok(())
    }
}
