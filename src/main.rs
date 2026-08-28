#![forbid(unsafe_code)]

mod config;
mod limits;
mod protocol;
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
    ApiError, BackupStream, DELETE_ACTION, DeleteRequest, FETCH_ACTION, FetchRequest,
    FetchResponse, MutationResponse, RateLimitKind, SMALL_BODY_LIMIT_BYTES, STORE_ACTION,
    StoreRequest, VERSION, compute_etag, decode_canonical_hex, decode_ciphertext, private_no_store,
    unix_time, validate_generation, validate_version, verify_request_signature,
};
use sha2::{Digest, Sha256};
use storage::{
    CallError, MutationOutcome, Storage, StorageConfig, StorageMetricsSnapshot, StorageOwner,
};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;

const REQUEST_TOTALS: usize = 15;
// Not configurable: the checked Nginx configuration overwrites exactly this header.
const SOURCE_IDENTITY_HEADER: &str = "x-real-ip";

#[derive(Clone)]
struct AppState {
    storage: Storage,
    limiter: RateLimiter,
    fetch_in_flight: Arc<Semaphore>,
    store_in_flight: Arc<Semaphore>,
    delete_in_flight: Arc<Semaphore>,
    accepted_ciphertext_bytes: usize,
    saturation_retry_after_secs: u64,
    admission_retry_after_secs: u64,
    request_totals: Arc<RequestTotals>,
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
        "verify-backup" => {
            let path = next_path(&mut arguments)?;
            if arguments.next().is_some() {
                return Err(usage());
            }
            let report = storage::verify_backup(&path)?;
            println!(
                "verified backup: heads={} live_bytes={} aggregate_sha256={}",
                report.heads, report.live_bytes, report.aggregate_sha256
            );
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: backup-server serve | verify-backup <absolute-path>".to_owned()
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

async fn serve(config: config::Config) -> Result<(), String> {
    let limiter = RateLimiter::new(config.limiter)?;
    let request_totals = Arc::new(RequestTotals::new(config.request_totals_interval));
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|_| "failed to bind loopback listener".to_owned())?;
    let owner = StorageOwner::start(StorageConfig {
        path: config.db_path.clone(),
        queue_depth: config.storage_queue_depth,
        busy_timeout: config.busy_timeout,
        max_live_bytes: config.max_live_bytes,
        max_heads: config.max_heads,
        admission: config.admission,
    })?;
    let storage = owner.client();
    let state = AppState {
        storage: storage.clone(),
        limiter,
        fetch_in_flight: Arc::new(Semaphore::new(config.fetch_max_in_flight)),
        store_in_flight: Arc::new(Semaphore::new(config.store_max_in_flight)),
        delete_in_flight: Arc::new(Semaphore::new(config.delete_max_in_flight)),
        accepted_ciphertext_bytes: config.accepted_ciphertext_bytes,
        saturation_retry_after_secs: config.saturation_retry_after_secs,
        admission_retry_after_secs: config.admission_retry_after_secs,
        request_totals: Arc::clone(&request_totals),
    };
    let router = router(state, config.store_body_limit_bytes);
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

fn router(state: AppState, store_body_limit_bytes: usize) -> Router {
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
        .route("/healthz", get(health))
        .with_state(state)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::HeaderValue;
    use config::{AdmissionBucketConfig, AdmissionConfig, LimiterConfig, WindowLimit};
    use protocol::{
        ABSOLUTE_MAX_CIPHERTEXT_BYTES, ABSOLUTE_MAX_STORE_BODY_BYTES, build_signing_message,
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
            max_subjects: 16,
            overflow: limit,
            overflow_retry_after_secs: 900,
            prune_interval: Duration::from_secs(60),
            fetch_npub: limit,
            mutation_npub: limit,
        }
    }

    fn test_router(state: AppState) -> Router {
        router(state, ABSOLUTE_MAX_STORE_BODY_BYTES)
    }

    fn test_state(name: &str) -> Result<(PathBuf, StorageOwner, AppState), String> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|_| "randomness unavailable".to_owned())?;
        let directory =
            env::temp_dir().join(format!("backup-server-{name}-{}", hex::encode(random)));
        fs::create_dir(&directory).map_err(|_| "failed to create test directory".to_owned())?;
        let owner = StorageOwner::start(StorageConfig {
            path: directory.join("backup.sqlite3"),
            queue_depth: 8,
            busy_timeout: Duration::from_secs(1),
            max_live_bytes: 1024,
            max_heads: 4,
            admission: test_admission(),
        })?;
        let state = AppState {
            storage: owner.client(),
            limiter: RateLimiter::new(test_limiter())?,
            fetch_in_flight: Arc::new(Semaphore::new(4)),
            store_in_flight: Arc::new(Semaphore::new(4)),
            delete_in_flight: Arc::new(Semaphore::new(4)),
            accepted_ciphertext_bytes: ABSOLUTE_MAX_CIPHERTEXT_BYTES,
            saturation_retry_after_secs: 5,
            admission_retry_after_secs: 900,
            request_totals: Arc::new(RequestTotals::new(Duration::from_secs(60))),
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
    async fn store_saturation_fails_immediately_without_starving_fetch() -> Result<(), String> {
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
            "limit_conn backup_conn_all 128;",
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
            "limit_conn_zone $server_name zone=backup_conn_all:1m;",
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
}
