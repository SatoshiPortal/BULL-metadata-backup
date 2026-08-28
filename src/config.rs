use std::collections::HashSet;
use std::env;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use crate::protocol::{
    ABSOLUTE_MAX_CIPHERTEXT_BYTES, ABSOLUTE_MAX_STORE_BODY_BYTES, MIN_TOMBSTONE_RETENTION_SECS,
    STORE_ENVELOPE_HEADROOM_BYTES,
};

const PREFIX: &str = "BACKUP_SERVER_";
const KNOWN: [&str; 33] = [
    "BACKUP_SERVER_BIND",
    "BACKUP_SERVER_DB_PATH",
    "BACKUP_SERVER_MAX_LIVE_BYTES",
    "BACKUP_SERVER_MAX_HEADS",
    "BACKUP_SERVER_ACCEPTED_CIPHERTEXT_BYTES",
    "BACKUP_SERVER_STORE_BODY_LIMIT_BYTES",
    "BACKUP_SERVER_LIMITER_MAX_SUBJECTS",
    "BACKUP_SERVER_LIMITER_OVERFLOW_LIMIT",
    "BACKUP_SERVER_LIMITER_OVERFLOW_WINDOW_SECS",
    "BACKUP_SERVER_OVERFLOW_RETRY_AFTER_SECS",
    "BACKUP_SERVER_LIMITER_PRUNE_INTERVAL_SECS",
    "BACKUP_SERVER_FETCH_NPUB_LIMIT",
    "BACKUP_SERVER_FETCH_NPUB_WINDOW_SECS",
    "BACKUP_SERVER_MUTATION_NPUB_LIMIT",
    "BACKUP_SERVER_MUTATION_NPUB_WINDOW_SECS",
    "BACKUP_SERVER_STORAGE_QUEUE_DEPTH",
    "BACKUP_SERVER_FETCH_MAX_IN_FLIGHT",
    "BACKUP_SERVER_STORE_MAX_IN_FLIGHT",
    "BACKUP_SERVER_DELETE_MAX_IN_FLIGHT",
    "BACKUP_SERVER_SATURATION_RETRY_AFTER_SECS",
    "BACKUP_SERVER_ADMISSION_RETRY_AFTER_SECS",
    "BACKUP_SERVER_NEW_HEAD_BUCKET_CAPACITY",
    "BACKUP_SERVER_NEW_HEAD_BUCKET_REFILL",
    "BACKUP_SERVER_TOTAL_GROWTH_BUCKET_CAPACITY_BYTES",
    "BACKUP_SERVER_TOTAL_GROWTH_BUCKET_REFILL_BYTES",
    "BACKUP_SERVER_ADMISSION_REFILL_INTERVAL_SECS",
    "BACKUP_SERVER_BUSY_TIMEOUT_MS",
    "BACKUP_SERVER_TOMBSTONE_RETENTION_SECS",
    "BACKUP_SERVER_CLEANUP_INTERVAL_SECS",
    "BACKUP_SERVER_CLEANUP_BATCH_SIZE",
    "BACKUP_SERVER_SHUTDOWN_TIMEOUT_SECS",
    "BACKUP_SERVER_REQUEST_TOTALS_INTERVAL_SECS",
    "BACKUP_SERVER_LOG",
];

#[derive(Clone, Copy)]
pub struct WindowLimit {
    pub requests: usize,
    pub window: Duration,
}

#[derive(Clone, Copy)]
pub struct LimiterConfig {
    pub max_subjects: usize,
    pub overflow: WindowLimit,
    pub overflow_retry_after_secs: u64,
    pub prune_interval: Duration,
    pub fetch_npub: WindowLimit,
    pub mutation_npub: WindowLimit,
}

#[derive(Clone, Copy)]
pub struct AdmissionBucketConfig {
    pub capacity: u64,
    pub refill: u64,
    pub refill_interval: Duration,
}

#[derive(Clone, Copy)]
pub struct AdmissionConfig {
    pub new_heads: AdmissionBucketConfig,
    pub total_growth_bytes: AdmissionBucketConfig,
}

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub db_path: PathBuf,
    pub max_live_bytes: u64,
    pub max_heads: u64,
    pub accepted_ciphertext_bytes: usize,
    pub store_body_limit_bytes: usize,
    pub limiter: LimiterConfig,
    pub storage_queue_depth: usize,
    pub fetch_max_in_flight: usize,
    pub store_max_in_flight: usize,
    pub delete_max_in_flight: usize,
    pub saturation_retry_after_secs: u64,
    pub admission_retry_after_secs: u64,
    pub admission: AdmissionConfig,
    pub busy_timeout: Duration,
    pub tombstone_retention: Duration,
    pub cleanup_interval: Duration,
    pub cleanup_batch_size: u64,
    pub shutdown_timeout: Duration,
    pub request_totals_interval: Duration,
}

impl Config {
    #[allow(clippy::too_many_lines)]
    pub fn from_env() -> Result<Self, String> {
        reject_unknown_prefixed_env()?;
        let bind = optional("BACKUP_SERVER_BIND")?
            .unwrap_or_else(|| "127.0.0.1:3000".to_owned())
            .parse::<SocketAddr>()
            .map_err(|_| "BACKUP_SERVER_BIND must be a socket address".to_owned())?;
        if !bind.ip().is_loopback() {
            return Err("BACKUP_SERVER_BIND must use a loopback address".to_owned());
        }
        let db_path = PathBuf::from(required("BACKUP_SERVER_DB_PATH")?);
        if !db_path.is_absolute() {
            return Err("BACKUP_SERVER_DB_PATH must be absolute".to_owned());
        }
        let max_live_bytes = positive_u64("BACKUP_SERVER_MAX_LIVE_BYTES")?;
        let max_heads = positive_u64("BACKUP_SERVER_MAX_HEADS")?;
        let accepted_ciphertext_bytes = optional_usize(
            "BACKUP_SERVER_ACCEPTED_CIPHERTEXT_BYTES",
            ABSOLUTE_MAX_CIPHERTEXT_BYTES,
        )?;
        if accepted_ciphertext_bytes > ABSOLUTE_MAX_CIPHERTEXT_BYTES {
            return Err(format!(
                "BACKUP_SERVER_ACCEPTED_CIPHERTEXT_BYTES must be at most {ABSOLUTE_MAX_CIPHERTEXT_BYTES}"
            ));
        }
        let store_body_limit_bytes = optional_usize(
            "BACKUP_SERVER_STORE_BODY_LIMIT_BYTES",
            ABSOLUTE_MAX_STORE_BODY_BYTES,
        )?;
        if store_body_limit_bytes > ABSOLUTE_MAX_STORE_BODY_BYTES {
            return Err(format!(
                "BACKUP_SERVER_STORE_BODY_LIMIT_BYTES must be at most {ABSOLUTE_MAX_STORE_BODY_BYTES}"
            ));
        }
        let encoded_ciphertext = accepted_ciphertext_bytes
            .checked_add(2)
            .and_then(|value| value.checked_div(3))
            .and_then(|value| value.checked_mul(4))
            .ok_or_else(|| "configured ciphertext size is out of range".to_owned())?;
        let minimum_store_body = encoded_ciphertext
            .checked_add(STORE_ENVELOPE_HEADROOM_BYTES)
            .ok_or_else(|| "configured store body size is out of range".to_owned())?;
        if store_body_limit_bytes < minimum_store_body {
            return Err(format!(
                "BACKUP_SERVER_STORE_BODY_LIMIT_BYTES must be at least {minimum_store_body} for the configured ciphertext size"
            ));
        }
        let maximum_live_shape = max_heads
            .checked_mul(u64::try_from(accepted_ciphertext_bytes).map_err(|_| {
                "BACKUP_SERVER_ACCEPTED_CIPHERTEXT_BYTES is out of range".to_owned()
            })?)
            .ok_or_else(|| "configured maximum head shape is out of range".to_owned())?;
        if maximum_live_shape > max_live_bytes {
            return Err(
                "BACKUP_SERVER_MAX_HEADS times BACKUP_SERVER_ACCEPTED_CIPHERTEXT_BYTES must not exceed BACKUP_SERVER_MAX_LIVE_BYTES"
                    .to_owned(),
            );
        }

        let limiter = LimiterConfig {
            max_subjects: positive_usize("BACKUP_SERVER_LIMITER_MAX_SUBJECTS")?,
            overflow: window_limit(
                "BACKUP_SERVER_LIMITER_OVERFLOW_LIMIT",
                600,
                "BACKUP_SERVER_LIMITER_OVERFLOW_WINDOW_SECS",
                3_600,
            )?,
            overflow_retry_after_secs: optional_u64(
                "BACKUP_SERVER_OVERFLOW_RETRY_AFTER_SECS",
                900,
            )?,
            prune_interval: Duration::from_secs(optional_u64(
                "BACKUP_SERVER_LIMITER_PRUNE_INTERVAL_SECS",
                60,
            )?),
            fetch_npub: window_limit(
                "BACKUP_SERVER_FETCH_NPUB_LIMIT",
                60,
                "BACKUP_SERVER_FETCH_NPUB_WINDOW_SECS",
                3_600,
            )?,
            mutation_npub: window_limit(
                "BACKUP_SERVER_MUTATION_NPUB_LIMIT",
                20,
                "BACKUP_SERVER_MUTATION_NPUB_WINDOW_SECS",
                3_600,
            )?,
        };

        let storage_queue_depth = optional_usize("BACKUP_SERVER_STORAGE_QUEUE_DEPTH", 64)?;
        let fetch_max_in_flight = optional_usize("BACKUP_SERVER_FETCH_MAX_IN_FLIGHT", 24)?;
        let store_max_in_flight = optional_usize("BACKUP_SERVER_STORE_MAX_IN_FLIGHT", 8)?;
        let delete_max_in_flight = optional_usize("BACKUP_SERVER_DELETE_MAX_IN_FLIGHT", 4)?;
        let total_permits = fetch_max_in_flight
            .checked_add(store_max_in_flight)
            .and_then(|value| value.checked_add(delete_max_in_flight))
            .ok_or_else(|| "configured concurrency is out of range".to_owned())?;
        if storage_queue_depth <= total_permits {
            return Err(
                "BACKUP_SERVER_STORAGE_QUEUE_DEPTH must be greater than the sum of fetch, store, and delete in-flight limits"
                    .to_owned(),
            );
        }

        let saturation_retry_after_secs =
            optional_u64("BACKUP_SERVER_SATURATION_RETRY_AFTER_SECS", 5)?;
        let admission_retry_after_secs =
            optional_u64("BACKUP_SERVER_ADMISSION_RETRY_AFTER_SECS", 900)?;
        let admission_interval = Duration::from_secs(optional_u64(
            "BACKUP_SERVER_ADMISSION_REFILL_INTERVAL_SECS",
            86_400,
        )?);
        let admission = AdmissionConfig {
            new_heads: admission_bucket(
                "BACKUP_SERVER_NEW_HEAD_BUCKET_CAPACITY",
                50,
                "BACKUP_SERVER_NEW_HEAD_BUCKET_REFILL",
                500,
                admission_interval,
            )?,
            total_growth_bytes: admission_bucket(
                "BACKUP_SERVER_TOTAL_GROWTH_BUCKET_CAPACITY_BYTES",
                80 * 1024 * 1024,
                "BACKUP_SERVER_TOTAL_GROWTH_BUCKET_REFILL_BYTES",
                640 * 1024 * 1024,
                admission_interval,
            )?,
        };
        let accepted_u64 = u64::try_from(accepted_ciphertext_bytes)
            .map_err(|_| "configured ciphertext size is out of range".to_owned())?;
        if admission.total_growth_bytes.capacity < accepted_u64 {
            return Err(
                "total-growth admission capacity must admit one maximum-size ciphertext".to_owned(),
            );
        }

        let busy_timeout =
            Duration::from_millis(optional_u64("BACKUP_SERVER_BUSY_TIMEOUT_MS", 5_000)?);
        let tombstone_retention_secs = optional_u64(
            "BACKUP_SERVER_TOMBSTONE_RETENTION_SECS",
            MIN_TOMBSTONE_RETENTION_SECS,
        )?;
        if tombstone_retention_secs < MIN_TOMBSTONE_RETENTION_SECS {
            return Err(format!(
                "BACKUP_SERVER_TOMBSTONE_RETENTION_SECS must be at least {MIN_TOMBSTONE_RETENTION_SECS}"
            ));
        }
        let cleanup_interval =
            Duration::from_secs(optional_u64("BACKUP_SERVER_CLEANUP_INTERVAL_SECS", 60)?);
        let cleanup_batch_size = optional_u64("BACKUP_SERVER_CLEANUP_BATCH_SIZE", 128)?;
        let shutdown_timeout =
            Duration::from_secs(optional_u64("BACKUP_SERVER_SHUTDOWN_TIMEOUT_SECS", 10)?);
        let request_totals_interval = Duration::from_secs(optional_u64(
            "BACKUP_SERVER_REQUEST_TOTALS_INTERVAL_SECS",
            60,
        )?);

        Ok(Self {
            bind,
            db_path,
            max_live_bytes,
            max_heads,
            accepted_ciphertext_bytes,
            store_body_limit_bytes,
            limiter,
            storage_queue_depth,
            fetch_max_in_flight,
            store_max_in_flight,
            delete_max_in_flight,
            saturation_retry_after_secs,
            admission_retry_after_secs,
            admission,
            busy_timeout,
            tombstone_retention: Duration::from_secs(tombstone_retention_secs),
            cleanup_interval,
            cleanup_batch_size,
            shutdown_timeout,
            request_totals_interval,
        })
    }
}

pub fn log_level() -> Result<String, String> {
    Ok(optional("BACKUP_SERVER_LOG")?.unwrap_or_else(|| "info".to_owned()))
}

fn window_limit(
    limit_key: &str,
    limit_default: usize,
    window_key: &str,
    window_default: u64,
) -> Result<WindowLimit, String> {
    Ok(WindowLimit {
        requests: optional_usize(limit_key, limit_default)?,
        window: Duration::from_secs(optional_u64(window_key, window_default)?),
    })
}

fn admission_bucket(
    capacity_key: &str,
    capacity_default: u64,
    refill_key: &str,
    refill_default: u64,
    refill_interval: Duration,
) -> Result<AdmissionBucketConfig, String> {
    let capacity = optional_u64(capacity_key, capacity_default)?;
    let refill = optional_u64(refill_key, refill_default)?;
    if capacity > i64::MAX as u64 || refill > i64::MAX as u64 {
        return Err(format!(
            "{capacity_key} and {refill_key} must fit in a signed 64-bit integer"
        ));
    }
    Ok(AdmissionBucketConfig {
        capacity,
        refill,
        refill_interval,
    })
}

fn reject_unknown_prefixed_env() -> Result<(), String> {
    let known = KNOWN.into_iter().collect::<HashSet<_>>();
    for (key, _) in env::vars_os() {
        if !key.as_os_str().as_bytes().starts_with(PREFIX.as_bytes()) {
            continue;
        }
        let key = key
            .into_string()
            .map_err(|_| "BACKUP_SERVER_ configuration variable name is not UTF-8".to_owned())?;
        if !known.contains(key.as_str()) {
            return Err(format!("unknown configuration variable {key}"));
        }
    }
    Ok(())
}

fn required(key: &str) -> Result<String, String> {
    optional(key)?.ok_or_else(|| format!("{key} is required"))
}

fn optional(key: &str) -> Result<Option<String>, String> {
    match env::var_os(key) {
        Some(value) => value
            .into_string()
            .map_err(|_| format!("{key} must be UTF-8"))
            .map(|value| if value.is_empty() { None } else { Some(value) }),
        None => Ok(None),
    }
}

fn positive_u64(key: &str) -> Result<u64, String> {
    let value = required(key)?;
    parse_positive_u64(key, &value)
}

fn positive_usize(key: &str) -> Result<usize, String> {
    let value = positive_u64(key)?;
    usize::try_from(value).map_err(|_| format!("{key} is too large"))
}

fn optional_u64(key: &str, default: u64) -> Result<u64, String> {
    match optional(key)? {
        Some(value) => parse_positive_u64(key, &value),
        None => Ok(default),
    }
}

fn optional_usize(key: &str, default: usize) -> Result<usize, String> {
    usize::try_from(optional_u64(key, default as u64)?).map_err(|_| format!("{key} is too large"))
}

fn parse_positive_u64(key: &str, value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{key} must be a positive integer"))?;
    if parsed == 0 {
        return Err(format!("{key} must be positive"));
    }
    Ok(parsed)
}
