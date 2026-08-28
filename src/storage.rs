use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

use crate::config::{AdmissionBucketConfig, AdmissionConfig};
use crate::protocol::{ABSOLUTE_MAX_CIPHERTEXT_BYTES, BackupStream, compute_etag};

const SCHEMA_VERSION: i64 = 1;
const SCHEMA: &str = include_str!("../schema.sql");
const TABLE_SCHEMA: &str = "CREATE TABLE wallet_backup_heads (
    author_pubkey       BLOB    NOT NULL PRIMARY KEY,
    generation          INTEGER NOT NULL,
    ciphertext          BLOB,
    ciphertext_sha256   BLOB,
    updated_at           INTEGER NOT NULL,
    CONSTRAINT author_pubkey_length CHECK (length(author_pubkey) = 32),
    CONSTRAINT generation_positive CHECK (generation > 0),
    CONSTRAINT updated_at_nonnegative CHECK (updated_at >= 0),
    CONSTRAINT live_or_tombstone CHECK (
        (ciphertext IS NULL AND ciphertext_sha256 IS NULL)
        OR
        (
            ciphertext IS NOT NULL
            AND ciphertext_sha256 IS NOT NULL
            AND length(ciphertext_sha256) = 32
            AND length(ciphertext) <= 1048576
        )
    )
) STRICT, WITHOUT ROWID";
const TOMBSTONE_INDEX_SCHEMA: &str = "CREATE INDEX wallet_backup_tombstones_by_time
    ON wallet_backup_heads(updated_at)
    WHERE ciphertext IS NULL";
const ADMISSION_TABLE_SCHEMA: &str = "CREATE TABLE wallet_backup_admission (
    bucket                  TEXT    NOT NULL PRIMARY KEY,
    tokens                  INTEGER NOT NULL,
    refill_remainder        INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL,
    capacity                INTEGER NOT NULL,
    refill                  INTEGER NOT NULL,
    refill_interval_secs    INTEGER NOT NULL,
    CONSTRAINT admission_bucket_name CHECK (
        bucket IN ('new_heads', 'total_growth_bytes')
    ),
    CONSTRAINT admission_values_positive CHECK (
        tokens >= 0
        AND refill_remainder >= 0
        AND updated_at >= 0
        AND capacity > 0
        AND refill > 0
        AND refill_interval_secs > 0
    ),
    CONSTRAINT admission_tokens_bounded CHECK (tokens <= capacity),
    CONSTRAINT admission_remainder_bounded CHECK (
        refill_remainder < refill_interval_secs
    )
) STRICT, WITHOUT ROWID";
const ADMISSION_BUCKET_NAMES: [&str; 2] = ["new_heads", "total_growth_bytes"];

#[derive(Clone)]
pub struct Storage {
    sender: mpsc::Sender<Command>,
    alive: Arc<AtomicBool>,
    metrics: Arc<StorageMetrics>,
}

pub struct StorageOwner {
    storage: Storage,
    join: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct StorageConfig {
    pub path: PathBuf,
    pub queue_depth: usize,
    pub busy_timeout: Duration,
    pub max_live_bytes: u64,
    pub max_heads: u64,
    pub admission: AdmissionConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub generation: i64,
    pub ciphertext: Option<Vec<u8>>,
    pub ciphertext_sha256: Option<[u8; 32]>,
    pub updated_at: i64,
}

impl Head {
    pub fn is_tombstone(&self) -> bool {
        self.ciphertext.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationOutcome {
    Applied,
    ExactRetry,
    HeadConflict,
    CapacityExceeded,
    AdmissionLimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    QueueFull,
    Unavailable,
    Storage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub heads: u64,
    pub live_bytes: u64,
    pub aggregate_sha256: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageMetricsSnapshot {
    pub new_heads_admitted: u64,
    pub new_allocation_bytes_admitted: u64,
    pub existing_head_growth_bytes_admitted: u64,
    pub current_heads: u64,
    pub current_live_bytes: u64,
}

#[derive(Default)]
struct StorageMetrics {
    new_heads_admitted: AtomicU64,
    new_allocation_bytes_admitted: AtomicU64,
    existing_head_growth_bytes_admitted: AtomicU64,
    current_heads: AtomicU64,
    current_live_bytes: AtomicU64,
}

enum Command {
    Fetch {
        author: [u8; 32],
        reply: oneshot::Sender<Result<Option<Head>, StorageError>>,
    },
    Store {
        npub: String,
        author: [u8; 32],
        generation: i64,
        expected_etag: Option<[u8; 32]>,
        requested_etag: [u8; 32],
        ciphertext: Vec<u8>,
        ciphertext_sha256: [u8; 32],
        now: i64,
        reply: oneshot::Sender<Result<MutationOutcome, StorageError>>,
    },
    Delete {
        npub: String,
        author: [u8; 32],
        generation: i64,
        expected_etag: [u8; 32],
        tombstone_etag: [u8; 32],
        now: i64,
        reply: oneshot::Sender<Result<MutationOutcome, StorageError>>,
    },
    Cleanup {
        cutoff: i64,
        batch_size: u64,
        reply: oneshot::Sender<Result<u64, StorageError>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

#[derive(Debug, Clone, Copy)]
enum StorageError {
    Database,
    InvalidData,
}

struct Actor {
    connection: Connection,
    serve_lock: File,
    live_bytes: u64,
    heads: u64,
    max_live_bytes: u64,
    max_heads: u64,
    admission: AdmissionConfig,
    metrics: Arc<StorageMetrics>,
}

#[derive(Clone, Copy)]
struct AdmissionState {
    tokens: u64,
    refill_remainder: u64,
    updated_at: u64,
    config: AdmissionBucketConfig,
}

#[derive(Clone, Copy)]
struct AdmissionCharge {
    new_heads: u64,
    total_growth_bytes: u64,
}

struct AliveGuard(Arc<AtomicBool>);

impl StorageMetrics {
    fn snapshot_and_reset(&self) -> StorageMetricsSnapshot {
        StorageMetricsSnapshot {
            new_heads_admitted: self.new_heads_admitted.swap(0, Ordering::Relaxed),
            new_allocation_bytes_admitted: self
                .new_allocation_bytes_admitted
                .swap(0, Ordering::Relaxed),
            existing_head_growth_bytes_admitted: self
                .existing_head_growth_bytes_admitted
                .swap(0, Ordering::Relaxed),
            current_heads: self.current_heads.load(Ordering::Relaxed),
            current_live_bytes: self.current_live_bytes.load(Ordering::Relaxed),
        }
    }

    fn record_store(
        &self,
        new_heads: u64,
        new_allocation_bytes: u64,
        existing_head_growth_bytes: u64,
        current_heads: u64,
        current_live_bytes: u64,
    ) {
        saturating_add(&self.new_heads_admitted, new_heads);
        saturating_add(&self.new_allocation_bytes_admitted, new_allocation_bytes);
        saturating_add(
            &self.existing_head_growth_bytes_admitted,
            existing_head_growth_bytes,
        );
        self.set_current(current_heads, current_live_bytes);
    }

    fn set_current(&self, heads: u64, live_bytes: u64) {
        self.current_heads.store(heads, Ordering::Relaxed);
        self.current_live_bytes.store(live_bytes, Ordering::Relaxed);
    }
}

fn saturating_add(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
}

impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl StorageOwner {
    pub fn start(config: StorageConfig) -> Result<Self, String> {
        if config.queue_depth == 0
            || config.max_live_bytes == 0
            || config.max_heads == 0
            || admission_configs(&config.admission)
                .iter()
                .any(|(_, bucket)| {
                    bucket.capacity == 0 || bucket.refill == 0 || bucket.refill_interval.is_zero()
                })
        {
            return Err("storage limits must be positive".to_owned());
        }
        let (sender, receiver) = mpsc::channel(config.queue_depth);
        let (startup_sender, startup_receiver) = std_mpsc::sync_channel(1);
        let alive = Arc::new(AtomicBool::new(false));
        let thread_alive = Arc::clone(&alive);
        let metrics = Arc::new(StorageMetrics::default());
        let thread_metrics = Arc::clone(&metrics);
        let join = thread::Builder::new()
            .name("backup-sqlite".to_owned())
            .spawn(move || {
                let alive_guard = AliveGuard(thread_alive);
                match Actor::open(&config, thread_metrics) {
                    Ok(mut actor) => {
                        alive_guard.0.store(true, Ordering::Release);
                        if startup_sender.send(Ok(())).is_err() {
                            return;
                        }
                        actor.run(receiver);
                    }
                    Err(error) => {
                        if startup_sender.send(Err(error)).is_err() {
                            tracing::debug!(
                                event = "sqlite_startup_receiver_closed",
                                "SQLite startup receiver closed"
                            );
                        }
                    }
                }
            })
            .map_err(|_| "failed to spawn SQLite owner thread".to_owned())?;
        match startup_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                storage: Storage {
                    sender,
                    alive,
                    metrics,
                },
                join: Some(join),
            }),
            Ok(Err(error)) => {
                if join.join().is_err() {
                    return Err("SQLite owner thread panicked during startup".to_owned());
                }
                Err(error)
            }
            Err(_) => {
                if join.join().is_err() {
                    return Err("SQLite owner thread panicked during startup".to_owned());
                }
                Err("SQLite owner thread failed during startup".to_owned())
            }
        }
    }

    pub fn client(&self) -> Storage {
        self.storage.clone()
    }

    pub async fn shutdown(mut self) -> Result<(), String> {
        let (reply, response) = oneshot::channel();
        self.storage
            .sender
            .send(Command::Shutdown { reply })
            .await
            .map_err(|_| "SQLite owner is unavailable during shutdown".to_owned())?;
        response
            .await
            .map_err(|_| "SQLite owner did not acknowledge shutdown".to_owned())?;
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| "SQLite owner thread panicked".to_owned())?;
        }
        Ok(())
    }
}

impl Storage {
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    pub fn metrics_snapshot(&self) -> StorageMetricsSnapshot {
        self.metrics.snapshot_and_reset()
    }

    pub async fn fetch(&self, author: [u8; 32]) -> Result<Option<Head>, CallError> {
        let (reply, response) = oneshot::channel();
        self.try_send(Command::Fetch { author, reply })?;
        response
            .await
            .map_err(|_| CallError::Unavailable)?
            .map_err(map_storage_error)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn store(
        &self,
        npub: String,
        author: [u8; 32],
        generation: i64,
        expected_etag: Option<[u8; 32]>,
        requested_etag: [u8; 32],
        ciphertext: Vec<u8>,
        ciphertext_sha256: [u8; 32],
        now: i64,
    ) -> Result<MutationOutcome, CallError> {
        let (reply, response) = oneshot::channel();
        self.try_send(Command::Store {
            npub,
            author,
            generation,
            expected_etag,
            requested_etag,
            ciphertext,
            ciphertext_sha256,
            now,
            reply,
        })?;
        response
            .await
            .map_err(|_| CallError::Unavailable)?
            .map_err(map_storage_error)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn delete(
        &self,
        npub: String,
        author: [u8; 32],
        generation: i64,
        expected_etag: [u8; 32],
        tombstone_etag: [u8; 32],
        now: i64,
    ) -> Result<MutationOutcome, CallError> {
        let (reply, response) = oneshot::channel();
        self.try_send(Command::Delete {
            npub,
            author,
            generation,
            expected_etag,
            tombstone_etag,
            now,
            reply,
        })?;
        response
            .await
            .map_err(|_| CallError::Unavailable)?
            .map_err(map_storage_error)
    }

    pub async fn cleanup(&self, cutoff: i64, batch_size: u64) -> Result<u64, CallError> {
        let (reply, response) = oneshot::channel();
        self.try_send(Command::Cleanup {
            cutoff,
            batch_size,
            reply,
        })?;
        response
            .await
            .map_err(|_| CallError::Unavailable)?
            .map_err(map_storage_error)
    }

    fn try_send(&self, command: Command) -> Result<(), CallError> {
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => CallError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => CallError::Unavailable,
        })
    }
}

impl Actor {
    fn open(config: &StorageConfig, metrics: Arc<StorageMetrics>) -> Result<Self, String> {
        reject_symlink(&config.path)?;
        let lock_path = lock_path(&config.path);
        reject_symlink(&lock_path)?;
        let serve_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|error| format!("failed to open serve lock: {error}"))?;
        fs2::FileExt::try_lock_exclusive(&serve_lock)
            .map_err(|_| "another serving process owns the database".to_owned())?;
        let mut connection = Connection::open_with_flags(
            &config.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| format!("failed to open SQLite database: {error}"))?;
        fs::set_permissions(&config.path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("failed to set SQLite database permissions: {error}"))?;
        configure_connection(&connection, config.busy_timeout)?;
        let fresh_database = initialize_schema(&connection)?;
        verify_schema_objects(&connection)?;
        synchronize_admission(
            &mut connection,
            &config.admission,
            system_time_secs()?,
            fresh_database,
        )?;
        verify_admission_rows(&connection)?;
        let (heads, live_bytes) = reconstruct_counters(&connection)?;
        metrics.set_current(heads, live_bytes);
        if live_bytes > config.max_live_bytes || heads > config.max_heads {
            tracing::warn!(
                event = "configured_capacity_below_existing_state",
                "configured capacity is below existing wallet backup state"
            );
        }
        Ok(Self {
            connection,
            serve_lock,
            live_bytes,
            heads,
            max_live_bytes: config.max_live_bytes,
            max_heads: config.max_heads,
            admission: config.admission,
            metrics,
        })
    }

    fn run(&mut self, mut receiver: mpsc::Receiver<Command>) {
        while let Some(command) = receiver.blocking_recv() {
            match command {
                Command::Fetch { author, reply } => {
                    send_response(reply, fetch_head(&self.connection, &author));
                }
                Command::Store {
                    npub,
                    author,
                    generation,
                    expected_etag,
                    requested_etag,
                    ciphertext,
                    ciphertext_sha256,
                    now,
                    reply,
                } => {
                    let result = self.store(
                        &npub,
                        &author,
                        generation,
                        expected_etag.as_ref(),
                        &requested_etag,
                        &ciphertext,
                        &ciphertext_sha256,
                        now,
                    );
                    send_response(reply, result);
                }
                Command::Delete {
                    npub,
                    author,
                    generation,
                    expected_etag,
                    tombstone_etag,
                    now,
                    reply,
                } => {
                    let result = self.delete(
                        &npub,
                        &author,
                        generation,
                        &expected_etag,
                        &tombstone_etag,
                        now,
                    );
                    send_response(reply, result);
                }
                Command::Cleanup {
                    cutoff,
                    batch_size,
                    reply,
                } => {
                    let result = self.cleanup(cutoff, batch_size);
                    send_response(reply, result);
                }
                Command::Shutdown { reply } => {
                    send_response(reply, ());
                    break;
                }
            }
        }
        if fs2::FileExt::unlock(&self.serve_lock).is_err() {
            tracing::error!(
                event = "serve_lock_release_failed",
                "serve lock release failed"
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn store(
        &mut self,
        npub: &str,
        author: &[u8; 32],
        generation: i64,
        expected_etag: Option<&[u8; 32]>,
        requested_etag: &[u8; 32],
        ciphertext: &[u8],
        ciphertext_sha256: &[u8; 32],
        now: i64,
    ) -> Result<MutationOutcome, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StorageError::Database)?;
        let current = fetch_head(&transaction, author)?;
        if let Some(head) = current.as_ref() {
            let current_etag = etag_for_head(npub, head)?;
            if !head.is_tombstone()
                && head.generation == generation
                && current_etag == *requested_etag
                && head.ciphertext.as_deref() == Some(ciphertext)
                && head.ciphertext_sha256.as_ref() == Some(ciphertext_sha256)
            {
                return Ok(MutationOutcome::ExactRetry);
            }
        }
        let expected_generation = match current.as_ref() {
            None => Some(1),
            Some(head) => head.generation.checked_add(1),
        };
        let expected_matches = match (current.as_ref(), expected_etag) {
            (None, None) => true,
            (Some(head), Some(expected)) => etag_for_head(npub, head)? == *expected,
            _ => false,
        };
        if expected_generation != Some(generation) || !expected_matches {
            return Ok(MutationOutcome::HeadConflict);
        }
        if current.is_none() && self.heads >= self.max_heads {
            return Ok(MutationOutcome::CapacityExceeded);
        }
        let projected_heads = if current.is_none() {
            self.heads.checked_add(1).ok_or(StorageError::InvalidData)?
        } else {
            self.heads
        };
        let previous = current
            .as_ref()
            .and_then(|head| head.ciphertext.as_ref())
            .map(|value| u64::try_from(value.len()).map_err(|_| StorageError::InvalidData))
            .transpose()?
            .map_or(0, |value| value);
        let new_bytes = u64::try_from(ciphertext.len()).map_err(|_| StorageError::InvalidData)?;
        let projected = self
            .live_bytes
            .checked_sub(previous)
            .and_then(|value| value.checked_add(new_bytes))
            .ok_or(StorageError::InvalidData)?;
        if projected > self.max_live_bytes {
            return Ok(MutationOutcome::CapacityExceeded);
        }
        let new_head = current.is_none();
        let new_allocation = current.as_ref().is_none_or(Head::is_tombstone);
        let positive_growth = new_bytes.saturating_sub(previous);
        let new_allocation_bytes = if new_allocation { new_bytes } else { 0 };
        let existing_head_growth_bytes = if new_allocation { 0 } else { positive_growth };
        let admission = AdmissionCharge {
            new_heads: u64::from(new_head),
            total_growth_bytes: positive_growth,
        };
        let admission_now = u64::try_from(now).map_err(|_| StorageError::InvalidData)?;
        if !consume_admission(&transaction, &self.admission, admission, admission_now)? {
            transaction.commit().map_err(|_| StorageError::Database)?;
            return Ok(MutationOutcome::AdmissionLimited);
        }
        transaction
            .execute(
                "INSERT INTO wallet_backup_heads (
                     author_pubkey, generation, ciphertext, ciphertext_sha256, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(author_pubkey) DO UPDATE SET
                     generation = excluded.generation,
                     ciphertext = excluded.ciphertext,
                     ciphertext_sha256 = excluded.ciphertext_sha256,
                     updated_at = excluded.updated_at",
                params![author, generation, ciphertext, ciphertext_sha256, now],
            )
            .map_err(|_| StorageError::Database)?;
        // Only commit path for a store; every earlier return rolls back.
        transaction.commit().map_err(|_| StorageError::Database)?;
        self.live_bytes = projected;
        self.heads = projected_heads;
        self.metrics.record_store(
            admission.new_heads,
            new_allocation_bytes,
            existing_head_growth_bytes,
            self.heads,
            self.live_bytes,
        );
        Ok(MutationOutcome::Applied)
    }

    #[allow(clippy::too_many_arguments)]
    fn delete(
        &mut self,
        npub: &str,
        author: &[u8; 32],
        generation: i64,
        expected_etag: &[u8; 32],
        tombstone_etag: &[u8; 32],
        now: i64,
    ) -> Result<MutationOutcome, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StorageError::Database)?;
        let Some(current) = fetch_head(&transaction, author)? else {
            return Ok(MutationOutcome::HeadConflict);
        };
        if current.is_tombstone()
            && current.generation == generation
            && etag_for_head(npub, &current)? == *tombstone_etag
        {
            return Ok(MutationOutcome::ExactRetry);
        }
        if current.is_tombstone()
            || current.generation.checked_add(1) != Some(generation)
            || etag_for_head(npub, &current)? != *expected_etag
        {
            return Ok(MutationOutcome::HeadConflict);
        }
        let previous = current
            .ciphertext
            .as_ref()
            .map(|value| u64::try_from(value.len()).map_err(|_| StorageError::InvalidData))
            .transpose()?
            .map_or(0, |value| value);
        let projected = self
            .live_bytes
            .checked_sub(previous)
            .ok_or(StorageError::InvalidData)?;
        transaction
            .execute(
                "UPDATE wallet_backup_heads SET
                     generation = ?2,
                     ciphertext = NULL,
                     ciphertext_sha256 = NULL,
                     updated_at = ?3
                 WHERE author_pubkey = ?1",
                params![author, generation, now],
            )
            .map_err(|_| StorageError::Database)?;
        transaction.commit().map_err(|_| StorageError::Database)?;
        self.live_bytes = projected;
        self.metrics.set_current(self.heads, self.live_bytes);
        Ok(MutationOutcome::Applied)
    }

    fn cleanup(&mut self, cutoff: i64, batch_size: u64) -> Result<u64, StorageError> {
        let batch_size = i64::try_from(batch_size).map_err(|_| StorageError::InvalidData)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StorageError::Database)?;
        let removed = transaction
            .execute(
                "DELETE FROM wallet_backup_heads
                 WHERE author_pubkey IN (
                     SELECT author_pubkey FROM wallet_backup_heads
                     WHERE ciphertext IS NULL AND updated_at < ?1
                     ORDER BY updated_at, author_pubkey
                     LIMIT ?2
                 )",
                params![cutoff, batch_size],
            )
            .map_err(|_| StorageError::Database)?;
        let removed = u64::try_from(removed).map_err(|_| StorageError::InvalidData)?;
        let projected = self
            .heads
            .checked_sub(removed)
            .ok_or(StorageError::InvalidData)?;
        transaction.commit().map_err(|_| StorageError::Database)?;
        self.heads = projected;
        self.metrics.set_current(self.heads, self.live_bytes);
        Ok(removed)
    }
}

fn map_storage_error(_: StorageError) -> CallError {
    CallError::Storage
}

fn send_response<T>(reply: oneshot::Sender<T>, value: T) {
    if reply.send(value).is_err() {
        tracing::debug!(
            event = "storage_response_receiver_closed",
            "storage response receiver closed"
        );
    }
}

fn fetch_head(connection: &Connection, author: &[u8; 32]) -> Result<Option<Head>, StorageError> {
    let raw = connection
        .query_row(
            "SELECT generation, ciphertext, ciphertext_sha256, updated_at
             FROM wallet_backup_heads WHERE author_pubkey = ?1",
            params![author],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| StorageError::Database)?;
    raw.map(head_from_raw).transpose()
}

fn head_from_raw(raw: (i64, Option<Vec<u8>>, Option<Vec<u8>>, i64)) -> Result<Head, StorageError> {
    let (generation, ciphertext, hash, updated_at) = raw;
    if generation <= 0 || updated_at < 0 || ciphertext.is_some() != hash.is_some() {
        return Err(StorageError::InvalidData);
    }
    let ciphertext_sha256 = hash
        .map(|value| value.try_into().map_err(|_| StorageError::InvalidData))
        .transpose()?;
    if ciphertext
        .as_ref()
        .is_some_and(|value| value.len() > ABSOLUTE_MAX_CIPHERTEXT_BYTES)
    {
        return Err(StorageError::InvalidData);
    }
    Ok(Head {
        generation,
        ciphertext,
        ciphertext_sha256,
        updated_at,
    })
}

fn etag_for_head(npub: &str, head: &Head) -> Result<[u8; 32], StorageError> {
    let generation = u64::try_from(head.generation).map_err(|_| StorageError::InvalidData)?;
    let hash = head.ciphertext_sha256.as_ref().map(hex::encode);
    Ok(compute_etag(
        BackupStream::WalletBackup,
        npub,
        generation,
        hash.as_deref(),
    ))
}

fn configure_connection(connection: &Connection, busy_timeout: Duration) -> Result<(), String> {
    connection
        .busy_timeout(busy_timeout)
        .map_err(|_| "failed to set SQLite busy timeout".to_owned())?;
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(|_| "failed to set SQLite journal mode".to_owned())?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| "failed to set SQLite synchronous mode".to_owned())?;
    connection
        .pragma_update(None, "secure_delete", "ON")
        .map_err(|_| "failed to enable SQLite secure delete".to_owned())?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| "failed to enable SQLite foreign keys".to_owned())?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|_| "failed to disable SQLite trusted schema".to_owned())?;
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|_| "failed to read SQLite journal mode".to_owned())?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|_| "failed to read SQLite synchronous mode".to_owned())?;
    let secure_delete: i64 = connection
        .query_row("PRAGMA secure_delete", [], |row| row.get(0))
        .map_err(|_| "failed to read SQLite secure delete".to_owned())?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|_| "failed to read SQLite foreign keys".to_owned())?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|_| "failed to read SQLite trusted schema".to_owned())?;
    let busy_ms: u128 = busy_timeout.as_millis();
    let configured_busy: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(|_| "failed to read SQLite busy timeout".to_owned())?;
    if journal != "delete"
        || synchronous != 2
        || secure_delete != 1
        || foreign_keys != 1
        || trusted_schema != 0
        || u128::try_from(configured_busy).ok() != Some(busy_ms)
    {
        return Err("SQLite safety settings did not persist".to_owned());
    }
    Ok(())
}

/// Returns whether the schema was created by this call (a fresh database).
fn initialize_schema(connection: &Connection) -> Result<bool, String> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| "failed to read SQLite schema version".to_owned())?;
    if version == 0 {
        let objects: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| "failed to inspect empty SQLite schema".to_owned())?;
        if objects != 0 {
            return Err("unversioned SQLite database is not empty".to_owned());
        }
        connection
            .execute_batch(SCHEMA)
            .map_err(|_| "failed to create SQLite schema".to_owned())?;
        return Ok(true);
    }
    if version != SCHEMA_VERSION {
        return Err("unsupported SQLite schema version".to_owned());
    }
    Ok(false)
}

fn reconstruct_counters(connection: &Connection) -> Result<(u64, u64), String> {
    let (heads, live_bytes) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(ciphertext)), 0)
             FROM wallet_backup_heads",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|_| "failed to reconstruct SQLite counters".to_owned())?;
    let heads = u64::try_from(heads).map_err(|_| "SQLite head count is invalid".to_owned())?;
    let live_bytes =
        u64::try_from(live_bytes).map_err(|_| "SQLite byte total is invalid".to_owned())?;
    Ok((heads, live_bytes))
}

fn admission_configs(config: &AdmissionConfig) -> [(&'static str, AdmissionBucketConfig); 2] {
    [
        (ADMISSION_BUCKET_NAMES[0], config.new_heads),
        (ADMISSION_BUCKET_NAMES[1], config.total_growth_bytes),
    ]
}

fn system_time_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".to_owned())
}

fn synchronize_admission(
    connection: &mut Connection,
    config: &AdmissionConfig,
    now: u64,
    fresh_database: bool,
) -> Result<(), String> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| "failed to begin admission configuration transaction".to_owned())?;
    for (name, configured) in admission_configs(config) {
        let current = load_admission(&transaction, name)
            .map_err(|_| "failed to read admission configuration".to_owned())?;
        let state = match current {
            Some(mut state) => {
                state
                    .refill(now)
                    .map_err(|_| "failed to refill admission configuration".to_owned())?;
                if state.config.capacity != configured.capacity
                    || state.config.refill != configured.refill
                    || state.config.refill_interval != configured.refill_interval
                {
                    state.tokens = state.tokens.min(configured.capacity);
                    state.refill_remainder = 0;
                    state.updated_at = state.updated_at.max(now);
                    state.config = configured;
                }
                state
            }
            // Recreating a missing row on an existing database would
            // manufacture spent admission capacity, so only a fresh
            // database may seed.
            None if fresh_database => AdmissionState {
                tokens: configured.capacity,
                refill_remainder: 0,
                updated_at: now,
                config: configured,
            },
            None => {
                return Err(
                    "wallet backup admission row is missing; refusing to recreate capacity"
                        .to_owned(),
                );
            }
        };
        upsert_admission(&transaction, name, state)
            .map_err(|_| "failed to persist admission configuration".to_owned())?;
    }
    transaction
        .commit()
        .map_err(|_| "failed to commit admission configuration".to_owned())
}

fn consume_admission(
    transaction: &Transaction<'_>,
    config: &AdmissionConfig,
    charge: AdmissionCharge,
    now: u64,
) -> Result<bool, StorageError> {
    let charges = [charge.new_heads, charge.total_growth_bytes];
    let configured = admission_configs(config);
    let mut states = Vec::with_capacity(configured.len());
    for (name, expected_config) in configured {
        let mut state = load_admission(transaction, name)?.ok_or(StorageError::InvalidData)?;
        if state.config.capacity != expected_config.capacity
            || state.config.refill != expected_config.refill
            || state.config.refill_interval != expected_config.refill_interval
        {
            return Err(StorageError::InvalidData);
        }
        state.refill(now)?;
        states.push((name, state));
    }
    let admitted = states
        .iter()
        .zip(charges)
        .all(|((_, state), required)| state.tokens >= required);
    if admitted {
        for ((_, state), required) in states.iter_mut().zip(charges) {
            state.tokens = state
                .tokens
                .checked_sub(required)
                .ok_or(StorageError::InvalidData)?;
        }
    }
    for (name, state) in states {
        update_admission(transaction, name, state)?;
    }
    Ok(admitted)
}

impl AdmissionState {
    fn refill(&mut self, now: u64) -> Result<(), StorageError> {
        let elapsed = now.saturating_sub(self.updated_at);
        if elapsed == 0 {
            return Ok(());
        }
        let interval = self.config.refill_interval.as_secs();
        if interval == 0 {
            return Err(StorageError::InvalidData);
        }
        let numerator = u128::from(elapsed)
            .checked_mul(u128::from(self.config.refill))
            .and_then(|value| value.checked_add(u128::from(self.refill_remainder)))
            .ok_or(StorageError::InvalidData)?;
        let added = numerator / u128::from(interval);
        let available = u128::from(self.tokens)
            .checked_add(added)
            .ok_or(StorageError::InvalidData)?;
        if available >= u128::from(self.config.capacity) {
            self.tokens = self.config.capacity;
            self.refill_remainder = 0;
        } else {
            self.tokens = u64::try_from(available).map_err(|_| StorageError::InvalidData)?;
            self.refill_remainder = u64::try_from(numerator % u128::from(interval))
                .map_err(|_| StorageError::InvalidData)?;
        }
        self.updated_at = now;
        Ok(())
    }
}

fn load_admission(
    connection: &Connection,
    name: &str,
) -> Result<Option<AdmissionState>, StorageError> {
    let raw = connection
        .query_row(
            "SELECT tokens, refill_remainder, updated_at, capacity, refill,
                    refill_interval_secs
             FROM wallet_backup_admission WHERE bucket = ?1",
            params![name],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| StorageError::Database)?;
    raw.map(admission_from_raw).transpose()
}

fn admission_from_raw(raw: (i64, i64, i64, i64, i64, i64)) -> Result<AdmissionState, StorageError> {
    let (tokens, refill_remainder, updated_at, capacity, refill, refill_interval_secs) = raw;
    let tokens = u64::try_from(tokens).map_err(|_| StorageError::InvalidData)?;
    let refill_remainder =
        u64::try_from(refill_remainder).map_err(|_| StorageError::InvalidData)?;
    let updated_at = u64::try_from(updated_at).map_err(|_| StorageError::InvalidData)?;
    let capacity = u64::try_from(capacity).map_err(|_| StorageError::InvalidData)?;
    let refill = u64::try_from(refill).map_err(|_| StorageError::InvalidData)?;
    let refill_interval_secs =
        u64::try_from(refill_interval_secs).map_err(|_| StorageError::InvalidData)?;
    if capacity == 0
        || refill == 0
        || refill_interval_secs == 0
        || tokens > capacity
        || refill_remainder >= refill_interval_secs
    {
        return Err(StorageError::InvalidData);
    }
    Ok(AdmissionState {
        tokens,
        refill_remainder,
        updated_at,
        config: AdmissionBucketConfig {
            capacity,
            refill,
            refill_interval: Duration::from_secs(refill_interval_secs),
        },
    })
}

fn upsert_admission(
    transaction: &Transaction<'_>,
    name: &str,
    state: AdmissionState,
) -> Result<(), StorageError> {
    let values = admission_sql_values(state)?;
    transaction
        .execute(
            "INSERT INTO wallet_backup_admission (
                 bucket, tokens, refill_remainder, updated_at, capacity, refill,
                 refill_interval_secs
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(bucket) DO UPDATE SET
                 tokens = excluded.tokens,
                 refill_remainder = excluded.refill_remainder,
                 updated_at = excluded.updated_at,
                 capacity = excluded.capacity,
                 refill = excluded.refill,
                 refill_interval_secs = excluded.refill_interval_secs",
            params![
                name, values.0, values.1, values.2, values.3, values.4, values.5
            ],
        )
        .map_err(|_| StorageError::Database)?;
    Ok(())
}

fn update_admission(
    transaction: &Transaction<'_>,
    name: &str,
    state: AdmissionState,
) -> Result<(), StorageError> {
    let values = admission_sql_values(state)?;
    let changed = transaction
        .execute(
            "UPDATE wallet_backup_admission SET
                 tokens = ?2,
                 refill_remainder = ?3,
                 updated_at = ?4,
                 capacity = ?5,
                 refill = ?6,
                 refill_interval_secs = ?7
             WHERE bucket = ?1",
            params![
                name, values.0, values.1, values.2, values.3, values.4, values.5
            ],
        )
        .map_err(|_| StorageError::Database)?;
    if changed != 1 {
        return Err(StorageError::InvalidData);
    }
    Ok(())
}

fn admission_sql_values(
    state: AdmissionState,
) -> Result<(i64, i64, i64, i64, i64, i64), StorageError> {
    Ok((
        i64::try_from(state.tokens).map_err(|_| StorageError::InvalidData)?,
        i64::try_from(state.refill_remainder).map_err(|_| StorageError::InvalidData)?,
        i64::try_from(state.updated_at).map_err(|_| StorageError::InvalidData)?,
        i64::try_from(state.config.capacity).map_err(|_| StorageError::InvalidData)?,
        i64::try_from(state.config.refill).map_err(|_| StorageError::InvalidData)?,
        i64::try_from(state.config.refill_interval.as_secs())
            .map_err(|_| StorageError::InvalidData)?,
    ))
}

fn verify_admission_rows(connection: &Connection) -> Result<(), String> {
    let (total, new_heads, total_growth) = connection
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(bucket = 'new_heads'), 0),
                    COALESCE(SUM(bucket = 'total_growth_bytes'), 0)
             FROM wallet_backup_admission",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(|_| "failed to verify wallet backup admission rows".to_owned())?;
    if (total, new_heads, total_growth) != (2, 1, 1) {
        return Err("wallet backup admission rows are incomplete".to_owned());
    }
    for name in ADMISSION_BUCKET_NAMES {
        load_admission(connection, name)
            .map_err(|_| "wallet backup admission row is invalid".to_owned())?
            .ok_or_else(|| "wallet backup admission row is missing".to_owned())?;
    }
    Ok(())
}

fn verify_connection(connection: &Connection) -> Result<VerifyReport, String> {
    verify_schema(connection)?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| "SQLite integrity check failed to run".to_owned())?;
    if integrity != "ok" {
        return Err("SQLite integrity check failed".to_owned());
    }
    let mut statement = connection
        .prepare(
            "SELECT author_pubkey, generation, ciphertext, ciphertext_sha256, updated_at
             FROM wallet_backup_heads ORDER BY author_pubkey",
        )
        .map_err(|_| "failed to inspect SQLite rows".to_owned())?;
    let mut rows = statement
        .query([])
        .map_err(|_| "failed to read SQLite rows".to_owned())?;
    let mut heads = 0_u64;
    let mut live_bytes = 0_u64;
    let mut aggregate = Sha256::new();
    loop {
        let Some(row) = rows
            .next()
            .map_err(|_| "failed while reading SQLite rows".to_owned())?
        else {
            break;
        };
        let author = row
            .get::<_, Vec<u8>>(0)
            .map_err(|_| "invalid SQLite public key".to_owned())?;
        let author: [u8; 32] = author
            .try_into()
            .map_err(|_| "invalid SQLite public key".to_owned())?;
        let head = head_from_raw((
            row.get(1)
                .map_err(|_| "invalid SQLite generation".to_owned())?,
            row.get(2)
                .map_err(|_| "invalid SQLite ciphertext".to_owned())?,
            row.get(3)
                .map_err(|_| "invalid SQLite ciphertext hash".to_owned())?,
            row.get(4)
                .map_err(|_| "invalid SQLite timestamp".to_owned())?,
        ))
        .map_err(|_| "SQLite row violates wallet backup invariants".to_owned())?;
        if let (Some(ciphertext), Some(stored_hash)) =
            (head.ciphertext.as_ref(), head.ciphertext_sha256.as_ref())
        {
            let actual: [u8; 32] = Sha256::digest(ciphertext).into();
            if actual != *stored_hash {
                return Err("SQLite ciphertext commitment mismatch".to_owned());
            }
            live_bytes = live_bytes
                .checked_add(
                    u64::try_from(ciphertext.len())
                        .map_err(|_| "SQLite byte total overflow".to_owned())?,
                )
                .ok_or_else(|| "SQLite byte total overflow".to_owned())?;
        }
        heads = heads
            .checked_add(1)
            .ok_or_else(|| "SQLite head count overflow".to_owned())?;
        aggregate.update(author);
        aggregate.update(head.generation.to_be_bytes());
        aggregate.update(head.updated_at.to_be_bytes());
        match head.ciphertext_sha256 {
            Some(hash) => {
                aggregate.update([1]);
                aggregate.update(hash);
            }
            None => aggregate.update([0]),
        }
    }
    Ok(VerifyReport {
        heads,
        live_bytes,
        aggregate_sha256: hex::encode(aggregate.finalize()),
    })
}

fn verify_schema(connection: &Connection) -> Result<(), String> {
    verify_schema_objects(connection)?;
    verify_admission_rows(connection)?;
    Ok(())
}

fn verify_schema_objects(connection: &Connection) -> Result<(), String> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| "failed to read SQLite schema version".to_owned())?;
    if version != SCHEMA_VERSION {
        return Err("unsupported SQLite schema version".to_owned());
    }
    let table_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'wallet_backup_heads'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "wallet backup table is missing".to_owned())?;
    if table_sql != TABLE_SCHEMA {
        return Err("wallet backup table definition does not match version 1".to_owned());
    }
    let index_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'index' AND name = 'wallet_backup_tombstones_by_time'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "wallet backup tombstone index is missing".to_owned())?;
    if index_sql != TOMBSTONE_INDEX_SCHEMA {
        return Err("wallet backup tombstone index does not match version 1".to_owned());
    }
    let admission_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'table' AND name = 'wallet_backup_admission'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "wallet backup admission table is missing".to_owned())?;
    if admission_sql != ADMISSION_TABLE_SCHEMA {
        return Err("wallet backup admission table does not match version 1".to_owned());
    }
    let user_objects: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "failed to count SQLite schema objects".to_owned())?;
    if user_objects != 3 {
        return Err("SQLite contains an unexpected schema object".to_owned());
    }
    Ok(())
}

pub fn verify_backup(path: &Path) -> Result<VerifyReport, String> {
    if !path.is_absolute() {
        return Err("backup path must be absolute".to_owned());
    }
    reject_symlink(path)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| "failed to open backup database".to_owned())?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|_| "failed to disable trusted schema for verification".to_owned())?;
    verify_connection(&connection)
}

#[cfg(test)]
fn parent_of(path: &Path) -> Result<&Path, String> {
    path.parent()
        .ok_or_else(|| "path has no parent directory".to_owned())
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("refusing symbolic link path".to_owned())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("failed to inspect filesystem path".to_owned()),
    }
}

fn lock_path(database: &Path) -> PathBuf {
    let mut value = database.as_os_str().to_os_string();
    value.push(".serve.lock");
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn test_path(name: &str) -> Result<PathBuf, String> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|_| "randomness unavailable".to_owned())?;
        let directory =
            env::temp_dir().join(format!("backup-server-{name}-{}", hex::encode(random)));
        fs::create_dir(&directory).map_err(|_| "failed to create test directory".to_owned())?;
        Ok(directory.join("backup.sqlite3"))
    }

    fn config(path: PathBuf) -> StorageConfig {
        let bucket = AdmissionBucketConfig {
            capacity: 1024,
            refill: 1024,
            refill_interval: Duration::from_secs(60),
        };
        StorageConfig {
            path,
            queue_depth: 8,
            busy_timeout: Duration::from_secs(1),
            max_live_bytes: 1024,
            max_heads: 4,
            admission: AdmissionConfig {
                new_heads: bucket,
                total_growth_bytes: bucket,
            },
        }
    }

    fn admission_tokens(path: &Path) -> Result<[u64; 2], String> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| "failed to open admission database".to_owned())?;
        let mut tokens = [0_u64; 2];
        for (index, name) in ADMISSION_BUCKET_NAMES.into_iter().enumerate() {
            tokens[index] = load_admission(&connection, name)
                .map_err(|error| format!("failed to read admission bucket: {error:?}"))?
                .ok_or_else(|| format!("admission bucket {name} is missing"))?
                .tokens;
        }
        Ok(tokens)
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn retry_delete_and_recreate_preserve_state_machine() -> Result<(), String> {
        let path = test_path("state")?;
        let owner = StorageOwner::start(config(path.clone()))?;
        let storage = owner.client();
        let npub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let author: [u8; 32] = hex::decode(npub)
            .map_err(|_| "invalid test public key".to_owned())?
            .try_into()
            .map_err(|_| "invalid test public key".to_owned())?;
        let ciphertext = vec![0, 1, 2, 3];
        let hash: [u8; 32] = Sha256::digest(&ciphertext).into();
        let hash_hex = hex::encode(hash);
        let first_etag = compute_etag(BackupStream::WalletBackup, npub, 1, Some(&hash_hex));
        let first = storage
            .store(
                npub.to_owned(),
                author,
                1,
                None,
                first_etag,
                ciphertext.clone(),
                hash,
                100,
            )
            .await
            .map_err(|error| format!("store failed: {error:?}"))?;
        assert_eq!(first, MutationOutcome::Applied);
        assert_eq!(
            storage.metrics_snapshot(),
            StorageMetricsSnapshot {
                new_heads_admitted: 1,
                new_allocation_bytes_admitted: 4,
                existing_head_growth_bytes_admitted: 0,
                current_heads: 1,
                current_live_bytes: 4,
            }
        );
        let retry = storage
            .store(
                npub.to_owned(),
                author,
                1,
                Some([9; 32]),
                first_etag,
                ciphertext,
                hash,
                200,
            )
            .await
            .map_err(|error| format!("retry failed: {error:?}"))?;
        assert_eq!(retry, MutationOutcome::ExactRetry);
        assert_eq!(
            storage.metrics_snapshot(),
            StorageMetricsSnapshot {
                current_heads: 1,
                current_live_bytes: 4,
                ..StorageMetricsSnapshot::default()
            }
        );
        let unchanged = storage
            .fetch(author)
            .await
            .map_err(|error| format!("fetch failed: {error:?}"))?
            .ok_or_else(|| "head missing".to_owned())?;
        assert_eq!(unchanged.updated_at, 100);

        let grown_ciphertext = vec![0, 1, 2, 3, 4, 5];
        let grown_hash: [u8; 32] = Sha256::digest(&grown_ciphertext).into();
        let grown_etag = compute_etag(
            BackupStream::WalletBackup,
            npub,
            2,
            Some(&hex::encode(grown_hash)),
        );
        assert_eq!(
            storage
                .store(
                    npub.to_owned(),
                    author,
                    2,
                    Some(first_etag),
                    grown_etag,
                    grown_ciphertext,
                    grown_hash,
                    250,
                )
                .await
                .map_err(|error| format!("growth store failed: {error:?}"))?,
            MutationOutcome::Applied
        );
        assert_eq!(
            storage.metrics_snapshot(),
            StorageMetricsSnapshot {
                new_heads_admitted: 0,
                new_allocation_bytes_admitted: 0,
                existing_head_growth_bytes_admitted: 2,
                current_heads: 1,
                current_live_bytes: 6,
            }
        );

        let tombstone_etag = compute_etag(BackupStream::WalletBackup, npub, 3, None);
        let deleted = storage
            .delete(npub.to_owned(), author, 3, grown_etag, tombstone_etag, 300)
            .await
            .map_err(|error| format!("delete failed: {error:?}"))?;
        assert_eq!(deleted, MutationOutcome::Applied);
        assert_eq!(
            storage.metrics_snapshot(),
            StorageMetricsSnapshot {
                current_heads: 1,
                current_live_bytes: 0,
                ..StorageMetricsSnapshot::default()
            }
        );
        let delete_retry = storage
            .delete(npub.to_owned(), author, 3, [8; 32], tombstone_etag, 400)
            .await
            .map_err(|error| format!("delete retry failed: {error:?}"))?;
        assert_eq!(delete_retry, MutationOutcome::ExactRetry);
        let tombstone = storage
            .fetch(author)
            .await
            .map_err(|error| format!("fetch failed: {error:?}"))?
            .ok_or_else(|| "tombstone missing".to_owned())?;
        assert_eq!(tombstone.updated_at, 300);

        let revived_ciphertext = vec![9, 9];
        let revived_hash: [u8; 32] = Sha256::digest(&revived_ciphertext).into();
        let revived_etag = compute_etag(
            BackupStream::WalletBackup,
            npub,
            4,
            Some(&hex::encode(revived_hash)),
        );
        assert_eq!(
            storage
                .store(
                    npub.to_owned(),
                    author,
                    4,
                    Some(tombstone_etag),
                    revived_etag,
                    revived_ciphertext,
                    revived_hash,
                    500,
                )
                .await
                .map_err(|error| format!("revival store failed: {error:?}"))?,
            MutationOutcome::Applied
        );
        assert_eq!(
            storage.metrics_snapshot(),
            StorageMetricsSnapshot {
                new_heads_admitted: 0,
                new_allocation_bytes_admitted: 2,
                existing_head_growth_bytes_admitted: 0,
                current_heads: 1,
                current_live_bytes: 2,
            }
        );
        owner.shutdown().await?;
        let report = verify_backup(&path)?;
        assert_eq!((report.heads, report.live_bytes), (1, 2));
        fs::remove_dir_all(parent_of(&path)?).map_err(|_| "cleanup failed".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn capacity_projection_and_cleanup_are_exact() -> Result<(), String> {
        let path = test_path("capacity")?;
        let mut storage_config = config(path.clone());
        storage_config.max_live_bytes = 4;
        storage_config.max_heads = 1;
        let owner = StorageOwner::start(storage_config)?;
        let storage = owner.client();
        let first_npub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let first_author: [u8; 32] = hex::decode(first_npub)
            .map_err(|_| "invalid first public key".to_owned())?
            .try_into()
            .map_err(|_| "invalid first public key".to_owned())?;
        let first_ciphertext = vec![0, 1, 2, 3];
        let first_hash: [u8; 32] = Sha256::digest(&first_ciphertext).into();
        let first_etag = compute_etag(
            BackupStream::WalletBackup,
            first_npub,
            1,
            Some(&hex::encode(first_hash)),
        );
        assert_eq!(
            storage
                .store(
                    first_npub.to_owned(),
                    first_author,
                    1,
                    None,
                    first_etag,
                    first_ciphertext,
                    first_hash,
                    100,
                )
                .await
                .map_err(|error| format!("first store failed: {error:?}"))?,
            MutationOutcome::Applied
        );

        let second_npub = "02".repeat(32);
        let second_author = [2_u8; 32];
        let empty_hash: [u8; 32] = Sha256::digest([]).into();
        let second_etag = compute_etag(
            BackupStream::WalletBackup,
            &second_npub,
            1,
            Some(&hex::encode(empty_hash)),
        );
        assert_eq!(
            storage
                .store(
                    second_npub.clone(),
                    second_author,
                    1,
                    None,
                    second_etag,
                    Vec::new(),
                    empty_hash,
                    200,
                )
                .await
                .map_err(|error| format!("head limit check failed: {error:?}"))?,
            MutationOutcome::CapacityExceeded
        );

        let oversized = vec![0_u8; 5];
        let oversized_hash: [u8; 32] = Sha256::digest(&oversized).into();
        let oversized_etag = compute_etag(
            BackupStream::WalletBackup,
            first_npub,
            2,
            Some(&hex::encode(oversized_hash)),
        );
        assert_eq!(
            storage
                .store(
                    first_npub.to_owned(),
                    first_author,
                    2,
                    Some(first_etag),
                    oversized_etag,
                    oversized,
                    oversized_hash,
                    300,
                )
                .await
                .map_err(|error| format!("byte limit check failed: {error:?}"))?,
            MutationOutcome::CapacityExceeded
        );

        let tombstone_etag = compute_etag(BackupStream::WalletBackup, first_npub, 2, None);
        assert_eq!(
            storage
                .delete(
                    first_npub.to_owned(),
                    first_author,
                    2,
                    first_etag,
                    tombstone_etag,
                    400,
                )
                .await
                .map_err(|error| format!("delete failed: {error:?}"))?,
            MutationOutcome::Applied
        );
        assert_eq!(
            storage
                .cleanup(401, 1)
                .await
                .map_err(|error| format!("cleanup failed: {error:?}"))?,
            1
        );
        assert_eq!(
            storage
                .store(
                    second_npub,
                    second_author,
                    1,
                    None,
                    second_etag,
                    Vec::new(),
                    empty_hash,
                    500,
                )
                .await
                .map_err(|error| format!("post-cleanup store failed: {error:?}"))?,
            MutationOutcome::Applied
        );
        owner.shutdown().await?;
        fs::remove_dir_all(parent_of(&path)?).map_err(|_| "cleanup failed".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn admission_is_atomic_persistent_and_not_refunded_on_delete() -> Result<(), String> {
        let path = test_path("admission")?;
        let mut storage_config = config(path.clone());
        storage_config.admission = AdmissionConfig {
            new_heads: AdmissionBucketConfig {
                capacity: 1,
                refill: 1,
                refill_interval: Duration::from_secs(3_600),
            },
            total_growth_bytes: AdmissionBucketConfig {
                capacity: 4,
                refill: 4,
                refill_interval: Duration::from_secs(3_600),
            },
        };
        let first_npub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let first_author: [u8; 32] = hex::decode(first_npub)
            .map_err(|_| "invalid first public key".to_owned())?
            .try_into()
            .map_err(|_| "invalid first public key".to_owned())?;
        let ciphertext = vec![0, 1, 2, 3];
        let hash: [u8; 32] = Sha256::digest(&ciphertext).into();
        let first_etag = compute_etag(
            BackupStream::WalletBackup,
            first_npub,
            1,
            Some(&hex::encode(hash)),
        );
        let owner = StorageOwner::start(storage_config.clone())?;
        let storage = owner.client();
        assert_eq!(
            storage
                .store(
                    first_npub.to_owned(),
                    first_author,
                    1,
                    None,
                    first_etag,
                    ciphertext.clone(),
                    hash,
                    100,
                )
                .await
                .map_err(|error| format!("first admission failed: {error:?}"))?,
            MutationOutcome::Applied
        );
        let second_npub = "02".repeat(32);
        let second_author = [2; 32];
        let empty_hash: [u8; 32] = Sha256::digest([]).into();
        let second_etag = compute_etag(
            BackupStream::WalletBackup,
            &second_npub,
            1,
            Some(&hex::encode(empty_hash)),
        );
        assert_eq!(
            storage
                .store(
                    second_npub.clone(),
                    second_author,
                    1,
                    None,
                    second_etag,
                    Vec::new(),
                    empty_hash,
                    101,
                )
                .await
                .map_err(|error| format!("second admission failed: {error:?}"))?,
            MutationOutcome::AdmissionLimited
        );
        let tombstone_etag = compute_etag(BackupStream::WalletBackup, first_npub, 2, None);
        assert_eq!(
            storage
                .delete(
                    first_npub.to_owned(),
                    first_author,
                    2,
                    first_etag,
                    tombstone_etag,
                    102,
                )
                .await
                .map_err(|error| format!("delete failed: {error:?}"))?,
            MutationOutcome::Applied
        );
        owner.shutdown().await?;

        let owner = StorageOwner::start(storage_config)?;
        let storage = owner.client();
        let recreated_etag = compute_etag(
            BackupStream::WalletBackup,
            first_npub,
            3,
            Some(&hex::encode(hash)),
        );
        assert_eq!(
            storage
                .store(
                    first_npub.to_owned(),
                    first_author,
                    3,
                    Some(tombstone_etag),
                    recreated_etag,
                    ciphertext,
                    hash,
                    103,
                )
                .await
                .map_err(|error| format!("recreation admission failed: {error:?}"))?,
            MutationOutcome::AdmissionLimited
        );
        assert!(
            storage
                .fetch(second_author)
                .await
                .map_err(|error| format!("second fetch failed: {error:?}"))?
                .is_none()
        );
        let first = storage
            .fetch(first_author)
            .await
            .map_err(|error| format!("first fetch failed: {error:?}"))?
            .ok_or_else(|| "first head missing".to_owned())?;
        assert!(first.is_tombstone());
        owner.shutdown().await?;
        fs::remove_dir_all(parent_of(&path)?).map_err(|_| "cleanup failed".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn committed_store_retry_after_restart_is_admission_free() -> Result<(), String> {
        let path = test_path("admission-retry-restart")?;
        let mut storage_config = config(path.clone());
        storage_config.admission = AdmissionConfig {
            new_heads: AdmissionBucketConfig {
                capacity: 1,
                refill: 1,
                refill_interval: Duration::from_secs(86_400),
            },
            total_growth_bytes: AdmissionBucketConfig {
                capacity: 4,
                refill: 4,
                refill_interval: Duration::from_secs(86_400),
            },
        };
        let npub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let author: [u8; 32] = hex::decode(npub)
            .map_err(|_| "invalid test public key".to_owned())?
            .try_into()
            .map_err(|_| "invalid test public key".to_owned())?;
        let ciphertext = vec![0, 1, 2, 3];
        let hash: [u8; 32] = Sha256::digest(&ciphertext).into();
        let etag = compute_etag(
            BackupStream::WalletBackup,
            npub,
            1,
            Some(&hex::encode(hash)),
        );
        let owner = StorageOwner::start(storage_config.clone())?;
        assert_eq!(
            owner
                .client()
                .store(
                    npub.to_owned(),
                    author,
                    1,
                    None,
                    etag,
                    ciphertext.clone(),
                    hash,
                    100,
                )
                .await
                .map_err(|error| format!("store failed: {error:?}"))?,
            MutationOutcome::Applied
        );
        owner.shutdown().await?;
        assert_eq!(admission_tokens(&path)?, [0, 0]);

        let owner = StorageOwner::start(storage_config)?;
        let storage = owner.client();
        assert_eq!(
            storage
                .store(
                    npub.to_owned(),
                    author,
                    1,
                    Some([9; 32]),
                    etag,
                    ciphertext,
                    hash,
                    200,
                )
                .await
                .map_err(|error| format!("restart retry failed: {error:?}"))?,
            MutationOutcome::ExactRetry
        );
        let head = storage
            .fetch(author)
            .await
            .map_err(|error| format!("restart fetch failed: {error:?}"))?
            .ok_or_else(|| "stored head is missing".to_owned())?;
        assert_eq!(head.updated_at, 100);
        owner.shutdown().await?;
        assert_eq!(admission_tokens(&path)?, [0, 0]);
        fs::remove_dir_all(parent_of(&path)?).map_err(|_| "cleanup failed".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn failed_head_insert_rolls_back_admission() -> Result<(), String> {
        let path = test_path("admission-head-failure")?;
        let oversized_len = ABSOLUTE_MAX_CIPHERTEXT_BYTES
            .checked_add(1)
            .ok_or_else(|| "oversized test length overflow".to_owned())?;
        let oversized_bytes =
            u64::try_from(oversized_len).map_err(|_| "oversized length is invalid".to_owned())?;
        let byte_bucket = AdmissionBucketConfig {
            capacity: oversized_bytes,
            refill: oversized_bytes,
            refill_interval: Duration::from_secs(86_400),
        };
        let mut storage_config = config(path.clone());
        storage_config.max_live_bytes = oversized_bytes;
        storage_config.admission = AdmissionConfig {
            new_heads: AdmissionBucketConfig {
                capacity: 2,
                refill: 2,
                refill_interval: Duration::from_secs(86_400),
            },
            total_growth_bytes: byte_bucket,
        };
        let owner = StorageOwner::start(storage_config)?;
        let storage = owner.client();
        let npub = "03".repeat(32);
        let author = [3_u8; 32];
        let ciphertext = vec![7_u8; oversized_len];
        let hash: [u8; 32] = Sha256::digest(&ciphertext).into();
        let etag = compute_etag(
            BackupStream::WalletBackup,
            &npub,
            1,
            Some(&hex::encode(hash)),
        );
        assert_eq!(
            storage
                .store(npub, author, 1, None, etag, ciphertext, hash, 100,)
                .await,
            Err(CallError::Storage)
        );
        assert!(
            storage
                .fetch(author)
                .await
                .map_err(|error| format!("post-failure fetch failed: {error:?}"))?
                .is_none()
        );
        owner.shutdown().await?;
        assert_eq!(admission_tokens(&path)?, [2, oversized_bytes]);
        fs::remove_dir_all(parent_of(&path)?).map_err(|_| "cleanup failed".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn missing_admission_row_on_existing_database_fails_closed() -> Result<(), String> {
        let path = test_path("admission-row-missing")?;
        let owner = StorageOwner::start(config(path.clone()))?;
        owner.shutdown().await?;
        let connection =
            Connection::open(&path).map_err(|_| "failed to reopen database".to_owned())?;
        connection
            .execute(
                "DELETE FROM wallet_backup_admission WHERE bucket = 'new_heads'",
                [],
            )
            .map_err(|_| "failed to delete admission row".to_owned())?;
        drop(connection);
        let Err(error) = StorageOwner::start(config(path.clone())) else {
            return Err("startup with a missing admission row succeeded".to_owned());
        };
        assert!(error.contains("refusing to recreate capacity"));
        fs::remove_dir_all(parent_of(&path)?).map_err(|_| "cleanup failed".to_owned())?;
        Ok(())
    }

    #[test]
    fn admission_refill_preserves_fractional_progress_and_caps_bursts() -> Result<(), String> {
        let mut state = AdmissionState {
            tokens: 0,
            refill_remainder: 0,
            updated_at: 100,
            config: AdmissionBucketConfig {
                capacity: 5,
                refill: 3,
                refill_interval: Duration::from_secs(10),
            },
        };
        state
            .refill(101)
            .map_err(|_| "first refill failed".to_owned())?;
        assert_eq!((state.tokens, state.refill_remainder), (0, 3));
        state
            .refill(104)
            .map_err(|_| "second refill failed".to_owned())?;
        assert_eq!((state.tokens, state.refill_remainder), (1, 2));
        state
            .refill(1_000)
            .map_err(|_| "capacity refill failed".to_owned())?;
        assert_eq!((state.tokens, state.refill_remainder), (5, 0));
        Ok(())
    }

    #[test]
    fn verify_backup_accepts_an_offline_copy_and_rejects_corruption() -> Result<(), String> {
        let path = test_path("verify-copy")?;
        let owner = StorageOwner::start(config(path.clone()))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "failed to create runtime".to_owned())?;
        runtime.block_on(owner.shutdown())?;
        let copy = parent_of(&path)?.join("copy.sqlite3");
        fs::copy(&path, &copy).map_err(|_| "failed to copy database".to_owned())?;
        let report = verify_backup(&copy)?;
        assert_eq!(report.heads, 0);
        let connection = Connection::open(&copy).map_err(|_| "failed to open copy".to_owned())?;
        connection
            .execute("DELETE FROM wallet_backup_admission", [])
            .map_err(|_| "failed to corrupt copy".to_owned())?;
        drop(connection);
        assert!(verify_backup(&copy).is_err());
        fs::remove_dir_all(parent_of(&path)?).map_err(|_| "cleanup failed".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn serve_lock_and_schema_shape_fail_closed() -> Result<(), String> {
        let path = test_path("startup-guards")?;
        let owner = StorageOwner::start(config(path.clone()))?;
        assert!(StorageOwner::start(config(path.clone())).is_err());
        owner.shutdown().await?;

        let connection = Connection::open(&path)
            .map_err(|_| "failed to open startup-guard database".to_owned())?;
        connection
            .execute("CREATE TABLE unexpected (value INTEGER)", [])
            .map_err(|_| "failed to alter startup-guard schema".to_owned())?;
        drop(connection);
        assert!(verify_backup(&path).is_err());
        assert!(StorageOwner::start(config(path.clone())).is_err());
        fs::remove_dir_all(parent_of(&path)?).map_err(|_| "cleanup failed".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn startup_defers_semantic_scan_and_serves_over_capacity() -> Result<(), String> {
        let path = test_path("startup-reconstruction")?;
        let initial = StorageOwner::start(config(path.clone()))?;
        initial.shutdown().await?;
        let author = [3_u8; 32];
        let connection = Connection::open(&path)
            .map_err(|_| "failed to open startup-reconstruction database".to_owned())?;
        connection
            .execute(
                "INSERT INTO wallet_backup_heads (
                     author_pubkey, generation, ciphertext, ciphertext_sha256, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![author, 1_i64, vec![0_u8; 4], [9_u8; 32], 10_i64],
            )
            .map_err(|_| "failed to seed startup-reconstruction database".to_owned())?;
        drop(connection);

        let mut reduced = config(path.clone());
        reduced.max_live_bytes = 3;
        let owner = StorageOwner::start(reduced)?;
        assert!(
            owner
                .client()
                .fetch(author)
                .await
                .map_err(|error| format!("fetch failed: {error:?}"))?
                .is_some()
        );
        owner.shutdown().await?;
        assert!(verify_backup(&path).is_err());
        fs::remove_dir_all(parent_of(&path)?).map_err(|_| "cleanup failed".to_owned())?;
        Ok(())
    }

    #[tokio::test]
    async fn maximum_generation_retries_without_overflow() -> Result<(), String> {
        let path = test_path("maximum-generation")?;
        let initial = StorageOwner::start(config(path.clone()))?;
        initial.shutdown().await?;
        let npub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let author: [u8; 32] = hex::decode(npub)
            .map_err(|_| "invalid test public key".to_owned())?
            .try_into()
            .map_err(|_| "invalid test public key".to_owned())?;
        let ciphertext = vec![1, 2, 3];
        let hash: [u8; 32] = Sha256::digest(&ciphertext).into();
        let connection = Connection::open(&path)
            .map_err(|_| "failed to open maximum-generation database".to_owned())?;
        connection
            .execute(
                "INSERT INTO wallet_backup_heads (
                     author_pubkey, generation, ciphertext, ciphertext_sha256, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![author, i64::MAX, ciphertext, hash, 10_i64],
            )
            .map_err(|_| "failed to seed maximum generation".to_owned())?;
        drop(connection);
        let owner = StorageOwner::start(config(path.clone()))?;
        let storage = owner.client();
        let max_generation = u64::try_from(i64::MAX)
            .map_err(|_| "maximum generation conversion failed".to_owned())?;
        let hash_hex = hex::encode(hash);
        let etag = compute_etag(
            BackupStream::WalletBackup,
            npub,
            max_generation,
            Some(&hash_hex),
        );
        let retry = storage
            .store(
                npub.to_owned(),
                author,
                i64::MAX,
                Some([9; 32]),
                etag,
                vec![1, 2, 3],
                hash,
                20,
            )
            .await
            .map_err(|error| format!("maximum retry failed: {error:?}"))?;
        assert_eq!(retry, MutationOutcome::ExactRetry);
        let changed = vec![4, 5, 6];
        let changed_hash: [u8; 32] = Sha256::digest(&changed).into();
        let changed_etag = compute_etag(
            BackupStream::WalletBackup,
            npub,
            max_generation,
            Some(&hex::encode(changed_hash)),
        );
        let conflict = storage
            .store(
                npub.to_owned(),
                author,
                i64::MAX,
                Some(etag),
                changed_etag,
                changed,
                changed_hash,
                30,
            )
            .await
            .map_err(|error| format!("maximum conflict failed: {error:?}"))?;
        assert_eq!(conflict, MutationOutcome::HeadConflict);
        owner.shutdown().await?;
        let connection = Connection::open(&path)
            .map_err(|_| "failed to reopen maximum-generation database".to_owned())?;
        connection
            .execute(
                "UPDATE wallet_backup_heads SET
                     ciphertext = NULL, ciphertext_sha256 = NULL, updated_at = 40
                 WHERE author_pubkey = ?1",
                params![author],
            )
            .map_err(|_| "failed to seed maximum tombstone".to_owned())?;
        drop(connection);
        let owner = StorageOwner::start(config(path.clone()))?;
        let tombstone_etag = compute_etag(BackupStream::WalletBackup, npub, max_generation, None);
        let delete_retry = owner
            .client()
            .delete(
                npub.to_owned(),
                author,
                i64::MAX,
                [8; 32],
                tombstone_etag,
                50,
            )
            .await
            .map_err(|error| format!("maximum delete retry failed: {error:?}"))?;
        assert_eq!(delete_retry, MutationOutcome::ExactRetry);
        owner.shutdown().await?;
        fs::remove_dir_all(parent_of(&path)?).map_err(|_| "cleanup failed".to_owned())?;
        Ok(())
    }
}
