use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, params};
use secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    os::unix::fs::OpenOptionsExt,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

const MAX_RECORD: usize = 128 * 1024;
const MAX_GRANT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_OWNER_BYTES: i64 = 16 * 1024 * 1024;
const MAX_GLOBAL_BYTES: u64 = 256 * 1024 * 1024;
const PAGE: i64 = 8;
const DOMAIN: &str = "bullbitcoin-arkade-recovery-prototype-v1";
const SCHEMA: &str = "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;
        CREATE TABLE IF NOT EXISTS recovery_grants(owner TEXT NOT NULL, grant_id TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(owner,grant_id));
        CREATE TABLE IF NOT EXISTS recovery_records(id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, grant_id TEXT NOT NULL, hash TEXT NOT NULL, ciphertext BLOB NOT NULL, grant_json TEXT NOT NULL, UNIQUE(owner,grant_id,hash));
        CREATE INDEX IF NOT EXISTS recovery_owner_id ON recovery_records(owner,id);";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub owner: String,
    pub publisher: String,
    pub origin: String,
    pub id: String,
    pub scope: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub max_records: u64,
    pub max_bytes: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRequest {
    pub grant: Grant,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
    pub ciphertext_bytes: u64,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchRequest {
    pub owner: String,
    pub after: u64,
    pub snapshot: u64,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub id: i64,
    pub ciphertext_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: i64,
    pub grant: Grant,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Page {
    pub records: Vec<Record>,
    pub snapshot: u64,
    pub next_after: Option<u64>,
}

/// Per-deployment capacity; owner and grant limits remain wire-compatible.
#[derive(Debug, Clone)]
pub struct RecoveryPolicy {
    pub origin: String,
    pub publisher: String,
    pub max_records: u64,
    pub max_bytes: u64,
}

impl RecoveryPolicy {
    pub fn validate(&self) -> Result<(), String> {
        let uri = self
            .origin
            .parse::<axum::http::Uri>()
            .map_err(|_| "invalid recovery origin".to_owned())?;
        let allowed_scheme = uri.scheme_str() == Some("https")
            || (uri.scheme_str() == Some("http")
                && uri.host() == Some("127.0.0.1")
                && uri.port_u16().is_some());
        if !allowed_scheme
            || uri.host().is_none()
            || uri.path() != "/"
            || key(&self.publisher).is_err()
            || self.origin.contains(['\0', '?', '#', '@'])
            || self.origin.ends_with('/')
            || !(self.origin.starts_with("https://")
                || self.origin.starts_with("http://127.0.0.1:"))
            || self.max_records == 0
            || self.max_records > i64::MAX as u64
            || self.max_bytes == 0
            || self.max_bytes > i64::MAX as u64
        {
            return Err("invalid recovery publisher, origin or capacity".to_owned());
        }
        Ok(())
    }
}

struct Database {
    conn: Connection,
    _lock: std::fs::File,
}
#[derive(Clone)]
struct App {
    db: Arc<Mutex<Database>>,
    slots: Arc<Semaphore>,
    origin: String,
    publisher: String,
}

#[derive(Debug)]
pub struct Error(pub StatusCode);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (
            self.0,
            [(header::CACHE_CONTROL, "no-store")],
            "recovery request rejected",
        )
            .into_response()
    }
}
fn bad() -> Error {
    Error(StatusCode::BAD_REQUEST)
}
fn internal<E>(_: E) -> Error {
    Error(StatusCode::INTERNAL_SERVER_ERROR)
}
fn denied<E>(_: E) -> Error {
    Error(StatusCode::UNAUTHORIZED)
}
fn hex_bytes(value: &str, length: usize) -> Result<Vec<u8>, Error> {
    if value.len() != length * 2
        || value
            .bytes()
            .any(|c| !c.is_ascii_digit() && !(b'a'..=b'f').contains(&c))
    {
        return Err(bad());
    }
    hex::decode(value).map_err(|_| bad())
}
fn key(value: &str) -> Result<XOnlyPublicKey, Error> {
    let bytes: [u8; 32] = hex_bytes(value, 32)?.try_into().map_err(|_| bad())?;
    XOnlyPublicKey::from_byte_array(bytes).map_err(|_| bad())
}
pub fn digest(fields: &[&str]) -> [u8; 32] {
    Sha256::digest(fields.join("\0").as_bytes()).into()
}
pub fn grant_digest(g: &Grant) -> [u8; 32] {
    digest(&[
        DOMAIN,
        "grant",
        &g.owner,
        &g.publisher,
        &g.origin,
        &g.id,
        &g.scope,
        &g.valid_from.to_string(),
        &g.expires_at.to_string(),
        &g.max_records.to_string(),
        &g.max_bytes.to_string(),
    ])
}
pub fn store_digest(s: &StoreRequest) -> [u8; 32] {
    digest(&[
        DOMAIN,
        "store",
        &hex::encode(grant_digest(&s.grant)),
        &s.ciphertext_sha256,
        &s.ciphertext_bytes.to_string(),
        &s.timestamp.to_string(),
    ])
}
pub fn fetch_digest(f: &FetchRequest) -> [u8; 32] {
    digest(&[
        DOMAIN,
        "fetch",
        &f.owner,
        &f.after.to_string(),
        &f.snapshot.to_string(),
        &f.timestamp.to_string(),
    ])
}
fn verify(pubkey: &str, hash: &[u8; 32], sig: &str) -> Result<(), Error> {
    let raw: [u8; 64] = hex_bytes(sig, 64)?.try_into().map_err(|_| bad())?;
    Secp256k1::verification_only()
        .verify_schnorr(&Signature::from_byte_array(raw), hash, &key(pubkey)?)
        .map_err(denied)
}
fn now() -> Result<u64, Error> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(internal)?
        .as_secs())
}
fn fresh(timestamp: u64, clock: u64) -> Result<(), Error> {
    if clock.abs_diff(timestamp) > 300 {
        return Err(Error(StatusCode::UNAUTHORIZED));
    }
    Ok(())
}

#[allow(dead_code)] // The standalone compatibility binary uses this launcher.
pub fn app(
    path: &str,
    origin: String,
    publisher: String,
) -> Result<Router, Box<dyn std::error::Error>> {
    RecoveryPolicy {
        origin: origin.clone(),
        publisher: publisher.clone(),
        max_records: 10_000,
        max_bytes: MAX_GLOBAL_BYTES,
    }
    .validate()?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(format!("{path}.lock"))?;
    lock.try_lock_exclusive()?;
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA)?;
    verify_rows(&conn)?;
    let state = App {
        db: Arc::new(Mutex::new(Database { conn, _lock: lock })),
        slots: Arc::new(Semaphore::new(8)),
        origin,
        publisher,
    };
    Ok(Router::new()
        .route(
            "/api/v1/arkade-recovery-records",
            post(store).layer(DefaultBodyLimit::max(192 * 1024)),
        )
        .route(
            "/api/v1/arkade-recovery-records/fetch",
            post(fetch).layer(DefaultBodyLimit::max(4096)),
        )
        .with_state(state))
}

async fn store(
    State(app): State<App>,
    Json(req): Json<StoreRequest>,
) -> Result<impl IntoResponse, Error> {
    let permit = app
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::TOO_MANY_REQUESTS))?;
    let receipt = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        store_record(&app, &req, now()?)
    })
    .await
    .map_err(internal)??;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(receipt)))
}

pub fn validate_store(
    policy: &RecoveryPolicy,
    req: &StoreRequest,
    clock: u64,
) -> Result<Vec<u8>, Error> {
    fresh(req.timestamp, clock)?;
    let g = &req.grant;
    if g.origin != policy.origin
        || g.publisher != policy.publisher
        || g.max_records == 0
        || g.max_records > 16
        || g.max_bytes == 0
        || g.max_bytes > MAX_GRANT_BYTES
        || g.expires_at <= g.valid_from
        || g.expires_at - g.valid_from > 32 * 86400
        || req.ciphertext_bytes == 0
        || req.ciphertext_bytes > MAX_RECORD as u64
    {
        return Err(bad());
    }
    hex_bytes(&g.id, 32)?;
    hex_bytes(&g.scope, 32)?;
    verify(&g.owner, &grant_digest(g), &g.signature)?;
    verify(&g.publisher, &store_digest(req), &req.signature)?;
    let raw = B64.decode(&req.ciphertext).map_err(|_| bad())?;
    if raw.len() as u64 != req.ciphertext_bytes
        || B64.encode(&raw) != req.ciphertext
        || hex::encode(Sha256::digest(&raw)) != req.ciphertext_sha256
    {
        return Err(bad());
    }
    Ok(raw)
}

fn store_record(app: &App, req: &StoreRequest, clock: u64) -> Result<Receipt, Error> {
    let policy = RecoveryPolicy {
        origin: app.origin.clone(),
        publisher: app.publisher.clone(),
        max_records: 10_000,
        max_bytes: MAX_GLOBAL_BYTES,
    };
    let mut db = app.db.lock().map_err(internal)?;
    store_on_connection(&mut db.conn, &policy, req, clock, u64::MAX)
}

pub fn store_on_connection(
    connection: &mut Connection,
    policy: &RecoveryPolicy,
    req: &StoreRequest,
    clock: u64,
    aggregate_available_bytes: u64,
) -> Result<Receipt, Error> {
    let tx = connection.transaction().map_err(internal)?;
    let receipt = store_in_transaction(&tx, policy, req, clock, aggregate_available_bytes)?;
    tx.commit().map_err(internal)?;
    Ok(receipt)
}

pub fn store_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    policy: &RecoveryPolicy,
    req: &StoreRequest,
    clock: u64,
    aggregate_available_bytes: u64,
) -> Result<Receipt, Error> {
    let raw = validate_store(policy, req, clock)?;
    let g = &req.grant;
    let grant_hash = hex::encode(grant_digest(g));
    let prior: Option<String> = tx
        .query_row(
            "SELECT digest FROM recovery_grants WHERE owner=? AND grant_id=?",
            params![g.owner, g.id],
            |r| r.get(0),
        )
        .optional()
        .map_err(internal)?;
    if prior.as_ref().is_some_and(|value| value != &grant_hash) {
        return Err(Error(StatusCode::CONFLICT));
    }
    let existing: Option<(i64, Vec<u8>, String)> = tx
        .query_row(
            "SELECT id,ciphertext,grant_json FROM recovery_records WHERE owner=? AND grant_id=? AND hash=?",
            params![g.owner, g.id, req.ciphertext_sha256],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(internal)?;
    if let Some((id, stored_raw, stored_grant)) = existing {
        let stored_grant: Grant = serde_json::from_str(&stored_grant).map_err(internal)?;
        if prior.is_none() || stored_raw != raw || grant_digest(&stored_grant) != grant_digest(g) {
            return Err(internal("persisted recovery record does not match retry"));
        }
        verify(
            &stored_grant.owner,
            &grant_digest(&stored_grant),
            &stored_grant.signature,
        )
        .map_err(internal)?;
        return Ok(Receipt {
            id,
            ciphertext_sha256: req.ciphertext_sha256.clone(),
        });
    }
    if clock < g.valid_from || clock > g.expires_at {
        return Err(Error(StatusCode::FORBIDDEN));
    }
    let (count, bytes): (u64,u64) = tx.query_row("SELECT COUNT(*),COALESCE(SUM(length(ciphertext)),0) FROM recovery_records WHERE owner=? AND grant_id=?", params![g.owner,g.id], |r| Ok((r.get(0)?,r.get(1)?))).map_err(internal)?;
    let owner_bytes: i64 = tx
        .query_row(
            "SELECT COALESCE(SUM(length(ciphertext)),0) FROM recovery_records WHERE owner=?",
            [&g.owner],
            |r| r.get(0),
        )
        .map_err(internal)?;
    let (global_count, global_bytes): (u64, u64) = tx
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(ciphertext)),0) FROM recovery_records",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(internal)?;
    let length = i64::try_from(raw.len()).map_err(internal)?;
    let owner_count: u64 = tx
        .query_row(
            "SELECT COUNT(*) FROM recovery_records WHERE owner=?",
            [&g.owner],
            |r| r.get(0),
        )
        .map_err(internal)?;
    if count >= g.max_records
        || bytes + req.ciphertext_bytes > g.max_bytes
        || owner_bytes + length > MAX_OWNER_BYTES
        || owner_count >= 10_000
        || global_count >= policy.max_records
        || global_bytes + req.ciphertext_bytes > policy.max_bytes
        || req.ciphertext_bytes > aggregate_available_bytes
    {
        return Err(Error(StatusCode::INSUFFICIENT_STORAGE));
    }
    tx.execute(
        "INSERT OR IGNORE INTO recovery_grants VALUES(?,?,?)",
        params![g.owner, g.id, grant_hash],
    )
    .map_err(internal)?;
    tx.execute(
        "INSERT INTO recovery_records(owner,grant_id,hash,ciphertext,grant_json) VALUES(?,?,?,?,?)",
        params![
            g.owner,
            g.id,
            req.ciphertext_sha256,
            raw,
            serde_json::to_string(g).map_err(internal)?
        ],
    )
    .map_err(internal)?;
    let id = tx.last_insert_rowid();
    Ok(Receipt {
        id,
        ciphertext_sha256: req.ciphertext_sha256.clone(),
    })
}

async fn fetch(
    State(app): State<App>,
    Json(req): Json<FetchRequest>,
) -> Result<impl IntoResponse, Error> {
    let permit = app
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::TOO_MANY_REQUESTS))?;
    let page = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        fetch_records(&app, &req, now()?)
    })
    .await
    .map_err(internal)??;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(page)))
}

fn fetch_records(app: &App, req: &FetchRequest, clock: u64) -> Result<Page, Error> {
    let db = app.db.lock().map_err(internal)?;
    fetch_on_connection(&db.conn, req, clock)
}

pub fn validate_fetch(req: &FetchRequest, clock: u64) -> Result<(), Error> {
    fresh(req.timestamp, clock)?;
    verify(&req.owner, &fetch_digest(req), &req.signature)?;
    if req.after > i64::MAX as u64
        || req.snapshot > i64::MAX as u64
        || (req.snapshot == 0 && req.after != 0)
    {
        return Err(bad());
    }
    Ok(())
}

pub fn fetch_on_connection(
    connection: &Connection,
    req: &FetchRequest,
    clock: u64,
) -> Result<Page, Error> {
    validate_fetch(req, clock)?;
    let latest: u64 = connection
        .query_row(
            "SELECT COALESCE(MAX(id),0) FROM recovery_records WHERE owner=?",
            [&req.owner],
            |r| r.get(0),
        )
        .map_err(internal)?;
    let snapshot = if req.snapshot == 0 {
        latest
    } else {
        req.snapshot
    };
    if snapshot > latest || req.after > snapshot {
        return Err(Error(StatusCode::CONFLICT));
    }
    for anchor in [req.after, snapshot] {
        if anchor != 0 {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM recovery_records WHERE owner=? AND id=?)",
                    params![req.owner, anchor],
                    |r| r.get(0),
                )
                .map_err(internal)?;
            if !exists {
                return Err(Error(StatusCode::CONFLICT));
            }
        }
    }
    let mut query = connection.prepare("SELECT id,grant_json,ciphertext,hash FROM recovery_records WHERE owner=? AND id>? AND id<=? ORDER BY id LIMIT ?").map_err(internal)?;
    let rows = query
        .query_map(params![req.owner, req.after, snapshot, PAGE + 1], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(internal)?;
    let mut records = Vec::new();
    for row in rows {
        let (id, grant, raw, hash) = row.map_err(internal)?;
        records.push(Record {
            id,
            grant: serde_json::from_str(&grant).map_err(internal)?,
            ciphertext: B64.encode(raw),
            ciphertext_sha256: hash,
        });
    }
    let next_after = if records.len() > usize::try_from(PAGE).map_err(internal)? {
        records.pop();
        records.last().and_then(|r| u64::try_from(r.id).ok())
    } else {
        None
    };
    Ok(Page {
        records,
        snapshot,
        next_after,
    })
}

/// Verify retained records without applying request freshness or append expiry.
pub fn verify_rows(connection: &Connection) -> Result<(u64, u64, String), String> {
    fn checked(connection: &Connection) -> Result<(u64, u64, String), Error> {
        let mut query = connection.prepare("SELECT id,owner,grant_id,hash,length(ciphertext),ciphertext,grant_json FROM recovery_records ORDER BY id").map_err(internal)?;
        let mut rows = query.query([]).map_err(internal)?;
        let mut digest = Sha256::new();
        digest.update(b"bull-recovery-records-v1");
        let mut count = 0_u64;
        let mut bytes = 0_u64;
        while let Some(row) = rows.next().map_err(internal)? {
            let id: i64 = row.get(0).map_err(internal)?;
            let owner: String = row.get(1).map_err(internal)?;
            let grant_id: String = row.get(2).map_err(internal)?;
            let hash: String = row.get(3).map_err(internal)?;
            let length: u64 = row.get(4).map_err(internal)?;
            if id <= 0 || length == 0 || length > MAX_RECORD as u64 {
                return Err(bad());
            }
            let raw: Vec<u8> = row.get(5).map_err(internal)?;
            let grant_json: String = row.get(6).map_err(internal)?;
            let grant: Grant = serde_json::from_str(&grant_json).map_err(internal)?;
            let grant_hash = hex::encode(grant_digest(&grant));
            if owner != grant.owner
                || grant_id != grant.id
                || hash != hex::encode(Sha256::digest(&raw))
                || grant.max_records == 0
                || grant.max_records > 16
                || grant.max_bytes == 0
                || grant.max_bytes > MAX_GRANT_BYTES
                || grant.expires_at <= grant.valid_from
                || grant.expires_at - grant.valid_from > 32 * 86400
            {
                return Err(bad());
            }
            hex_bytes(&grant.id, 32)?;
            hex_bytes(&grant.scope, 32)?;
            key(&grant.publisher)?;
            verify(&owner, &grant_digest(&grant), &grant.signature)?;
            let stored: String = connection
                .query_row(
                    "SELECT digest FROM recovery_grants WHERE owner=? AND grant_id=?",
                    params![owner, grant_id],
                    |r| r.get(0),
                )
                .map_err(internal)?;
            if stored != grant_hash {
                return Err(bad());
            }
            digest.update(id.to_be_bytes());
            digest.update(hex_bytes(&owner, 32)?);
            digest.update(hex_bytes(&grant_id, 32)?);
            digest.update(hex_bytes(&grant_hash, 32)?);
            digest.update(hex_bytes(&hash, 32)?);
            count += 1;
            bytes = bytes.checked_add(length).ok_or_else(bad)?;
        }
        let invalid: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM recovery_grants g WHERE NOT EXISTS(SELECT 1 FROM recovery_records r WHERE r.owner=g.owner AND r.grant_id=g.grant_id)) OR EXISTS(SELECT 1 FROM recovery_records GROUP BY owner HAVING COUNT(*)>10000 OR SUM(length(ciphertext))>16777216) OR EXISTS(SELECT 1 FROM recovery_records GROUP BY owner,grant_id HAVING COUNT(*)>json_extract(grant_json,'$.max_records') OR SUM(length(ciphertext))>json_extract(grant_json,'$.max_bytes'))", [], |r| r.get(0)).map_err(internal)?;
        if invalid {
            return Err(bad());
        }
        Ok((count, bytes, hex::encode(digest.finalize())))
    }
    checked(connection).map_err(|_| "recovery record verification failed".to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SecretKey};

    fn pair(byte: u8) -> Keypair {
        Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array([byte; 32]).unwrap(),
        )
    }
    fn public(key: &Keypair) -> String {
        key.x_only_public_key().0.to_string()
    }
    fn sign(key: &Keypair, digest: &[u8; 32]) -> String {
        Secp256k1::new()
            .sign_schnorr_no_aux_rand(digest, key)
            .to_string()
    }
    fn fixture() -> (App, StoreRequest) {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let app = App {
            db: Arc::new(Mutex::new(Database {
                conn,
                _lock: std::fs::File::open("/dev/null").unwrap(),
            })),
            slots: Arc::new(Semaphore::new(8)),
            origin: "http://127.0.0.1:9000".into(),
            publisher: public(&pair(2)),
        };
        let mut grant = Grant {
            owner: public(&pair(1)),
            publisher: app.publisher.clone(),
            origin: app.origin.clone(),
            id: "11".repeat(32),
            scope: "22".repeat(32),
            valid_from: 90,
            expires_at: 110,
            max_records: 1,
            max_bytes: 1024,
            signature: String::new(),
        };
        grant.signature = sign(&pair(1), &grant_digest(&grant));
        let mut req = StoreRequest {
            grant,
            ciphertext: B64.encode(b"opaque"),
            ciphertext_sha256: hex::encode(Sha256::digest(b"opaque")),
            ciphertext_bytes: 6,
            timestamp: 100,
            signature: String::new(),
        };
        req.signature = sign(&pair(2), &store_digest(&req));
        (app, req)
    }
    fn fetch_request(owner: &Keypair) -> FetchRequest {
        let mut req = FetchRequest {
            owner: public(owner),
            after: 0,
            snapshot: 0,
            timestamp: 100,
            signature: String::new(),
        };
        req.signature = sign(owner, &fetch_digest(&req));
        req
    }
    fn check_shared_envelope(fixture: &serde_json::Value, grant: &Grant, store: &StoreRequest) {
        let envelope_bytes = B64.decode(&store.ciphertext).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&envelope_bytes)),
            fixture["digests"]["ciphertext"]
        );
        let envelope: serde_json::Value = serde_json::from_slice(&envelope_bytes).unwrap();
        assert_eq!(envelope, fixture["envelope"]);
        let event = &envelope["event"];
        let serialized = serde_json::to_vec(&serde_json::json!([
            0,
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"]
        ]))
        .unwrap();
        let event_digest: [u8; 32] = Sha256::digest(serialized).into();
        assert_eq!(hex::encode(event_digest), fixture["digests"]["event"]);
        verify(
            event["pubkey"].as_str().unwrap(),
            &event_digest,
            event["sig"].as_str().unwrap(),
        )
        .unwrap();
        let attestation = digest(&[
            DOMAIN,
            "sealed",
            &grant.owner,
            &hex::encode(grant_digest(grant)),
            event["id"].as_str().unwrap(),
        ]);
        assert_eq!(hex::encode(attestation), fixture["digests"]["attestation"]);
        verify(
            &grant.publisher,
            &attestation,
            envelope["publisher_signature"].as_str().unwrap(),
        )
        .unwrap();
        let plain = fixture["bundle_json"].as_str().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(plain.as_bytes())),
            fixture["digests"]["plaintext"]
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(plain).unwrap(),
            fixture["bundle"]
        );
    }

    #[test]
    fn shared_wire_conformance_vector() {
        let raw = include_bytes!("../tests/fixtures/recovery-wire-v1.json");
        assert_eq!(
            hex::encode(Sha256::digest(raw)),
            "4ce1053bb849e7bc0db7cd3702c1f623dcea5d60e45853ac1b5c4e0c224092c8"
        );
        let fixture: serde_json::Value = serde_json::from_slice(raw).unwrap();
        assert_eq!(fixture["domain"], DOMAIN);
        let grant: Grant = serde_json::from_value(fixture["grant"].clone()).unwrap();
        let store: StoreRequest = serde_json::from_value(fixture["store"].clone()).unwrap();
        let fetch: FetchRequest = serde_json::from_value(fixture["fetch"].clone()).unwrap();
        for (name, actual) in [
            ("grant", grant_digest(&grant)),
            ("store", store_digest(&store)),
            ("fetch", fetch_digest(&fetch)),
        ] {
            assert_eq!(fixture["digests"][name], hex::encode(actual));
        }
        assert_eq!(serde_json::to_value(&grant).unwrap(), fixture["grant"]);
        assert_eq!(serde_json::to_value(&store).unwrap(), fixture["store"]);
        assert_eq!(serde_json::to_value(&fetch).unwrap(), fixture["fetch"]);
        let encoding = &fixture["scope_encoding"];
        assert_eq!(
            hex::encode(digest(&[
                DOMAIN,
                "scope",
                encoding["message"].as_str().unwrap(),
                encoding["proof"].as_str().unwrap(),
                encoding["outputs_json"].as_str().unwrap()
            ])),
            encoding["digest"]
        );
        verify(&grant.owner, &grant_digest(&grant), &grant.signature).unwrap();
        verify(&grant.publisher, &store_digest(&store), &store.signature).unwrap();
        verify(&fetch.owner, &fetch_digest(&fetch), &fetch.signature).unwrap();
        let (mut app, _) = self::fixture();
        app.origin.clone_from(&grant.origin);
        app.publisher.clone_from(&grant.publisher);
        let receipt = store_record(&app, &store, 100).unwrap();
        assert_eq!(receipt.id, 1);
        let page = fetch_records(&app, &fetch, 100).unwrap();
        assert_eq!(page.snapshot, 1);
        assert!(page.next_after.is_none());
        assert_eq!(
            serde_json::to_value(&page.records[0]).unwrap(),
            fixture["record"]
        );
        check_shared_envelope(&fixture, &grant, &store);
        let mut changed = store.clone();
        changed.grant.max_records -= 1;
        assert_eq!(
            store_record(&app, &changed, 100).err().unwrap().0,
            StatusCode::UNAUTHORIZED
        );
        changed = store;
        changed.ciphertext_bytes += 1;
        assert_eq!(
            store_record(&app, &changed, 100).err().unwrap().0,
            StatusCode::UNAUTHORIZED
        );
        let mut changed = fetch;
        changed.after += 1;
        assert_eq!(
            fetch_records(&app, &changed, 100).err().unwrap().0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn exact_retry_survives_grant_expiry_but_new_append_does_not() {
        let (app, mut req) = fixture();
        let first = store_record(&app, &req, 100).unwrap();
        req.timestamp = 111;
        req.signature = sign(&pair(2), &store_digest(&req));
        assert_eq!(store_record(&app, &req, 111).unwrap().id, first.id);
        req.ciphertext = B64.encode(b"second");
        req.ciphertext_sha256 = hex::encode(Sha256::digest(b"second"));
        req.signature = sign(&pair(2), &store_digest(&req));
        assert_eq!(
            store_record(&app, &req, 111).err().unwrap().0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            fetch_records(&app, &fetch_request(&pair(1)), 111)
                .unwrap()
                .records
                .len(),
            1
        );
    }
    #[test]
    fn grant_quota_and_binding_are_persistent() {
        let (app, mut req) = fixture();
        store_record(&app, &req, 100).unwrap();
        req.ciphertext = B64.encode(b"second");
        req.ciphertext_sha256 = hex::encode(Sha256::digest(b"second"));
        req.signature = sign(&pair(2), &store_digest(&req));
        assert_eq!(
            store_record(&app, &req, 100).err().unwrap().0,
            StatusCode::INSUFFICIENT_STORAGE
        );
        req.grant.max_records = 2;
        req.grant.signature = sign(&pair(1), &grant_digest(&req.grant));
        req.signature = sign(&pair(2), &store_digest(&req));
        assert_eq!(
            store_record(&app, &req, 100).err().unwrap().0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            fetch_records(&app, &fetch_request(&pair(1)), 100)
                .unwrap()
                .records
                .len(),
            1
        );
    }
    #[test]
    fn user_authentication_is_required_and_namespace_isolated() {
        let (app, req) = fixture();
        store_record(&app, &req, 100).unwrap();
        let mut fetch = fetch_request(&pair(1));
        fetch.signature = sign(&pair(2), &fetch_digest(&fetch));
        assert_eq!(
            fetch_records(&app, &fetch, 100).err().unwrap().0,
            StatusCode::UNAUTHORIZED
        );
        assert!(
            fetch_records(&app, &fetch_request(&pair(3)), 100)
                .unwrap()
                .records
                .is_empty()
        );
        let mut fetch = fetch_request(&pair(1));
        fetch.after = 1;
        assert_eq!(
            fetch_records(&app, &fetch, 100).err().unwrap().0,
            StatusCode::UNAUTHORIZED
        );
        assert!(fetch_records(&app, &fetch_request(&pair(1)), 401).is_err());
    }
    #[test]
    fn payload_tampering_and_unknown_fields_are_rejected() {
        let (app, mut req) = fixture();
        req.ciphertext = B64.encode(b"broken");
        assert_eq!(
            store_record(&app, &req, 100).err().unwrap().0,
            StatusCode::BAD_REQUEST
        );
        let mut value = serde_json::to_value(fetch_request(&pair(1))).unwrap();
        value["token"] = serde_json::json!("not a credential");
        assert!(serde_json::from_value::<FetchRequest>(value).is_err());
    }
    fn resign(req: &mut StoreRequest) {
        req.grant.signature = sign(&pair(1), &grant_digest(&req.grant));
        req.signature = sign(&pair(2), &store_digest(req));
    }

    #[test]
    fn signed_invalid_grants_and_payload_boundaries() {
        for case in [
            "zero_records",
            "too_many_records",
            "zero_bytes",
            "too_many_bytes",
            "empty_window",
            "reversed_window",
            "long_window",
            "not_yet_valid",
            "expired",
            "wrong_origin",
            "wrong_publisher",
            "uppercase_id",
            "short_scope",
            "empty_payload",
            "oversized_payload",
            "wrong_length",
            "noncanonical_base64",
            "wrong_hash",
            "wrong_owner",
        ] {
            let (app, mut req) = fixture();
            match case {
                "zero_records" => req.grant.max_records = 0,
                "too_many_records" => req.grant.max_records = 17,
                "zero_bytes" => req.grant.max_bytes = 0,
                "too_many_bytes" => req.grant.max_bytes = MAX_GRANT_BYTES + 1,
                "empty_window" => req.grant.expires_at = req.grant.valid_from,
                "reversed_window" => req.grant.expires_at = 1,
                "long_window" => req.grant.expires_at = u64::MAX,
                "not_yet_valid" => req.grant.valid_from = 101,
                "expired" => req.grant.expires_at = 99,
                "wrong_origin" => req.grant.origin = "https://different.example".into(),
                "wrong_publisher" => req.grant.publisher = public(&pair(3)),
                "uppercase_id" => req.grant.id = "AA".repeat(32),
                "short_scope" => req.grant.scope = "00".into(),
                "empty_payload" => req.ciphertext_bytes = 0,
                "oversized_payload" => req.ciphertext_bytes = MAX_RECORD as u64 + 1,
                "wrong_length" => req.ciphertext_bytes = 5,
                "noncanonical_base64" => req.ciphertext.push('\n'),
                "wrong_hash" => req.ciphertext_sha256 = "00".repeat(32),
                "wrong_owner" => req.grant.owner = public(&pair(3)),
                _ => unreachable!(),
            }
            resign(&mut req);
            assert!(store_record(&app, &req, 100).is_err(), "{case}");
            assert!(
                fetch_records(&app, &fetch_request(&pair(1)), 100)
                    .unwrap()
                    .records
                    .is_empty(),
                "{case} mutated storage"
            );
        }
    }

    #[test]
    fn clock_and_grant_endpoints_are_inclusive() {
        for timestamp in [0, 100, 400] {
            let (app, mut req) = fixture();
            req.timestamp = timestamp;
            resign(&mut req);
            assert!(store_record(&app, &req, 100).is_ok());
        }
        let (app, mut req) = fixture();
        req.timestamp = 401;
        resign(&mut req);
        assert!(store_record(&app, &req, 100).is_err());
        for clock in [90, 110] {
            let (app, req) = fixture();
            assert!(store_record(&app, &req, clock).is_ok());
        }
    }

    #[test]
    fn signed_cursor_boundaries_and_rollback() {
        let (app, req) = fixture();
        let row = store_record(&app, &req, 100).unwrap();
        for (after, snapshot) in [
            (1, 0),
            (0, u64::try_from(row.id).unwrap() + 1),
            (u64::MAX, u64::MAX),
            (2, 1),
        ] {
            let mut fetch = fetch_request(&pair(1));
            fetch.after = after;
            fetch.snapshot = snapshot;
            fetch.signature = sign(&pair(1), &fetch_digest(&fetch));
            assert!(fetch_records(&app, &fetch, 100).is_err());
        }
        // A retained snapshot detects rollback beyond its tail, without claiming
        // that a fresh seed-only request can detect omitted history.
        app.db
            .lock()
            .unwrap()
            .conn
            .execute("DELETE FROM recovery_records", [])
            .unwrap();
        let mut fetch = fetch_request(&pair(1));
        fetch.snapshot = u64::try_from(row.id).unwrap();
        fetch.signature = sign(&pair(1), &fetch_digest(&fetch));
        assert_eq!(
            fetch_records(&app, &fetch, 100).err().unwrap().0,
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn pagination_rejects_missing_anchors_after_newer_records_arrive() {
        for missing in [8, 10] {
            let (app, mut req) = fixture();
            req.grant.max_records = 16;
            for i in 1..=10u8 {
                let raw = [i; 6];
                req.ciphertext = B64.encode(raw);
                req.ciphertext_sha256 = hex::encode(Sha256::digest(raw));
                resign(&mut req);
                store_record(&app, &req, 100).unwrap();
            }
            let first = fetch_records(&app, &fetch_request(&pair(1)), 100).unwrap();
            assert_eq!(first.next_after, Some(8));
            assert_eq!(first.snapshot, 10);
            let mut fetch = fetch_request(&pair(1));
            fetch.after = first.next_after.unwrap();
            fetch.snapshot = first.snapshot;
            fetch.signature = sign(&pair(1), &fetch_digest(&fetch));
            app.db
                .lock()
                .unwrap()
                .conn
                .execute("DELETE FROM recovery_records WHERE id=?", [missing])
                .unwrap();
            req.ciphertext = B64.encode([11u8; 6]);
            req.ciphertext_sha256 = hex::encode(Sha256::digest([11u8; 6]));
            resign(&mut req);
            assert_eq!(store_record(&app, &req, 100).unwrap().id, 11);
            assert_eq!(
                fetch_records(&app, &fetch, 100).err().unwrap().0,
                StatusCode::CONFLICT,
                "missing anchor {missing}"
            );
        }
    }

    #[test]
    fn exact_retry_never_acknowledges_damaged_persisted_data() {
        for damage in ["ciphertext", "grant_json", "grant_binding"] {
            let (app, req) = fixture();
            store_record(&app, &req, 100).unwrap();
            let sql = match damage {
                "ciphertext" => "UPDATE recovery_records SET ciphertext=x'00'",
                "grant_json" => "UPDATE recovery_records SET grant_json='{}'",
                "grant_binding" => "DELETE FROM recovery_grants",
                _ => unreachable!(),
            };
            app.db.lock().unwrap().conn.execute(sql, []).unwrap();
            assert_eq!(
                store_record(&app, &req, 100).err().unwrap().0,
                StatusCode::INTERNAL_SERVER_ERROR,
                "damaged {damage}"
            );
        }
    }

    #[test]
    fn exact_retry_accepts_equivalent_authorization_but_rejects_corrupt_grant() {
        let (app, mut req) = fixture();
        let receipt = store_record(&app, &req, 100).unwrap();
        req.grant.signature = Secp256k1::new()
            .sign_schnorr_with_aux_rand(&grant_digest(&req.grant), &pair(1), &[42; 32])
            .to_string();
        req.signature = sign(&pair(2), &store_digest(&req));
        assert_eq!(store_record(&app, &req, 100).unwrap().id, receipt.id);
        for changed_digest in [false, true] {
            let mut stored = req.grant.clone();
            if changed_digest {
                stored.scope = "33".repeat(32);
                stored.signature = sign(&pair(1), &grant_digest(&stored));
            } else {
                stored.signature = "00".repeat(64);
            }
            app.db
                .lock()
                .unwrap()
                .conn
                .execute(
                    "UPDATE recovery_records SET grant_json=?",
                    [serde_json::to_string(&stored).unwrap()],
                )
                .unwrap();
            assert_eq!(
                store_record(&app, &req, 100).err().unwrap().0,
                StatusCode::INTERNAL_SERVER_ERROR
            );
        }
    }

    #[test]
    fn retained_snapshot_excludes_later_appends_and_allows_completed_cursor() {
        let (app, mut req) = fixture();
        req.grant.max_records = 2;
        resign(&mut req);
        let receipt = store_record(&app, &req, 100).unwrap();
        let mut fetch = fetch_request(&pair(1));
        fetch.snapshot = u64::try_from(receipt.id).unwrap();
        fetch.signature = sign(&pair(1), &fetch_digest(&fetch));
        req.ciphertext = B64.encode(b"second");
        req.ciphertext_sha256 = hex::encode(Sha256::digest(b"second"));
        resign(&mut req);
        store_record(&app, &req, 100).unwrap();
        let page = fetch_records(&app, &fetch, 100).unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].id, receipt.id);
        assert_eq!(page.next_after, None);
        fetch.after = fetch.snapshot;
        fetch.signature = sign(&pair(1), &fetch_digest(&fetch));
        assert!(fetch_records(&app, &fetch, 100).unwrap().records.is_empty());
    }

    #[test]
    fn concurrent_exact_retries_preserve_receipt_and_consume_quota_once() {
        let (app, req) = fixture();
        let mut threads = Vec::new();
        for _ in 0..16 {
            let app = app.clone();
            let req = req.clone();
            threads.push(std::thread::spawn(move || {
                store_record(&app, &req, 100).unwrap().id
            }));
        }
        for thread in threads {
            assert_eq!(thread.join().unwrap(), 1);
        }
        let db = app.db.lock().unwrap();
        let counts: (u64, u64, u64) = db.conn.query_row(
            "SELECT COUNT(*), SUM(length(ciphertext)), (SELECT COUNT(*) FROM recovery_grants) FROM recovery_records",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!(counts, (1, 6, 1));
    }

    #[test]
    fn concurrent_uploads_cannot_exceed_grant_quota() {
        let (app, req) = fixture();
        let mut threads = Vec::new();
        for i in 0..16u8 {
            let app = app.clone();
            let mut req = req.clone();
            threads.push(std::thread::spawn(move || {
                let raw = [i; 6];
                req.ciphertext = B64.encode(raw);
                req.ciphertext_sha256 = hex::encode(Sha256::digest(raw));
                resign(&mut req);
                store_record(&app, &req, 100).is_ok()
            }));
        }
        let accepted = threads
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|v| *v)
            .count();
        assert_eq!(accepted, 1);
        assert_eq!(
            fetch_records(&app, &fetch_request(&pair(1)), 100)
                .unwrap()
                .records
                .len(),
            1
        );
    }

    #[test]
    fn byte_quota_is_exact_and_failures_leave_no_grant() {
        let (app, mut req) = fixture();
        req.grant.max_bytes = 5;
        resign(&mut req);
        assert_eq!(
            store_record(&app, &req, 100).err().unwrap().0,
            StatusCode::INSUFFICIENT_STORAGE
        );
        // The rejected request must not reserve the immutable grant ID.
        req.grant.max_bytes = 6;
        resign(&mut req);
        assert!(store_record(&app, &req, 100).is_ok());
    }
}
