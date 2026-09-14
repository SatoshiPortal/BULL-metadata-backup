use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use secp256k1::{Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

pub const VERSION: u8 = 1;
pub const AUTH_DOMAIN: &[u8] = b"bullbitcoin-wallet-backup-v1";
pub const ETAG_DOMAIN: &[u8] = b"bullbitcoin-wallet-backup-etag-v1";
pub const ABSOLUTE_MAX_CIPHERTEXT_BYTES: usize = 1024 * 1024;
pub const ABSOLUTE_MAX_STORE_BODY_BYTES: usize = 1536 * 1024;
pub const STORE_ENVELOPE_HEADROOM_BYTES: usize = 1024;
pub const SMALL_BODY_LIMIT_BYTES: usize = 8 * 1024;
pub const TIMESTAMP_WINDOW_SECS: u64 = 300;
pub const MIN_TOMBSTONE_RETENTION_SECS: u64 = 15 * 60;

pub const FETCH_ACTION: &str = "backup-fetch";
pub const STORE_ACTION: &str = "backup-store";
pub const DELETE_ACTION: &str = "backup-delete";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupStream {
    WalletBackup,
}

impl BackupStream {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletBackup => "wallet_backup",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchRequest {
    pub version: u8,
    pub stream: BackupStream,
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRequest {
    pub version: u8,
    pub stream: BackupStream,
    pub npub: String,
    pub generation: u64,
    pub expected_etag: RequiredNullableString,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
    pub ciphertext_bytes: u64,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Debug)]
pub struct RequiredNullableString(Option<String>);

impl RequiredNullableString {
    pub fn as_deref(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

impl<'de> Deserialize<'de> for RequiredNullableString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = RequiredNullableString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string or null")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(RequiredNullableString(None))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(RequiredNullableString(None))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(RequiredNullableString(Some(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(RequiredNullableString(Some(value)))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteRequest {
    pub version: u8,
    pub stream: BackupStream,
    pub npub: String,
    pub generation: u64,
    pub expected_etag: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Serialize)]
pub struct FetchResponse {
    pub version: u8,
    pub found: bool,
    pub generation: u64,
    pub etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
}

#[derive(Serialize)]
pub struct MutationResponse {
    pub version: u8,
    pub generation: u64,
    pub etag: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitKind {
    Npub,
    Overflow,
    Saturation,
    Admission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    InvalidRequest(&'static str),
    Authentication,
    HeadConflict,
    BlobTooLarge,
    RateLimited {
        retry_after_secs: u64,
        kind: RateLimitKind,
    },
    Capacity,
    Internal,
}

impl ApiError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "BackupInvalidRequest",
            Self::Authentication => "BackupAuthError",
            Self::HeadConflict => "BackupHeadConflict",
            Self::BlobTooLarge => "BackupBlobTooLarge",
            Self::RateLimited { .. } => "RateLimited",
            Self::Capacity => "BackupCapacityExceeded",
            Self::Internal => "InternalError",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::Authentication => StatusCode::UNAUTHORIZED,
            Self::HeadConflict => StatusCode::CONFLICT,
            Self::BlobTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Capacity => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::InvalidRequest(reason) => reason,
            Self::Authentication => "Wallet backup signature did not verify.",
            Self::HeadConflict => "Wallet backup changed. Fetch the current head and retry.",
            Self::BlobTooLarge => "Wallet backup exceeds the maximum object size.",
            Self::RateLimited { .. } => "Wallet backup request rate limit exceeded. Retry later.",
            Self::Capacity => "Wallet backup storage is temporarily at capacity.",
            Self::Internal => "Internal server error.",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let retry_after = match self {
            Self::RateLimited {
                retry_after_secs, ..
            } => Some(retry_after_secs),
            _ => None,
        };
        error_response(self.status(), self.code(), self.reason(), retry_after)
    }
}

fn error_response(
    status: StatusCode,
    code: &'static str,
    reason: &'static str,
    retry_after_secs: Option<u64>,
) -> Response {
    let mut response = private_no_store(
        (
            status,
            Json(json!({
                "status": "ERROR",
                "code": code,
                "reason": reason,
            })),
        )
            .into_response(),
    );
    if let Some(seconds) = retry_after_secs
        && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
    {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

pub fn private_no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

pub fn validate_version(version: u8) -> Result<(), ApiError> {
    if version == VERSION {
        Ok(())
    } else {
        Err(ApiError::InvalidRequest(
            "Unsupported wallet backup protocol version.",
        ))
    }
}

/// Canonical lowercase fixed-width hexadecimal only; every protocol hex field
/// on both resources decodes through this one function.
fn decode_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}

pub fn decode_canonical_hex<const N: usize>(
    value: &str,
    reason: &'static str,
) -> Result<[u8; N], ApiError> {
    decode_hex_array(value).ok_or(ApiError::InvalidRequest(reason))
}

pub fn validate_generation(generation: u64) -> Result<i64, ApiError> {
    if generation == 0 {
        return Err(ApiError::InvalidRequest(
            "Wallet backup generation must be positive.",
        ));
    }
    i64::try_from(generation)
        .map_err(|_| ApiError::InvalidRequest("Wallet backup generation is out of range."))
}

#[allow(clippy::too_many_arguments)]
pub fn build_signing_message(
    action: &str,
    stream: BackupStream,
    npub: &str,
    generation: u64,
    expected_etag: Option<&str>,
    ciphertext_sha256: Option<&str>,
    ciphertext_bytes: u64,
    timestamp: u64,
) -> Vec<u8> {
    let generation = generation.to_string();
    let ciphertext_bytes = ciphertext_bytes.to_string();
    let timestamp = timestamp.to_string();
    let fields = [
        action,
        stream.as_str(),
        npub,
        generation.as_str(),
        expected_etag.unwrap_or(""),
        ciphertext_sha256.unwrap_or(""),
        ciphertext_bytes.as_str(),
        timestamp.as_str(),
    ];
    let capacity = AUTH_DOMAIN.len()
        + fields
            .iter()
            .map(|field| field.len().saturating_add(1))
            .sum::<usize>();
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(AUTH_DOMAIN);
    for field in fields {
        message.push(0);
        message.extend_from_slice(field.as_bytes());
    }
    message
}

pub fn compute_etag(
    stream: BackupStream,
    npub: &str,
    generation: u64,
    ciphertext_sha256: Option<&str>,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(ETAG_DOMAIN);
    bytes.push(0);
    bytes.extend_from_slice(stream.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(npub.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(generation.to_string().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(ciphertext_sha256.unwrap_or("").as_bytes());
    Sha256::digest(bytes).into()
}

#[allow(clippy::too_many_arguments)]
pub fn verify_request_signature(
    action: &str,
    stream: BackupStream,
    npub: &str,
    generation: u64,
    expected_etag: Option<&str>,
    ciphertext_sha256: Option<&str>,
    ciphertext_bytes: u64,
    timestamp: u64,
    signature: &str,
    now: u64,
) -> Result<(), ApiError> {
    let signature_bytes =
        decode_canonical_hex::<64>(signature, "Wallet backup signature is invalid.")?;
    if now.abs_diff(timestamp) > TIMESTAMP_WINDOW_SECS {
        return Err(ApiError::Authentication);
    }
    let public_key = XOnlyPublicKey::from_str(npub).map_err(|_| ApiError::Authentication)?;
    let signature = secp256k1::schnorr::Signature::from_byte_array(signature_bytes);
    let digest: [u8; 32] = Sha256::digest(build_signing_message(
        action,
        stream,
        npub,
        generation,
        expected_etag,
        ciphertext_sha256,
        ciphertext_bytes,
        timestamp,
    ))
    .into();
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &digest, &public_key)
        .map_err(|_| ApiError::Authentication)
}

pub fn unix_time() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApiError::Internal)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiphertextError {
    NotBase64,
    NotCanonical,
    TooLarge,
}

pub fn decode_base64_ciphertext(value: &str, max_bytes: usize) -> Result<Vec<u8>, CiphertextError> {
    let decoded = BASE64_STANDARD
        .decode(value)
        .map_err(|_| CiphertextError::NotBase64)?;
    if decoded.len() > max_bytes {
        return Err(CiphertextError::TooLarge);
    }
    if BASE64_STANDARD.encode(&decoded) != value {
        return Err(CiphertextError::NotCanonical);
    }
    Ok(decoded)
}

pub fn decode_ciphertext(value: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    decode_base64_ciphertext(value, max_bytes).map_err(|error| match error {
        CiphertextError::NotBase64 => {
            ApiError::InvalidRequest("Wallet backup ciphertext is not base64.")
        }
        CiphertextError::NotCanonical => {
            ApiError::InvalidRequest("Wallet backup ciphertext base64 is not canonical.")
        }
        CiphertextError::TooLarge => ApiError::BlobTooLarge,
    })
}

// Private descriptor records. This section is additive: wallet backup v1
// above is frozen and shares no domain, action, table, or error code with it.

pub const DESCRIPTOR_VERSION: u8 = 1;
pub const DESCRIPTOR_AUTH_DOMAIN: &[u8] = b"bullbitcoin-descriptor-backup-v1";
pub const DESCRIPTOR_STORE_ACTION: &str = "descriptor-store";
pub const ABSOLUTE_MAX_DESCRIPTOR_CIPHERTEXT_BYTES: usize = 64 * 1024;
pub const ABSOLUTE_MAX_DESCRIPTOR_STORE_BODY_BYTES: usize = 96 * 1024;
pub const DESCRIPTOR_STORE_ENVELOPE_HEADROOM_BYTES: usize = 2 * 1024;
pub const MIN_DESCRIPTOR_LOOKUP_TOKENS: usize = 1;
pub const MAX_DESCRIPTOR_LOOKUP_TOKENS: usize = 16;
pub const DESCRIPTOR_LOOKUP_TOKEN_BYTES: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreDescriptorRequest {
    pub version: u8,
    pub npub: String,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
    pub ciphertext_bytes: u64,
    pub lookup_tokens: Vec<String>,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorLookupRequest {
    pub version: u8,
    pub lookup_tokens: Vec<String>,
    /// Where to resume, taken verbatim from a previous response. Absent asks
    /// for the newest page.
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Serialize)]
pub struct StoreDescriptorResponse {
    pub version: u8,
    pub ciphertext_sha256: String,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct DescriptorRecordView {
    pub ciphertext: String,
    pub ciphertext_sha256: String,
    pub ciphertext_bytes: u64,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct DescriptorLookupResponse {
    pub version: u8,
    /// Present when matching records remain after this page. Sending it back
    /// unchanged returns the next page; absent means the history is complete.
    pub next_cursor: Option<String>,
    pub records: Vec<DescriptorRecordView>,
}

/// The wire form of a lookup position: one version byte, the 8-byte creation
/// time and the record's 16-byte id, base64 as every other opaque field is.
///
/// It is meaningless to a client, which must return it verbatim. A forged one
/// only names a position inside records the token already opens, so nothing is
/// authenticated here and no server secret exists to authenticate it with.
pub const DESCRIPTOR_CURSOR_VERSION: u8 = 1;
pub const DESCRIPTOR_CURSOR_BYTES: usize = 25;

pub fn encode_descriptor_cursor(created_at: i64, record_id: [u8; 16]) -> String {
    let mut bytes = Vec::with_capacity(DESCRIPTOR_CURSOR_BYTES);
    bytes.push(DESCRIPTOR_CURSOR_VERSION);
    bytes.extend_from_slice(&created_at.to_be_bytes());
    bytes.extend_from_slice(&record_id);
    BASE64_STANDARD.encode(bytes)
}

pub fn decode_descriptor_cursor(value: &str) -> Result<(i64, [u8; 16]), DescriptorApiError> {
    let invalid = DescriptorApiError::InvalidRequest("Descriptor lookup cursor is not valid.");
    let decoded = BASE64_STANDARD.decode(value).map_err(|_| invalid)?;
    if decoded.len() != DESCRIPTOR_CURSOR_BYTES
        || decoded[0] != DESCRIPTOR_CURSOR_VERSION
        || BASE64_STANDARD.encode(&decoded) != value
    {
        return Err(invalid);
    }
    let created_at = i64::from_be_bytes(decoded[1..9].try_into().map_err(|_| invalid)?);
    let record_id: [u8; 16] = decoded[9..].try_into().map_err(|_| invalid)?;
    if created_at < 0 {
        return Err(invalid);
    }
    Ok((created_at, record_id))
}

/// Descriptor-record errors. Separate from [`ApiError`] so that the frozen
/// wallet backup v1 status, code, and reason table cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorApiError {
    InvalidRequest(&'static str),
    Authentication,
    RecordConflict,
    PublisherQuota,
    BlobTooLarge,
    RateLimited {
        retry_after_secs: u64,
        kind: RateLimitKind,
    },
    Capacity,
    Internal,
}

impl DescriptorApiError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "DescriptorInvalidRequest",
            Self::Authentication => "DescriptorAuthError",
            Self::RecordConflict => "DescriptorRecordConflict",
            Self::PublisherQuota => "DescriptorPublisherQuotaExceeded",
            Self::BlobTooLarge => "DescriptorBlobTooLarge",
            Self::RateLimited { .. } => "DescriptorRateLimited",
            Self::Capacity => "DescriptorCapacityExceeded",
            Self::Internal => "InternalError",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::Authentication => StatusCode::UNAUTHORIZED,
            Self::RecordConflict => StatusCode::CONFLICT,
            Self::PublisherQuota => StatusCode::FORBIDDEN,
            Self::BlobTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Capacity => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::InvalidRequest(reason) => reason,
            Self::Authentication => "Descriptor backup signature did not verify.",
            Self::RecordConflict => {
                "Descriptor record already exists with different content or lookup tokens."
            }
            Self::PublisherQuota => "Descriptor backup publisher record limit reached.",
            Self::BlobTooLarge => "Descriptor backup exceeds the maximum object size.",
            Self::RateLimited { .. } => {
                "Descriptor backup request rate limit exceeded. Retry later."
            }
            Self::Capacity => "Descriptor backup storage is temporarily at capacity.",
            Self::Internal => "Internal server error.",
        }
    }
}

impl IntoResponse for DescriptorApiError {
    fn into_response(self) -> Response {
        let retry_after = match self {
            Self::RateLimited {
                retry_after_secs, ..
            } => Some(retry_after_secs),
            _ => None,
        };
        error_response(self.status(), self.code(), self.reason(), retry_after)
    }
}

pub fn validate_descriptor_version(version: u8) -> Result<(), DescriptorApiError> {
    if version == DESCRIPTOR_VERSION {
        Ok(())
    } else {
        Err(DescriptorApiError::InvalidRequest(
            "Unsupported descriptor backup protocol version.",
        ))
    }
}

pub fn decode_descriptor_hex<const N: usize>(
    value: &str,
    reason: &'static str,
) -> Result<[u8; N], DescriptorApiError> {
    decode_hex_array(value).ok_or(DescriptorApiError::InvalidRequest(reason))
}

/// Accepts only the canonical lookup-token set: 1..=16 lowercase 32-byte hex
/// tokens in strictly ascending byte order, which is both sorted and
/// duplicate-free. The signed message covers this exact sequence, so the
/// server never reorders a client's tokens on its behalf.
pub fn canonical_lookup_tokens(
    values: &[String],
) -> Result<Vec<[u8; DESCRIPTOR_LOOKUP_TOKEN_BYTES]>, DescriptorApiError> {
    if values.len() < MIN_DESCRIPTOR_LOOKUP_TOKENS || values.len() > MAX_DESCRIPTOR_LOOKUP_TOKENS {
        return Err(DescriptorApiError::InvalidRequest(
            "Descriptor lookup token count must be between 1 and 16.",
        ));
    }
    let mut tokens = Vec::with_capacity(values.len());
    for value in values {
        let token = decode_descriptor_hex::<DESCRIPTOR_LOOKUP_TOKEN_BYTES>(
            value,
            "Descriptor lookup token must be 64 lowercase hexadecimal characters.",
        )?;
        if tokens.last().is_some_and(|previous| *previous >= token) {
            return Err(DescriptorApiError::InvalidRequest(
                "Descriptor lookup tokens must be sorted ascending without duplicates.",
            ));
        }
        tokens.push(token);
    }
    Ok(tokens)
}

pub fn build_descriptor_signing_message(
    action: &str,
    npub: &str,
    ciphertext_sha256: &str,
    ciphertext_bytes: u64,
    lookup_tokens: &[String],
    timestamp: u64,
) -> Vec<u8> {
    let ciphertext_bytes = ciphertext_bytes.to_string();
    let token_count = lookup_tokens.len().to_string();
    let timestamp = timestamp.to_string();
    let leading = [
        action,
        npub,
        ciphertext_sha256,
        ciphertext_bytes.as_str(),
        token_count.as_str(),
    ];
    let capacity = DESCRIPTOR_AUTH_DOMAIN.len()
        + leading
            .iter()
            .map(|field| field.len().saturating_add(1))
            .sum::<usize>()
        + lookup_tokens
            .iter()
            .map(|token| token.len().saturating_add(1))
            .sum::<usize>()
        + timestamp.len().saturating_add(1);
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(DESCRIPTOR_AUTH_DOMAIN);
    for field in leading {
        message.push(0);
        message.extend_from_slice(field.as_bytes());
    }
    for token in lookup_tokens {
        message.push(0);
        message.extend_from_slice(token.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(timestamp.as_bytes());
    message
}

pub fn verify_descriptor_signature(
    npub: &str,
    ciphertext_sha256: &str,
    ciphertext_bytes: u64,
    lookup_tokens: &[String],
    timestamp: u64,
    signature: &str,
    now: u64,
) -> Result<(), DescriptorApiError> {
    let signature_bytes =
        decode_descriptor_hex::<64>(signature, "Descriptor backup signature is invalid.")?;
    if now.abs_diff(timestamp) > TIMESTAMP_WINDOW_SECS {
        return Err(DescriptorApiError::Authentication);
    }
    let public_key =
        XOnlyPublicKey::from_str(npub).map_err(|_| DescriptorApiError::Authentication)?;
    let signature = secp256k1::schnorr::Signature::from_byte_array(signature_bytes);
    let digest: [u8; 32] = Sha256::digest(build_descriptor_signing_message(
        DESCRIPTOR_STORE_ACTION,
        npub,
        ciphertext_sha256,
        ciphertext_bytes,
        lookup_tokens,
        timestamp,
    ))
    .into();
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &digest, &public_key)
        .map_err(|_| DescriptorApiError::Authentication)
}

pub fn decode_descriptor_ciphertext(
    value: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, DescriptorApiError> {
    decode_base64_ciphertext(value, max_bytes).map_err(|error| match error {
        CiphertextError::NotBase64 => {
            DescriptorApiError::InvalidRequest("Descriptor backup ciphertext is not base64.")
        }
        CiphertextError::NotCanonical => DescriptorApiError::InvalidRequest(
            "Descriptor backup ciphertext base64 is not canonical.",
        ),
        CiphertextError::TooLarge => DescriptorApiError::BlobTooLarge,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NPUB: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const HASH: &str = "ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc";

    #[derive(Deserialize)]
    struct Fixture {
        npub: String,
        protocol: String,
        tamper_cases: Vec<TamperCase>,
        vectors: Vec<Vector>,
    }

    #[derive(Deserialize)]
    struct TamperCase {
        expected_code: String,
        field: String,
    }

    #[derive(Deserialize)]
    struct Vector {
        action: String,
        ciphertext: Option<String>,
        ciphertext_bytes: u64,
        ciphertext_sha256: Option<String>,
        expected_etag: Option<String>,
        generation: u64,
        result_etag: Option<String>,
        signature: String,
        signed_message_hex: String,
        signed_message_sha256: String,
        timestamp: u64,
    }

    #[test]
    fn signing_message_format() {
        let message = build_signing_message(
            STORE_ACTION,
            BackupStream::WalletBackup,
            NPUB,
            1,
            None,
            Some(HASH),
            4,
            1_700_000_000,
        );
        let expected = concat!(
            "bullbitcoin-wallet-backup-v1\0backup-store\0wallet_backup\0",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\0",
            "1\0\0ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc\0",
            "4\01700000000"
        );
        assert_eq!(message, expected.as_bytes());
    }

    #[test]
    fn etag_derivation() {
        assert_eq!(
            hex::encode(compute_etag(
                BackupStream::WalletBackup,
                NPUB,
                1,
                Some(HASH)
            )),
            "f2f8423662b6f766c0f95e57e78e6a969c73a1432d5f622d19acc2fce36112ad"
        );
    }

    #[test]
    fn timestamp_boundary_is_inclusive() {
        assert_eq!(1_000_u64.abs_diff(700), TIMESTAMP_WINDOW_SECS);
        assert!(1_000_u64.abs_diff(699) > TIMESTAMP_WINDOW_SECS);
    }

    #[test]
    fn nullable_etag_must_be_present() {
        let body = serde_json::json!({
            "version": 1,
            "stream": "wallet_backup",
            "npub": NPUB,
            "generation": 1,
            "ciphertext": "",
            "ciphertext_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ciphertext_bytes": 0,
            "timestamp": 1,
            "signature": "00".repeat(64)
        });
        assert!(serde_json::from_value::<StoreRequest>(body).is_err());
    }

    #[test]
    fn ciphertext_boundary_and_canonical_encoding_are_enforced() -> Result<(), String> {
        let at_limit = BASE64_STANDARD.encode(vec![0_u8; ABSOLUTE_MAX_CIPHERTEXT_BYTES]);
        let decoded = decode_ciphertext(&at_limit, ABSOLUTE_MAX_CIPHERTEXT_BYTES)
            .map_err(|_| "ciphertext at the limit was rejected".to_owned())?;
        assert_eq!(decoded.len(), ABSOLUTE_MAX_CIPHERTEXT_BYTES);

        let over_limit = BASE64_STANDARD.encode(vec![0_u8; ABSOLUTE_MAX_CIPHERTEXT_BYTES + 1]);
        assert_eq!(
            decode_ciphertext(&over_limit, ABSOLUTE_MAX_CIPHERTEXT_BYTES),
            Err(ApiError::BlobTooLarge)
        );
        assert!(decode_ciphertext("AAECAw", ABSOLUTE_MAX_CIPHERTEXT_BYTES).is_err());
        Ok(())
    }

    #[test]
    fn protocol_vectors_match() -> Result<(), String> {
        let fixture_bytes = include_bytes!("../tests/fixtures/wallet-backup-v1.json");
        assert_eq!(
            hex::encode(Sha256::digest(fixture_bytes)),
            "84b64d530c407c28df32bd3ef659842152784874595f28ebaaed250227404da1"
        );
        let fixture: Fixture = serde_json::from_slice(fixture_bytes)
            .map_err(|_| "invalid protocol fixture".to_owned())?;
        assert_eq!(fixture.protocol, "bullbitcoin-wallet-backup-v1");
        assert_eq!(fixture.vectors.len(), 7);
        assert_eq!(fixture.tamper_cases.len(), 8);
        assert_eq!(
            fixture
                .tamper_cases
                .iter()
                .map(|case| (case.field.as_str(), case.expected_code.as_str()))
                .collect::<Vec<_>>(),
            [
                ("action", "BackupAuthError"),
                ("stream", "BackupInvalidRequest"),
                ("generation", "BackupAuthError"),
                ("expected_etag", "BackupAuthError"),
                ("ciphertext_sha256", "BackupInvalidRequest"),
                ("ciphertext_bytes", "BackupInvalidRequest"),
                ("timestamp", "BackupAuthError"),
                ("signature", "BackupAuthError"),
            ]
        );
        for vector in fixture.vectors {
            let message = build_signing_message(
                &vector.action,
                BackupStream::WalletBackup,
                &fixture.npub,
                vector.generation,
                vector.expected_etag.as_deref(),
                vector.ciphertext_sha256.as_deref(),
                vector.ciphertext_bytes,
                vector.timestamp,
            );
            assert_eq!(hex::encode(&message), vector.signed_message_hex);
            assert_eq!(
                hex::encode(Sha256::digest(&message)),
                vector.signed_message_sha256
            );
            verify_request_signature(
                &vector.action,
                BackupStream::WalletBackup,
                &fixture.npub,
                vector.generation,
                vector.expected_etag.as_deref(),
                vector.ciphertext_sha256.as_deref(),
                vector.ciphertext_bytes,
                vector.timestamp,
                &vector.signature,
                vector.timestamp,
            )
            .map_err(|_| "fixture signature did not verify".to_owned())?;
            if let Some(expected) = vector.result_etag {
                assert_eq!(
                    hex::encode(compute_etag(
                        BackupStream::WalletBackup,
                        &fixture.npub,
                        vector.generation,
                        vector.ciphertext_sha256.as_deref()
                    )),
                    expected
                );
            }
            if let Some(ciphertext) = vector.ciphertext {
                let decoded = decode_ciphertext(&ciphertext, ABSOLUTE_MAX_CIPHERTEXT_BYTES)
                    .map_err(|_| "fixture ciphertext did not decode".to_owned())?;
                let expected_hash = vector
                    .ciphertext_sha256
                    .as_deref()
                    .ok_or_else(|| "fixture ciphertext hash is missing".to_owned())?;
                assert_eq!(
                    u64::try_from(decoded.len())
                        .map_err(|_| "fixture length overflow".to_owned())?,
                    vector.ciphertext_bytes
                );
                assert_eq!(hex::encode(Sha256::digest(decoded)), expected_hash);
            }
        }
        Ok(())
    }

    #[derive(Deserialize)]
    struct DescriptorFixture {
        action: String,
        ciphertext: String,
        ciphertext_bytes: u64,
        ciphertext_sha256: String,
        lookup_tokens: Vec<String>,
        protocol: String,
        tamper_cases: Vec<TamperCase>,
        timestamp: u64,
        vectors: Vec<DescriptorVector>,
        version: u8,
    }

    #[derive(Deserialize)]
    struct DescriptorVector {
        npub: String,
        signature: String,
        signed_message_hex: String,
        signed_message_sha256: String,
    }

    const DESCRIPTOR_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/descriptor-backup-v1.json");

    fn descriptor_fixture() -> Result<DescriptorFixture, String> {
        serde_json::from_slice(DESCRIPTOR_FIXTURE)
            .map_err(|_| "invalid descriptor fixture".to_owned())
    }

    #[test]
    fn descriptor_signing_message_format() {
        let tokens = ["11".repeat(32), "22".repeat(32)];
        let message = build_descriptor_signing_message(
            DESCRIPTOR_STORE_ACTION,
            NPUB,
            HASH,
            4,
            &tokens,
            1_700_000_000,
        );
        let expected = format!(
            "bullbitcoin-descriptor-backup-v1\0descriptor-store\0{NPUB}\0{HASH}\04\02\0{}\0{}\01700000000",
            tokens[0], tokens[1]
        );
        assert_eq!(message, expected.as_bytes());
    }

    #[test]
    fn descriptor_signing_domain_and_action_are_distinct_from_wallet_backup() {
        assert_ne!(DESCRIPTOR_AUTH_DOMAIN, AUTH_DOMAIN);
        for action in [FETCH_ACTION, STORE_ACTION, DELETE_ACTION] {
            assert_ne!(DESCRIPTOR_STORE_ACTION, action);
        }
        let descriptor = build_descriptor_signing_message(
            DESCRIPTOR_STORE_ACTION,
            NPUB,
            HASH,
            0,
            std::slice::from_ref(&"33".repeat(32)),
            1,
        );
        assert!(!descriptor.starts_with(AUTH_DOMAIN));
    }

    #[test]
    fn descriptor_error_codes_never_collide_with_wallet_backup_v1() {
        let wallet = [
            ApiError::InvalidRequest("test").code(),
            ApiError::Authentication.code(),
            ApiError::HeadConflict.code(),
            ApiError::BlobTooLarge.code(),
            ApiError::RateLimited {
                retry_after_secs: 1,
                kind: RateLimitKind::Npub,
            }
            .code(),
            ApiError::Capacity.code(),
        ];
        let descriptor = [
            DescriptorApiError::InvalidRequest("test").code(),
            DescriptorApiError::Authentication.code(),
            DescriptorApiError::RecordConflict.code(),
            DescriptorApiError::PublisherQuota.code(),
            DescriptorApiError::BlobTooLarge.code(),
            DescriptorApiError::RateLimited {
                retry_after_secs: 1,
                kind: RateLimitKind::Npub,
            }
            .code(),
            DescriptorApiError::Capacity.code(),
        ];
        for code in descriptor {
            assert!(!wallet.contains(&code), "{code}");
        }
        // The generic internal failure is deliberately shared.
        assert_eq!(
            DescriptorApiError::Internal.code(),
            ApiError::Internal.code()
        );
        assert_eq!(
            DescriptorApiError::Internal.reason(),
            ApiError::Internal.reason()
        );
    }

    #[test]
    fn descriptor_lookup_tokens_must_be_canonical() {
        let low = "11".repeat(32);
        let high = "22".repeat(32);
        assert!(canonical_lookup_tokens(&[]).is_err());
        assert!(canonical_lookup_tokens(std::slice::from_ref(&low)).is_ok());
        assert!(canonical_lookup_tokens(&[low.clone(), high.clone()]).is_ok());
        assert_eq!(
            canonical_lookup_tokens(&[high.clone(), low.clone()]),
            Err(DescriptorApiError::InvalidRequest(
                "Descriptor lookup tokens must be sorted ascending without duplicates."
            ))
        );
        assert_eq!(
            canonical_lookup_tokens(&[low.clone(), low.clone()]),
            Err(DescriptorApiError::InvalidRequest(
                "Descriptor lookup tokens must be sorted ascending without duplicates."
            ))
        );
        assert!(canonical_lookup_tokens(&["AA".repeat(32)]).is_err());
        assert!(canonical_lookup_tokens(&["11".repeat(31)]).is_err());
        let too_many = (0..=MAX_DESCRIPTOR_LOOKUP_TOKENS)
            .map(|index| {
                let mut token = [0_u8; DESCRIPTOR_LOOKUP_TOKEN_BYTES];
                token[0] = u8::try_from(index).unwrap_or(u8::MAX);
                hex::encode(token)
            })
            .collect::<Vec<_>>();
        assert_eq!(too_many.len(), MAX_DESCRIPTOR_LOOKUP_TOKENS + 1);
        assert!(canonical_lookup_tokens(&too_many).is_err());
        assert!(canonical_lookup_tokens(&too_many[..MAX_DESCRIPTOR_LOOKUP_TOKENS]).is_ok());
    }

    #[test]
    fn descriptor_ciphertext_boundary_and_canonical_encoding_are_enforced() -> Result<(), String> {
        let at_limit = BASE64_STANDARD.encode(vec![0_u8; ABSOLUTE_MAX_DESCRIPTOR_CIPHERTEXT_BYTES]);
        let decoded =
            decode_descriptor_ciphertext(&at_limit, ABSOLUTE_MAX_DESCRIPTOR_CIPHERTEXT_BYTES)
                .map_err(|_| "descriptor ciphertext at the limit was rejected".to_owned())?;
        assert_eq!(decoded.len(), ABSOLUTE_MAX_DESCRIPTOR_CIPHERTEXT_BYTES);
        let over_limit =
            BASE64_STANDARD.encode(vec![0_u8; ABSOLUTE_MAX_DESCRIPTOR_CIPHERTEXT_BYTES + 1]);
        assert_eq!(
            decode_descriptor_ciphertext(&over_limit, ABSOLUTE_MAX_DESCRIPTOR_CIPHERTEXT_BYTES),
            Err(DescriptorApiError::BlobTooLarge)
        );
        assert!(
            decode_descriptor_ciphertext("AAECAw", ABSOLUTE_MAX_DESCRIPTOR_CIPHERTEXT_BYTES)
                .is_err()
        );
        let encoded_limit = ABSOLUTE_MAX_DESCRIPTOR_CIPHERTEXT_BYTES
            .div_ceil(3)
            .saturating_mul(4);
        assert!(
            encoded_limit + DESCRIPTOR_STORE_ENVELOPE_HEADROOM_BYTES
                <= ABSOLUTE_MAX_DESCRIPTOR_STORE_BODY_BYTES
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn descriptor_protocol_vectors_match() -> Result<(), String> {
        assert_eq!(
            hex::encode(Sha256::digest(DESCRIPTOR_FIXTURE)),
            "ebb1afa8a93a8b9a539138df101327e1eae9a02be1585dda25301d835714a24b"
        );
        let fixture = descriptor_fixture()?;
        assert_eq!(fixture.protocol, "bullbitcoin-descriptor-backup-v1");
        assert_eq!(fixture.version, DESCRIPTOR_VERSION);
        assert_eq!(fixture.action, DESCRIPTOR_STORE_ACTION);
        assert_eq!(fixture.vectors.len(), 2);
        assert_eq!(fixture.tamper_cases.len(), 8);
        assert_eq!(
            fixture
                .tamper_cases
                .iter()
                .map(|case| (case.field.as_str(), case.expected_code.as_str()))
                .collect::<Vec<_>>(),
            [
                ("version", "DescriptorInvalidRequest"),
                ("npub", "DescriptorAuthError"),
                ("ciphertext_sha256", "DescriptorInvalidRequest"),
                ("ciphertext_bytes", "DescriptorInvalidRequest"),
                ("lookup_tokens_order", "DescriptorInvalidRequest"),
                ("lookup_tokens_member", "DescriptorAuthError"),
                ("timestamp", "DescriptorAuthError"),
                ("signature", "DescriptorAuthError"),
            ]
        );
        let tokens = canonical_lookup_tokens(&fixture.lookup_tokens)
            .map_err(|_| "fixture lookup tokens are not canonical".to_owned())?;
        assert_eq!(tokens.len(), 3);
        let ciphertext = decode_descriptor_ciphertext(
            &fixture.ciphertext,
            ABSOLUTE_MAX_DESCRIPTOR_CIPHERTEXT_BYTES,
        )
        .map_err(|_| "fixture ciphertext did not decode".to_owned())?;
        assert_eq!(
            u64::try_from(ciphertext.len()).map_err(|_| "fixture length overflow".to_owned())?,
            fixture.ciphertext_bytes
        );
        assert_eq!(
            hex::encode(Sha256::digest(&ciphertext)),
            fixture.ciphertext_sha256
        );
        for vector in &fixture.vectors {
            let message = build_descriptor_signing_message(
                &fixture.action,
                &vector.npub,
                &fixture.ciphertext_sha256,
                fixture.ciphertext_bytes,
                &fixture.lookup_tokens,
                fixture.timestamp,
            );
            assert_eq!(hex::encode(&message), vector.signed_message_hex);
            assert_eq!(
                hex::encode(Sha256::digest(&message)),
                vector.signed_message_sha256
            );
            verify_descriptor_signature(
                &vector.npub,
                &fixture.ciphertext_sha256,
                fixture.ciphertext_bytes,
                &fixture.lookup_tokens,
                fixture.timestamp,
                &vector.signature,
                fixture.timestamp,
            )
            .map_err(|_| "fixture descriptor signature did not verify".to_owned())?;
        }
        let first = fixture
            .vectors
            .first()
            .ok_or_else(|| "fixture is missing a vector".to_owned())?;
        let second = fixture
            .vectors
            .get(1)
            .ok_or_else(|| "fixture is missing a second vector".to_owned())?;
        assert_ne!(first.npub, second.npub);
        assert_eq!(
            verify_descriptor_signature(
                &second.npub,
                &fixture.ciphertext_sha256,
                fixture.ciphertext_bytes,
                &fixture.lookup_tokens,
                fixture.timestamp,
                &first.signature,
                fixture.timestamp,
            ),
            Err(DescriptorApiError::Authentication)
        );
        assert_eq!(
            verify_descriptor_signature(
                &first.npub,
                &fixture.ciphertext_sha256,
                fixture.ciphertext_bytes,
                &fixture.lookup_tokens,
                fixture.timestamp,
                &first.signature,
                fixture.timestamp + TIMESTAMP_WINDOW_SECS + 1,
            ),
            Err(DescriptorApiError::Authentication)
        );
        Ok(())
    }
}
