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
        let status = self.status();
        let code = self.code();
        let mut response = private_no_store(
            (
                status,
                Json(json!({
                    "status": "ERROR",
                    "code": code,
                    "reason": self.reason(),
                })),
            )
                .into_response(),
        );
        if let Self::RateLimited {
            retry_after_secs, ..
        } = self
            && let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
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

pub fn decode_canonical_hex<const N: usize>(
    value: &str,
    reason: &'static str,
) -> Result<[u8; N], ApiError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::InvalidRequest(reason));
    }
    let decoded = hex::decode(value).map_err(|_| ApiError::InvalidRequest(reason))?;
    decoded
        .try_into()
        .map_err(|_| ApiError::InvalidRequest(reason))
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

pub fn decode_ciphertext(value: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    let decoded = BASE64_STANDARD
        .decode(value)
        .map_err(|_| ApiError::InvalidRequest("Wallet backup ciphertext is not base64."))?;
    if decoded.len() > max_bytes {
        return Err(ApiError::BlobTooLarge);
    }
    if BASE64_STANDARD.encode(&decoded) != value {
        return Err(ApiError::InvalidRequest(
            "Wallet backup ciphertext base64 is not canonical.",
        ));
    }
    Ok(decoded)
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
}
