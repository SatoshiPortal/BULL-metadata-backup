# Wallet backup protocol v2

Protocol v2 binds every signature to the server's configured public origin.
The server accepts v2 only; no released mobile client used protocol v1.

## Constants

| Name | Value |
|---|---|
| Version | `2` |
| Stream | `wallet_backup` |
| Authentication domain | `bullbitcoin-wallet-backup-v2` |
| ETag domain | `bullbitcoin-wallet-backup-etag-v1` |
| Timestamp window | inclusive ±300 seconds |
| Decoded ciphertext maximum | 1,048,576 bytes |
| Store HTTP body maximum | 1,572,864 bytes |
| Fetch/delete HTTP body maximum | 8,192 bytes |
| Tombstone retention | at least 900 seconds |

## Authentication

Each request signs SHA-256 of this NUL-separated byte sequence with BIP340:

```text
bullbitcoin-wallet-backup-v2
audience
action
wallet_backup
npub
generation
expected_etag_or_empty
ciphertext_sha256_or_empty
ciphertext_bytes
timestamp
```

There is one NUL byte before each field after the domain. `audience` is the
exact server origin configured by the operator and sent by the client. The
server rejects any other value before signature verification. Integers use
minimal unsigned decimal ASCII. Fetch signs generation and byte count as zero.
Delete signs an empty ciphertext hash and zero byte count.

Actions are `backup-fetch`, `backup-store`, and `backup-delete`.

## ETags

ETag is lowercase hexadecimal SHA-256 of:

```text
bullbitcoin-wallet-backup-etag-v1\0wallet_backup\0npub\0generation\0ciphertext_sha256_or_empty
```

Tombstones use an empty ciphertext hash.

## State

- Absence accepts only generation 1 with explicit `expected_etag: null`.
- A live or tombstone head advances only to N+1 with the current ETag.
- A live store with the same generation, ciphertext, hash, and derived ETag is
  an exact success retry. Its submitted expected ETag is ignored and its
  timestamp is not changed.
- A tombstone delete with the same generation and derived tombstone ETag is an
  exact success retry. Its submitted expected ETag is ignored and its timestamp
  is not changed.
- A tombstone may be replaced by a live N+1 object using the tombstone ETag.
- Any skipped, stale, changed same-generation, zero, or unrepresentable
  generation conflicts or fails validation. Generation arithmetic never wraps.
- Expired tombstones become absent generation-0 heads after cleanup.
- A successful store or delete retains no previous-generation row in the live
  service. There is no history endpoint or live fallback. Operational database
  backups may retain older ciphertext until their documented retention expires.

## Client guidance (non-normative)

- Clients SHOULD hash a canonical serialization of the plaintext backup and
  persist the identity only after a confirmed store. If the current identity is
  unchanged, they SHOULD skip encryption and the network request.
- An uncertain store retry SHOULD reuse the same generation, ciphertext, and
  ciphertext hash. Reusing the complete request while its timestamp is valid is
  simplest; after the timestamp window, refresh only the timestamp and
  signature. Do not re-encrypt a retry with a fresh nonce.
- Clients SHOULD treat `Retry-After` as a minimum delay and add only upward
  scheduling jitter.
- Clients SHOULD validate the mutation receipt's generation, ETag, and
  ciphertext hash. Success is returned only after the SQLite transaction
  commits; a second full download is not required after every store.

These recommendations reduce honest traffic, preserve exact-retry behavior,
and protect backup usability; server-side limits remain the enforcement and
do not trust client compliance.

## Errors

| HTTP | Code | Reason |
|---:|---|---|
| 400 | `BackupInvalidRequest` | request-specific frozen reason |
| 401 | `BackupAuthError` | `Wallet backup signature did not verify.` |
| 409 | `BackupHeadConflict` | `Wallet backup changed. Fetch the current head and retry.` |
| 413 | `BackupBlobTooLarge` | `Wallet backup exceeds the maximum object size.` |
| 429 | `RateLimited` | `Wallet backup request rate limit exceeded. Retry later.` |
| 503 | `BackupCapacityExceeded` | `Wallet backup storage is temporarily at capacity.` |
| 500 | `InternalError` | `Internal server error.` |

Every application success and error sets:

```text
Cache-Control: private, no-store, max-age=0
Pragma: no-cache
```

HTTP 429 responses also set `Retry-After`; treat it as the minimum wait
before retrying.

The JSON error object is:

```json
{"code":"...","reason":"...","status":"ERROR"}
```

Protocol vectors are in `tests/fixtures/wallet-backup-v2.json`.
