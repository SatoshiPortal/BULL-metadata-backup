# Private descriptor record protocol v1

This protocol is additive. It shares the process, database file, ingress, and
limit machinery with [wallet backup v1](protocol-v1.md) and changes none of
it: no shared domain, action, table, error code, or log event.

The service stores opaque ciphertext addressed by its hash inside a publisher
namespace, plus a small set of opaque lookup tokens that point at that record.
It has no BIP138, Bitcoin, or Nostr code and cannot decrypt, interpret, or
validate what it holds.

## Constants

| Name | Value |
|---|---|
| Version | `1` |
| Authentication domain | `bullbitcoin-descriptor-backup-v1` |
| Store action | `descriptor-store` |
| Timestamp window | inclusive ±300 seconds |
| Decoded ciphertext maximum | 65,536 bytes |
| Store HTTP body maximum | 98,304 bytes |
| Lookup HTTP body maximum | 8,192 bytes |
| Lookup tokens per request | 1 to 16 |
| Lookup token size | exactly 32 bytes |

## Lookup tokens

A lookup token is **32 opaque bytes**. The server never derives, interprets,
or validates one, and never returns one. Token derivation from account
identity is defined entirely client side; the server only requires that the
set is canonical.

A canonical token set is 1 to 16 lowercase 64-character hexadecimal tokens in
**strictly ascending byte order**, which is both sorted and duplicate free.
The server rejects any other ordering rather than reordering on the client's
behalf, because the signed message covers the exact sequence sent.

Knowing a token is the read capability for the records it points at. It
confers no authority to create, change, or remove anything.

## Operations

### `POST /api/v1/descriptor-backups`

Signed. Creates one immutable record, or confirms an identical one.

```json
{
  "version": 1,
  "npub": "<64 lowercase hex, BIP340 x-only public key>",
  "ciphertext": "<canonical standard base64 with padding>",
  "ciphertext_sha256": "<64 lowercase hex>",
  "ciphertext_bytes": 32,
  "lookup_tokens": ["<64 lowercase hex>", "..."],
  "timestamp": 1700000000,
  "signature": "<128 lowercase hex, BIP340>"
}
```

Success is `200` with:

```json
{"version":1,"ciphertext_sha256":"<64 lowercase hex>","created_at":1700000000}
```

### `POST /api/v1/descriptor-backups/lookup`

Unsigned. Knowing a token is the read capability.

```json
{"version": 1, "lookup_tokens": ["<64 lowercase hex>", "..."], "cursor": "<opaque>"}
```

`cursor` is optional. Omit it to ask for the newest page; send back the
`next_cursor` of a previous response, byte for byte, to continue.

Success is `200` with one page of matching records across every publisher,
newest first:

```json
{
  "version": 1,
  "next_cursor": null,
  "records": [
    {
      "ciphertext": "<canonical standard base64>",
      "ciphertext_sha256": "<64 lowercase hex>",
      "ciphertext_bytes": 32,
      "created_at": 1700000000
    }
  ]
}
```

`next_cursor` is a string when the record cap or the response byte budget
stopped the page before the end of the history, and `null` when the history is
complete. Asking again with it returns the records that follow, so every
stored record is reachable however many share one token. A client that stops
before the cursor runs out has an incomplete result and must say so.

The cursor is opaque: build nothing from it and read nothing out of it. A
cursor the server did not issue is `400 DescriptorInvalidRequest`.

A response never contains a publisher public key or a lookup token, and the
cursor names neither. Records are ordered by `created_at` descending, then by
an internal record id, so the order is total: a repeated request from the same
cursor returns the same page, records are immutable, and a new publication can
only appear ahead of a cursor, never inside a page already read.

There is no delete operation in this version.

## Authentication

Only the store operation is signed. It signs SHA-256 of this NUL-separated
byte sequence with BIP340:

```text
bullbitcoin-descriptor-backup-v1
descriptor-store
npub
ciphertext_sha256
ciphertext_bytes
token_count
token[0]
...
token[token_count - 1]
timestamp
```

There is one NUL byte before each field after the domain. Hex fields are the
exact lowercase strings sent on the wire. Integers use minimal unsigned
decimal ASCII. Tokens appear in canonical ascending order, the same order the
request carries.

The signature therefore binds the operation domain, the publisher, the exact
ciphertext hash and length, and the complete token set. Changing any token,
adding one, or removing one invalidates the signature.

## Record state

- Record identity is (publisher public key, ciphertext SHA-256).
- A record is immutable. A renewal is a new record, and both remain
  retrievable; the service keeps every generation a publisher created.
- The same identity with the same bytes and the same token set is an
  idempotent success that returns the original `created_at`.
- The same identity with different bytes or a different token set is
  `409 DescriptorRecordConflict`. Nothing is modified.
- A publisher cannot change or remove another publisher's record, even when
  both publish under the same tokens.
- The record and all of its lookup associations are written in one
  transaction, so a token never points at a record that is not there.

## Client obligations

The server cannot prove that a supplied token belongs to any particular
descriptor, and it cannot see inside the ciphertext. A lookup result is a set
of **untrusted candidates**. The client must decrypt each candidate, verify
its format, and verify exact key membership and canonical policy before using
it. A record that fails those checks is discarded without discarding the
others.

## Limits

| Bound | Default |
|---|---|
| Ciphertext per record | 65,536 bytes |
| Records per publisher | 64 |
| Records in the service | 100,000 |
| Records per lookup response | 32 |
| Ciphertext bytes per lookup response | 524,288 |
| Publisher store requests per window | 20 per hour |
| Repeat lookups of one token set per window | 60 per hour |

Ciphertext growth draws from the same persistent growth budget wallet backups
use. Descriptor records deliberately do **not** draw from the new-head
budget, so descriptor traffic cannot block wallet backup head creation.
Deployments set the real values in the environment; they are not published.

## Errors

| HTTP | Code | Reason |
|---:|---|---|
| 400 | `DescriptorInvalidRequest` | request-specific reason |
| 401 | `DescriptorAuthError` | `Descriptor backup signature did not verify.` |
| 403 | `DescriptorPublisherQuotaExceeded` | `Descriptor backup publisher record limit reached.` |
| 409 | `DescriptorRecordConflict` | `Descriptor record already exists with different content or lookup tokens.` |
| 413 | `DescriptorBlobTooLarge` | `Descriptor backup exceeds the maximum object size.` |
| 429 | `DescriptorRateLimited` | `Descriptor backup request rate limit exceeded. Retry later.` |
| 503 | `DescriptorCapacityExceeded` | `Descriptor backup storage is temporarily at capacity.` |
| 500 | `InternalError` | `Internal server error.` |

Every response sets the same cache headers as wallet backup v1, and `429`
responses set `Retry-After`.

Protocol vectors are in `tests/fixtures/descriptor-backup-v1.json`.
