# Security

## Boundary

The service accepts encrypted bytes, BIP340 public keys and signatures, hashes,
generation counters, timestamps, and opaque 32-byte descriptor lookup tokens.
It never receives plaintext or encryption keys, and it never derives or
interprets a lookup token.

Descriptor lookup is deliberately unauthenticated: knowing a lookup token is
the read capability for the records it points at. That read capability confers
no authority to create, change, or remove anything, and one publisher cannot
alter another publisher's record even when both publish under the same token.
A lookup result is a set of untrusted candidates; the service cannot prove
that a token belongs to any particular descriptor, so membership and policy
validation belong to the client after decryption.

HTTPS protects the transport. It is not a promise that the operator cannot
correlate records, tokens, or traffic; separate signing identities remove the
direct public-key join but not timing, address, or ciphertext correlation.

The application rejects malformed input, replay outside the signed window,
invalid signatures, stale writes, oversized objects, capacity growth beyond
configured limits, excess request or storage concurrency, and active-window
abuse. Backup verification checks database integrity and ciphertext
commitments.

The accepted operating model is one process, one loopback listener, one SQLite
writer thread, one ingress, bounded restart-reset in-memory subject limits, and
two persistent SQLite admission buckets. TLS termination, connection limits,
slow-client handling, volumetric DDoS protection, firewalling, filesystem
quotas, and host resource limits belong to the deployment boundary. Compromise
of the host, ingress, client signing key, or provider control plane, traffic
analysis, and deletion from retained historical backups are outside the
application's guarantees.

## Dependency rationale

| Dependency | Required capability |
|---|---|
| `axum` | HTTP/1 routing, bounded JSON extraction, responses |
| `tokio` | loopback socket, signals, bounded channels, timers |
| `serde`, `serde_json` | strict frozen JSON contract |
| `secp256k1` | audited BIP340 verification |
| `sha2` | signed-message, ciphertext, ETag, and aggregate commitments |
| `base64`, `hex` | canonical protocol encodings |
| `rusqlite` | direct SQLite API and Online Backup API |
| `fs2` | OS-level exclusive serving lock |
| `getrandom` | process-private limiter salt and collision-safe temporary names |
| `tracing`, `tracing-subscriber` | structured static operational events |

`rusqlite` uses its bundled SQLite build. Dynamic extension loading, SQL
functions, virtual tables, serialization, tracing hooks, chrono/time adapters,
and connection pooling are not enabled.

## Storage

Startup verifies the configured SQLite pragmas and exact schema, upgrading a
version 1 database to version 2 by adding descriptor objects only, then
reconstructs aggregate counters without reading and hashing every ciphertext.
The `backup` and `verify-backup` commands perform full integrity, row, hash, and
aggregate verification over both wallet backup heads and descriptor records,
including that every lookup association points at a record that exists. Backups may retain ciphertext deleted from the live
database and must follow an explicit retention policy.

## Logging

Application requests produce no individual success or rejection logs. One
fixed event per configured interval contains only integer request, admission,
and aggregate storage totals; the seven frozen error codes; and four fixed
rate-limit classes.
Lifecycle logs are limited to static events, cleanup counts, backup results,
storage health, and process failures.

A second fixed event per interval carries the descriptor request and storage
totals under the same rules.

Logs must not contain per-request or per-user ciphertext, public keys,
signatures, hashes, ETags, lookup tokens, digests of lookup tokens, source
addresses, headers, request bodies, SQL values, or database paths. The `aggregate_sha256` printed to an operator's
standard output by `backup` and `verify-backup` is a database-wide verification
digest, not a request log or per-user identifier, and is exempt for
before-and-after verification.

Ingress access logs are disabled in every terminal backup location. The public
backup locations suppress Nginx error messages below `crit`. Critical failures,
and connection, TLS, or socket failures that occur before Nginx selects a
backup location, can still contain a peer address because standard Nginx error
logging has no address-redaction facility. Operators must restrict and expire
those infrastructure logs; deployments requiring stronger traffic anonymity
need an ingress with address-redacting logs.

## Reporting

Report vulnerabilities privately through the repository's security contact.
Do not include real backups, signatures, public keys, source addresses, or
production database material in an issue.

## Release checks

Review `cargo tree -e features --locked`, `cargo tree --duplicates --locked`,
RustSec advisories, direct-source provenance, CI action SHAs, service-manager
hardening, ingress routing, backup verification, and a restore drill before a
production release.
