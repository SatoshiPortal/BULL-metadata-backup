# backup-server

`backup-server` stores opaque encrypted data for BIP340 public keys. It cannot
decrypt or interpret anything it stores.

It serves three independent resources. Delegated recovery is opt-in.

**Wallet backups** are one authenticated head per public key, replaced in
place:

- `POST /api/v1/wallet-backups/fetch`
- `PUT /api/v1/wallet-backups`
- `DELETE /api/v1/wallet-backups`

**Private descriptor records** are immutable publications addressed by their
ciphertext hash within a publisher namespace, retrieved by opaque lookup
tokens the client derives and the server never interprets:

- `POST /api/v1/descriptor-backups`
- `POST /api/v1/descriptor-backups/lookup`

**Delegated Ark recovery records** are immutable ciphertext publications encrypted
to the user's Nostr key, with owner-signed grants and fetch requests:

- `POST /api/v1/arkade-recovery-records`
- `POST /api/v1/arkade-recovery-records/fetch`

They use the same listener, database worker, capacity accounting and operational
backup as the other resources. See [recovery deployment](docs/recovery-deployment.md)
for configuration, importing historical prototype records and rollback limits.

The descriptor resource is additive. It changes no wallet backup request
format, response, or semantic.

See [CHANGELOG.md](CHANGELOG.md) for the v0.4.0 release scope. The package
version is independent of the API version; both resources use `/api/v1/`.

## Build

```sh
cargo build --release --locked
```

TLS and public routing belong to the reverse proxy. The application binds to
loopback and has no outbound network client or administrative API.

## Run

```sh
export BACKUP_SERVER_DB_PATH=/var/lib/backup-server/backup.sqlite3
export BACKUP_SERVER_MAX_LIVE_BYTES=<bytes>
export BACKUP_SERVER_MAX_HEADS=<count>
export BACKUP_SERVER_LIMITER_MAX_SUBJECTS=<count>
backup-server serve
```

Four variables are required: `BACKUP_SERVER_DB_PATH`,
`BACKUP_SERVER_MAX_LIVE_BYTES`, `BACKUP_SERVER_MAX_HEADS`, and
`BACKUP_SERVER_LIMITER_MAX_SUBJECTS`. The optional variables — object size
ceilings, rate windows, admission budgets, concurrency, timeouts, descriptor
record and lookup bounds, and log level — are enumerated with their
development defaults in `src/config.rs`. Descriptor variables all carry
`DESCRIPTOR` in their name and every one of them is optional. Size the shared
queue and growth budget for both resources: the queue must exceed the sum of
all in-flight limits, and the growth bucket must admit the largest accepted
metadata or descriptor ciphertext. Defaults do not make every earlier custom
configuration valid; check the intended configuration before starting service.
Production limits are set in the deployment environment and are not
published. The Nginx files under `deploy/` are structural templates whose
rates are likewise tuned privately before deployment.

Unknown `BACKUP_SERVER_*` variables stop startup. Contradictory combinations
stop startup. The reverse proxy must replace `X-Real-IP` with exactly one
validated source address; missing or malformed source identity is rejected.

All policy changes require a process restart; there is no runtime reload.
Persistent admission balances survive that restart and are clamped when
capacity is lowered. The per-npub rolling windows restart empty. Per-source
rate limiting happens in Nginx; the application validates the proxy-supplied
source header and fails closed without it.

New heads draw from a persistent head-admission bucket, and every positive
byte delta — new heads and tombstone revivals included — draws from a
persistent growth bucket. Deletes never refund these budgets. Admission
checks and mutations commit in one SQLite transaction, so concurrent requests
cannot overshoot a bucket.

Descriptor records draw from the same persistent growth bucket, but not from
the head bucket. Exhausting shared growth capacity can temporarily prevent
metadata creation or growth as well as descriptor publication. Descriptor
counts are additionally bounded per publisher and across the service.

Each descriptor lookup page consumes one lookup-window request. Size the
window for multi-page recovery and ordinary retries. Clients must honor
`Retry-After` and retain a continuation cursor when interrupted; increasing
limits is not a substitute for resumable recovery. The per-token-set window
does not replace the proxy's per-source and global limits.

## Upgrade

The database carries a schema version. A version 1 database is upgraded to
version 2 on startup by adding the two descriptor tables and their index; the
upgrade never reads or writes `wallet_backup_heads`, and a fresh database is
built by running the same migration. Version 3 then adds recovery tables in a
verified transaction without rewriting wallet or descriptor records. The
version-3 verification digest also covers recovery records and their cursor
high-water mark; compare digests produced by the same verifier version. Keep the
original pre-upgrade database and matching verifier when migrating an old copy.
Older binaries reject version 3 and cannot serve as a rollback for that database.

## Back up

Copying the database is an operations task, done with standard SQLite tooling
while the server runs:

```sh
sqlite3 /var/lib/backup-server/backup.sqlite3 \
  ".backup /srv/backup-server/backup-2026-08-26.sqlite3"

backup-server verify-backup /srv/backup-server/backup-2026-08-26.sqlite3
```

`verify-backup` checks what generic tooling cannot: schema shape, admission
rows, head and byte consistency, descriptor lookup associations, recovery grant
signatures, ciphertext hashes, quotas and cursor high-water marks. Each
descriptor must have 1–16 valid associations; no association may point at a
missing record. The aggregate digest includes descriptor contents, cursor
identities and sorted lookup associations for before-and-after comparison.
Changing a well-formed token changes that digest, but only comparison with a
trusted earlier digest can identify the change; the server cannot determine
which token belongs to an encrypted descriptor. Always verify the copy, never
the live file in its place, and do not replace the previous backup until the
new copy verifies. Restoration is an offline operation: stop the service,
restore the verified file, and restart.

## Check

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
cargo doc --no-deps --document-private-items --locked
cargo audit
```

See [docs/protocol-v1.md](docs/protocol-v1.md) and
[docs/descriptor-v1.md](docs/descriptor-v1.md) for the wire contracts, and
[SECURITY.md](SECURITY.md) for the security boundary.
