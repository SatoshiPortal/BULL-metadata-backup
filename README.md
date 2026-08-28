# backup-server

`backup-server` stores one authenticated, opaque encrypted backup head per
BIP340 public key. It cannot decrypt or interpret stored data.

The public API has three operations:

- `POST /api/v1/wallet-backups/fetch`
- `PUT /api/v1/wallet-backups`
- `DELETE /api/v1/wallet-backups`

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
ceilings, rate windows, admission budgets, concurrency, timeouts, and log
level — are enumerated with their development defaults in `src/config.rs`.
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

## Back up

Copying the database is an operations task, done with standard SQLite tooling
while the server runs:

```sh
sqlite3 /var/lib/backup-server/backup.sqlite3 \
  ".backup /srv/backup-server/backup-2026-08-26.sqlite3"

backup-server verify-backup /srv/backup-server/backup-2026-08-26.sqlite3
```

`verify-backup` checks what generic tooling cannot: schema shape, admission
rows, head and byte consistency, and an aggregate digest for before-and-after
comparison. Always verify the copy, never the live file in its place, and do
not replace the previous backup until the new copy verifies. Restoration is an
offline operation: stop the service, restore the verified file, and restart.

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

See [docs/protocol-v1.md](docs/protocol-v1.md) for the wire contract and
[SECURITY.md](SECURITY.md) for the security boundary.
