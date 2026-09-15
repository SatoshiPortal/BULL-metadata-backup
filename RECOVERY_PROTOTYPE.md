# Arkade recovery resource

Branch: `prototype/arkade-recovery` in `SatoshiPortal/BULL-metadata-backup`.
Companion delegate: `prototype/encrypted-recovery` in `SatoshiPortal/fulmine`.

This prototype adds a separate executable and SQLite database for encrypted
delegated-refresh recovery records. The existing metadata server remains the
default executable; this resource is not yet integrated into its production API.

```sh
cargo build --locked --bin arkade-recovery-prototype
./target/debug/arkade-recovery-prototype DATABASE 127.0.0.1:9081 BACKUP_ORIGIN PUBLISHER_PUBLIC_KEY
```

The listener requires loopback. Remote deployments can carry traffic through an
SSH tunnel; the origin bound into signatures must match the configured origin.
The server stores ciphertext and has no user decryption keys.

- `POST /api/v1/arkade-recovery-records` accepts a user-authorized publisher's
  signed upload and returns a receipt after committing the exact ciphertext.
- `POST /api/v1/arkade-recovery-records/fetch` requires the user's Nostr signature
  and provides snapshot pagination. Missing retained cursor or snapshot records
  fail with a conflict, including after newer records arrive. There is no public
  lookup token. These checks cannot prove that all historical records remain.
- Exact upload retries are idempotent, including retries after grant expiry.
  A retry must still match the persisted ciphertext and verified grant before a
  receipt is returned. Grants, owner storage and total database capacity have
  bounded quotas.
- A process lock prevents two instances from owning the same database.

Run `cargo test --locked --bin arkade-recovery-prototype` for the authorization,
quota, pagination, concurrency and persistence tests. Fulmine's recovery suite
adds cross-language encryption and commit-then-lost-response tests when pointed
at this executable.

This is test infrastructure for regtest and Mutinynet, not a claim of completed
seed-only unilateral recovery. Backup records may describe unconfirmed or stale
candidates. The recovering wallet must validate the transaction ancestry,
Bitcoin state and expiry. Production listener integration, operational database
backups and complete wallet import remain separate work.
