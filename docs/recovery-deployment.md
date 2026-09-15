# Integrated recovery deployment

The main `backup-server serve` command serves delegated recovery through its
existing loopback listener and SQLite worker. The standalone prototype binary
remains temporarily for compatibility tests. Mainnet remains disabled by the
companion Fulmine fork; enabling these routes does not change that restriction.

## Configuration

Keep the ordinary required storage/admission settings. Enable recovery with:

```sh
export BACKUP_SERVER_RECOVERY_ORIGIN=https://<backup-origin>
export BACKUP_SERVER_RECOVERY_PUBLISHER=<delegate-publisher-public-key>
export BACKUP_SERVER_RECOVERY_MAX_RECORDS=<global-record-capacity>
export BACKUP_SERVER_RECOVERY_MAX_BYTES=<global-recovery-byte-capacity>
backup-server serve
```

Origin and publisher must be configured together. The origin is exact signed
protocol data: HTTPS with no path, credentials, query, fragment or trailing
slash. Loopback HTTP with an explicit port is supported for isolated tests and
tunnels. Do not rewrite existing grants when changing deployment topology.

The recovery resource defaults to 10,000 records and 256 MiB globally. Per-owner
limits remain 10,000 records and 16 MiB, compatible with existing recovery
clients. The shared `BACKUP_SERVER_MAX_LIVE_BYTES` cap includes wallet,
descriptor and recovery ciphertext. Recovery appends also consume the existing
persistent growth-admission bucket in the same transaction. Reads and valid
exact retries do not consume storage admission, including after grant expiry or
when retained bytes exceed a subsequently reduced admission cap.

Recovery uses existing fetch/store concurrency permits and the bounded worker
queue. It has independent owner request windows through the same limiter:

| Variable | Default |
|---|---:|
| `BACKUP_SERVER_RECOVERY_FETCH_NPUB_LIMIT` | 2500 |
| `BACKUP_SERVER_RECOVERY_FETCH_NPUB_WINDOW_SECS` | 3600 |
| `BACKUP_SERVER_RECOVERY_STORE_NPUB_LIMIT` | 256 |
| `BACKUP_SERVER_RECOVERY_STORE_NPUB_WINDOW_SECS` | 3600 |

Allow for eight-record fetch pages and retries when sizing these windows. These
are bounded initial settings, not a measured production throughput guarantee.
Rate limiting can still return 429; clients must retain incomplete status and
retry appropriately. Capacity rejection never deletes an existing record.

Include `deploy/nginx/recovery-backup.conf` alongside `backup-server.conf`,
`descriptor-backup.conf`, and the HTTP-level zones in `backup-server-http.conf`.
The proxy must overwrite `X-Real-IP`; the app rejects missing or malformed source
identity. Include the common server-level timeout configuration. Public HTTPS,
certificate renewal and deployment-specific browser origins belong to the
proxy configuration. Test the assembled configuration with `nginx -t`.

Periodic `recovery_storage_totals` logs expose new and retained record/byte
counts without owner keys or ciphertext. Monitor available storage, rejected
appends, service health and Fulmine's quarantined attempts. Preserve the
publisher identity, Fulmine task database, signed attempts and encrypted outboxes
as a consistent operational set.

## Import the standalone prototype database

This is an offline administrative operation, never a public upload bypass.

1. Stop the legacy writer and take a SQLite backup. Retain that original copy.
2. Back up the destination metadata database and stop its service. Configure the
   main server's destination path, recovery origin/publisher and capacities.
3. Run `backup-server import-recovery <absolute-offline-source>`.
4. Verify an offline copy of the resulting database with `backup-server
   verify-backup <absolute-copy>`, then start the main service and perform an
   owner-signed historical fetch before changing delegate traffic.

Import checks the exact source schema, integrity, grant signatures, hashes,
quotas, publisher/origin and cursor sequence under one source read transaction.
The destination requires pristine recovery tables or an identical full import
retry. It preserves record IDs and the source high-water mark, and commits the
records and growth accounting atomically. Expired grants can be imported because
these are verified historical records. Existing wallet and descriptor data are
preserved. An active legacy lock, conflicting target, corrupt data or insufficient
capacity/admission rejects the import without a partial record copy.

## Restore and rollback

Use SQLite's backup mechanism and the normal `verify-backup` command for all
three resources. Verification detects structural damage and hash/signature
inconsistency. Comparing its digest to a previously retained trusted digest is
necessary to detect a different but internally consistent snapshot; it cannot
prove a backup contains records that were never included in that snapshot.

Schema 3 is additive but older binaries refuse it. Roll back only to a binary
that understands schema 3, or perform an explicit data-preserving recovery.
Restoring an old database alone loses subsequently acknowledged records. Never
discard newer recovery copies or retry them through expired public append
authorization as a substitute for historical restoration.

The initial import supports a complete source into pristine recovery tables.
Merging missing records into a nonempty older destination is intentionally
rejected pending a separately tested reconciliation procedure. Host-loss
durability and restoring multiple divergent surviving copies remain release
gates; process-kill tests alone do not establish them.
