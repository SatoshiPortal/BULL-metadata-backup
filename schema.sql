BEGIN IMMEDIATE;

CREATE TABLE wallet_backup_heads (
    author_pubkey       BLOB    NOT NULL PRIMARY KEY,
    generation          INTEGER NOT NULL,
    ciphertext          BLOB,
    ciphertext_sha256   BLOB,
    updated_at           INTEGER NOT NULL,
    CONSTRAINT author_pubkey_length CHECK (length(author_pubkey) = 32),
    CONSTRAINT generation_positive CHECK (generation > 0),
    CONSTRAINT updated_at_nonnegative CHECK (updated_at >= 0),
    CONSTRAINT live_or_tombstone CHECK (
        (ciphertext IS NULL AND ciphertext_sha256 IS NULL)
        OR
        (
            ciphertext IS NOT NULL
            AND ciphertext_sha256 IS NOT NULL
            AND length(ciphertext_sha256) = 32
            AND length(ciphertext) <= 1048576
        )
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX wallet_backup_tombstones_by_time
    ON wallet_backup_heads(updated_at)
    WHERE ciphertext IS NULL;

CREATE TABLE wallet_backup_admission (
    bucket                  TEXT    NOT NULL PRIMARY KEY,
    tokens                  INTEGER NOT NULL,
    refill_remainder        INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL,
    capacity                INTEGER NOT NULL,
    refill                  INTEGER NOT NULL,
    refill_interval_secs    INTEGER NOT NULL,
    CONSTRAINT admission_bucket_name CHECK (
        bucket IN ('new_heads', 'total_growth_bytes')
    ),
    CONSTRAINT admission_values_positive CHECK (
        tokens >= 0
        AND refill_remainder >= 0
        AND updated_at >= 0
        AND capacity > 0
        AND refill > 0
        AND refill_interval_secs > 0
    ),
    CONSTRAINT admission_tokens_bounded CHECK (tokens <= capacity),
    CONSTRAINT admission_remainder_bounded CHECK (
        refill_remainder < refill_interval_secs
    )
) STRICT, WITHOUT ROWID;

PRAGMA user_version = 1;

COMMIT;
