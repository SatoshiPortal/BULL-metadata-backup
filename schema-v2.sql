BEGIN IMMEDIATE;

CREATE TABLE descriptor_records (
    publisher_pubkey    BLOB    NOT NULL,
    ciphertext_sha256   BLOB    NOT NULL,
    record_id           BLOB    NOT NULL UNIQUE,
    ciphertext          BLOB    NOT NULL,
    ciphertext_bytes    INTEGER NOT NULL,
    created_at          INTEGER NOT NULL,
    CONSTRAINT descriptor_publisher_length CHECK (length(publisher_pubkey) = 32),
    CONSTRAINT descriptor_hash_length CHECK (length(ciphertext_sha256) = 32),
    CONSTRAINT descriptor_record_id_length CHECK (length(record_id) = 16),
    CONSTRAINT descriptor_bytes_match CHECK (
        ciphertext_bytes = length(ciphertext)
        AND ciphertext_bytes > 0
        AND ciphertext_bytes <= 65536
    ),
    CONSTRAINT descriptor_created_at_nonnegative CHECK (created_at >= 0),
    PRIMARY KEY (publisher_pubkey, ciphertext_sha256)
) STRICT, WITHOUT ROWID;

CREATE TABLE descriptor_lookups (
    token               BLOB    NOT NULL,
    publisher_pubkey    BLOB    NOT NULL,
    ciphertext_sha256   BLOB    NOT NULL,
    CONSTRAINT descriptor_lookup_token_length CHECK (length(token) = 32),
    PRIMARY KEY (token, publisher_pubkey, ciphertext_sha256),
    FOREIGN KEY (publisher_pubkey, ciphertext_sha256)
        REFERENCES descriptor_records(publisher_pubkey, ciphertext_sha256)
) STRICT, WITHOUT ROWID;

CREATE INDEX descriptor_lookups_by_record
    ON descriptor_lookups(publisher_pubkey, ciphertext_sha256);

PRAGMA user_version = 2;

COMMIT;
