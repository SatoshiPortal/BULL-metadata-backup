-- Applied inside the storage actor's immediate migration transaction.
CREATE TABLE recovery_grants(owner TEXT NOT NULL, grant_id TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(owner,grant_id));
CREATE TABLE recovery_records(id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, grant_id TEXT NOT NULL, hash TEXT NOT NULL, ciphertext BLOB NOT NULL, grant_json TEXT NOT NULL, UNIQUE(owner,grant_id,hash));
CREATE INDEX recovery_owner_id ON recovery_records(owner,id);
PRAGMA user_version = 3;
