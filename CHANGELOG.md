# Changelog

## 0.4.0 — Unreleased

### Added

- Private BullVault descriptor records: signed, immutable publication and
  unsigned lookup by opaque, client-derived tokens. Records are isolated by
  publisher and retain prior vault generations.
- Bounded cursor pagination over matching descriptor records, including
  timestamp ties and continuation after a server restart. Responses disclose
  neither publisher identities nor lookup tokens.
- Descriptor-specific size, record-count, request and concurrency limits,
  aggregate metrics, and Nginx ingress templates.

### Fixed

- Database-backup verification now covers descriptor lookup associations and
  cursor identities, in addition to ciphertext commitments. Missing, orphaned
  or excessive associations are rejected; well-formed changes alter the
  aggregate digest for comparison with a trusted saved baseline.
- Association verification reads at most 17 rows per descriptor before
  rejecting an oversized set.
- Deployment documentation accurately describes shared capacity, paginated
  recovery budgets, and the available verification command.

### Scope

- Wallet backup protocol v1 remains unchanged relative to the current master
  branch, which reverted the audience-bound authentication change tagged 0.3.0.
- No new dependencies, server-side BIP138/decryption, Nostr publication or
  Bitcoin publication. Encrypting and validating descriptors belong to clients.
- Clients must follow `next_cursor` and retain it when a search pauses or is
  rate-limited. Backend pagination alone does not establish end-to-end app
  recovery readiness.
