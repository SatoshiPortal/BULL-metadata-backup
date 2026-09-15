# Recovery release checks

The `Recovery conformance` workflow tests this repository's candidate against an
exact Fulmine companion commit on all pull requests, master and recovery branch
pushes, and manual dispatch. It checks identical wire fixtures, all Rust targets,
the main-listener integration, both server builds, Go race tests using this Rust
companion, and explicitly required conformance and pre-forfeit gate passes.

The shared entrypoint and detailed release procedure live in Fulmine:
`test/recovery/backend_ci.py` and `docs/backend-release.md` at the exact
`.github/workflows/recovery.yml` companion SHA. A missing entrypoint, fixture or
required passing test must fail; do not bypass it. Keep the standalone prototype
executable until its cross-language fault tests have migrated to the main server.

The helper requires clean paired checkouts and writes a compact report with both
source revisions, fixture hash, executable hashes and skipped live tests. The
`Backend recovery components` check becomes an enforced merge gate only when a
repository administrator adds it to branch protection. This change does not
configure protection, publish packages, deploy services or provision runners.

When updating the pair, publish backup runtime/tests first, then Fulmine's runtime
and CI helper pinned to that backup revision, then this workflow pinned to the
resulting Fulmine commit. Review both passing reports. Keep full SHA pins; a
moving companion branch cannot establish reproducible compatibility.

Component CI does not replace exact-release-artifact live refresh/confirmed-exit
and backup-outage scenarios. Before deploying a schema change, test operational
database backup/restore of both metadata and recovery on an isolated instance,
including aggregate accounting and historical fetch. Preserve deployed data and
owner configuration. Follow the migration's rollback limits; an older binary
must not open a schema it cannot support. Record the deployed executable hash
and authenticated post-restart recovery evidence. Never publish live artifact
directories containing seeds or wallet state as ordinary CI logs.
