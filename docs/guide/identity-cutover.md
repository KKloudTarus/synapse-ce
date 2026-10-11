# Identity cutover

Shared organization identity begins disabled. The runtime flag only restricts the tenants that a
binary may serve; it does not grant native identity authority. The tenant policy and append-only
`identity_cutover_ledger` are authoritative.

Run the workflow for one tenant at a time after every API, worker, and MCP replica is on the
migrate-first release. The command derives each step from the current policy and evidence, so do
not maintain a separate rollout checklist as state.

```bash
synapse-identity-backfill --mode prepare --tenants tenant-a --expected-policy-version 0
synapse-identity-backfill --mode backfill --tenants tenant-a --oidc-issuer https://issuer.example
synapse-identity-backfill --mode canary --tenants tenant-a
synapse-identity-backfill --mode declare --tenants tenant-a --expected-policy-version 1 \
  --shadow-report-id REPORT_ID --old-writer-generation shared-authentication:BUILD
synapse-identity-backfill --mode contract --tenants tenant-a --expected-policy-version 2
```

`prepare` moves a legacy tenant to shadow. Backfill and shadow produce append-only parity evidence.
`canary` only reads that evidence: it does not write legacy data or grant authority. `declare`
requires a current clean shadow report, rollback-prepared evidence, and fresh writer heartbeats for
the named generation with no older generation still live. The application registers these heartbeats;
the command does not accept a manually asserted writer count. The required schema version is
derived from the running binary's embedded migrations. Unknown older binaries require a full
upgrade and drain before declaration. It is the point of no return. Flags cannot restore legacy
authentication for a declared tenant; a mismatch must refuse the request or startup.

Before declaration, `abort` returns shadow to legacy while preserving legacy authentication:

```bash
synapse-identity-backfill --mode abort --tenants tenant-a --expected-policy-version 1
```

After declaration, abort and projection rollback are refused. Use paired backups and a forward fix.
`contract` records that post-declaration cleanup has started and is also terminal. The migration Down
path refuses while the ledger contains evidence.

## Paired backup, restore, and forward-fix drill

Before declaration, pause legacy and native writers for the tenant, wait for in-flight requests to
finish, then take a consistent whole-database backup. Record the backup identifier alongside the
clean shadow report and writer-drain evidence. Restore it only into a newly created, isolated
database. Do not restore over the running production database or the migration-control database.

In the isolated restore, verify the pre-declaration state together: the legacy `users` row and its
credential digest route, the projected `identity_memberships` row, the policy version and phase,
and every cutover-ledger and audit record. Re-enable no writers in that restored database. This
proves that the paired backup is usable without treating restore as a cutover rollback mechanism.

If declaration has completed, keep writers paused while you diagnose the fault. Do not run
`abort`, migration Down, or projection rollback: each is intentionally refused after the declared
ledger entry. Apply a migrate-first compatible forward fix, validate it against the isolated restore,
then deploy it and use `contract` when the cleanup boundary is ready. Confirm that the declaration
and existing audit and ledger rows remain present after the forward fix before resuming writers.

Set `SYNAPSE_IDENTITY_CUTOVER_ENABLED=true` with
`SYNAPSE_IDENTITY_CUTOVER_READ_TENANTS`; native mutation tenants in
`SYNAPSE_IDENTITY_CUTOVER_MUTATION_TENANTS` must be a subset. Configure these explicit tenant sets
on every upgraded writer before declaration so its heartbeat advertises the shared-authentication
generation. While the tenant remains in shadow, the durable policy still refuses native identity
operations. Declare only after the clean shadow and writer-drain checks pass; enable required SSO
separately after approved access and recovery readiness have been tested.
