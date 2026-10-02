# Identity foundation rollout

The identity foundation adds persons, tenant memberships, approved authenticators, connections and
exact-digest credential routing next to the existing `users` table. Until a tenant declares cutover,
`users` stays the only writer of record: bearer keys, browser sessions and roles keep coming from it, and
the new tables are a projection that can be dropped and rebuilt. Enterprise identity stays disabled, and
nothing in this release reads the new tables to authenticate a request.

This guide covers the order of operations, the backfill and shadow parity commands, how to read their
results, and how to back out.

## What changes for operators now

- An unknown OIDC `(issuer, subject)` is refused. No user is created, and provider groups never assign or
  change a role. `SYNAPSE_OIDC_GROUP_ROLE_MAPPING` is still accepted but ignored, with a startup warning.
- An administrator approves a subject for an existing user with `POST /api/v1/users/{id}/oidc-links` and
  removes it with `DELETE /api/v1/users/{id}/oidc-links/{linkId}`. Both are audited in the same transaction.
- Disabling or re-enabling a user revokes the API key and every browser session it holds. After
  re-enabling, rotate the key to restore API access. Automation that pauses a service account by
  disabling and re-enabling it needs a rotation afterwards.
- Authentication errors carry a stable `code`, `request_id` and `retryable`. Only `authentication_invalid`
  means the credential is bad; `authentication_unavailable` (503) is a dependency outage.

## Order of operations

1. Run `synapse-migrate` with the migration credential. The migration only adds tables, functions and
   grants. It takes a brief `SHARE ROW EXCLUSIVE` lock on `users` and `tenants` while it adds foreign keys
   from the new, empty tables; schedule it outside a burst of user-management writes.
2. Roll out the API, worker and MCP on every replica. Do not start the backfill while an older binary can
   still write `users`: an older binary does not maintain the projection, so its rotations and disables
   leave derived rows stale until the next backfill pass. Shadow parity reports that drift; it is not
   silent, but it blocks readiness.
3. Run the backfill for each tenant.
4. Run shadow parity for each tenant and read the outcome.
5. Run the rollback drill once, then run the backfill and shadow again, so a clean back-out has been
   rehearsed before anything depends on the projection.

## Running the command

`synapse-identity-backfill` ships in the `production` image target at `/opt/synapse/synapse-identity-backfill`,
alongside the other backfill commands; the Compose `full` and distroless `api` targets do not include it. It reads
`SYNAPSE_DB_DSN`, uses the runtime role, and refuses to start when that role can bypass row level
security.

```bash
# Project legacy users of one tenant and import its approved OIDC links.
synapse-identity-backfill --mode backfill --tenants tenant-a \
  --oidc-issuer https://issuer.example --batch-size 200

# Compare the projection with users without changing anything.
synapse-identity-backfill --mode shadow --tenants tenant-a --max-drift 0

# Rehearse backing out: delete the derived rows and stop projecting. users is never written.
synapse-identity-backfill --mode rollback --tenants tenant-a
```

| Flag | Meaning |
| --- | --- |
| `--mode` | `backfill`, `shadow`, `rollback` or `deliver` |
| `--tenants` | Comma-separated tenant IDs, at most 16 per run |
| `--oidc-issuer` | The configured fixed issuer whose approved links are imported. Empty imports none |
| `--actor` | Audit actor recorded for the run |
| `--batch-size` | Users per committed batch, 1 to 1000 (default 200). The cap exists because projecting a person takes one advisory lock, and a transaction holds at most `max_locks_per_transaction` locks |
| `--max-drift` | Drift up to this count reports not ready; more aborts |
| `--delivery-limit` | Person-audit delivery obligations per tenant per pass, 1 to 500 |
| `--timeout` | Overall command timeout (default 30m) |
| `--lease-duration` | A running backfill updated within this window blocks a second one (default 10m) |

Each batch locks its `users` rows in ID order, then locks approved OIDC links in link-ID order and derived
authenticators in subject order. It reads all evidence for the batch in a fixed number of queries and
commits its checkpoint together with the derived rows. The authoritative approved links are reconciled
transactionally: stale `legacy_link` rows are removed, a rebound subject replaces its old legacy binding,
and a canonical key already owned by a native authenticator fails closed without partial writes. Inside a
batch, a lock wait longer than 5 seconds
or a statement longer than 60 seconds fails that batch and rolls it back, so a stuck batch releases its
locks instead of holding the tenant's user management. Rerunning resumes from the last committed
checkpoint; reprocessing a user is idempotent. A run whose lease expired is marked failed and can be
restarted.

Writes are still one row at a time, about six statements per user. On the first pass, the batch that
creates persons also holds a deployment-wide person-audit lock until it commits, so creating a user in
any tenant whose projection is on waits for that batch. Bearer and browser authentication take no lock
and are not affected, and reruns skip person creation. On a database a few milliseconds away a batch of
200 holds the lock for about a second; the time grows with batch size and with round-trip latency, so
lower `--batch-size` on a high-latency link or when user creation must not wait.

Each batch reads the tenant's audit records twice to find key-issuance evidence and link approvers, and
`audit_log` has no index on the target. Before the first run on a large tenant, count what each batch
will scan:

```sql
SELECT count(*) FROM audit_log WHERE tenant_id = 'tenant-a' AND hash_version = 2;
```

Tens of millions of rows make every batch noticeably slower, and a scan past the 60-second statement
bound fails the batch; it rolls back without losing data. For a tenant that size, keep `--batch-size`
high so there are fewer scans, and rehearse on a copy first.

## Reading the result

| Exit code | Outcome | Meaning |
| --- | --- | --- |
| 0 | ready | Zero drift and zero ambiguous rows in every tenant. Also success for `rollback` and `deliver` |
| 1 | failure | Invalid arguments or an operational failure in any tenant. This takes precedence over parity |
| 3 | not ready | Drift at or below `--max-drift`, or ambiguous rows remain |
| 4 | aborted | Drift above `--max-drift` in at least one tenant |

The log line for each tenant reports `outcome`, `drift_total` with each drift component, and `ambiguous`
separately. Authenticator parity has the same expected/matched/mismatch shape as credential parity:
`authenticators_expected` counts authoritative approved links under the configured OIDC connection,
`authenticators_matched` counts exact membership/person matches, and `authenticator_mismatches` includes
missing, stale, extra, or rebound rows. Any authenticator mismatch contributes to `drift_total` and blocks
readiness. Shadow mode only reports this drift; backfill mode performs the reconciliation. Every shadow run
also appends a row to `identity_shadow_reports`, and every backfill run is recorded in
`identity_backfill_runs`. Per-user classification is in `identity_backfill_items`.

Ambiguous rows are users the backfill would not project a credential for:

- `ambiguous_unproven_key`: no audit record proves the current key was issued. This includes users created
  before audit hash version 2 and users whose audit rows were removed by retention. Rotate the user's key,
  then rerun the backfill.
- A duplicate or malformed key hash, or a digest that already routes to another user. Investigate the
  `users` row; the backfill never repairs the source.
- A link whose issuer is not the configured `--oidc-issuer`. It is not imported.

The bootstrap `operator` user is never projected. A placeholder key on a user that only signs in through
OIDC gains no credential.

## Backing out

Prefer the rollback drill. It refuses a tenant that has declared cutover, deletes only derived rows, turns
projection off for the tenant, never writes `users`, `audit_log`, run records or shadow reports, and is
itself audited. Authentication keeps working throughout, because nothing reads the projection yet.

Reverting the migration with goose is a last resort. Its Down refuses to run while
`identity_person_audit` or `identity_shadow_reports` hold rows, because those are append-only evidence.
Archive them first, and roll every API, worker and MCP replica back to a binary that predates the
migration before running Down; a newer binary fails every user write once the tables are gone.

## Not in this release

- The backfill write phase is per row, and its audit reads have no supporting index. A set-based write
  phase and an `audit_log (tenant_id, target)` index built concurrently are planned before projection is
  run on very large tenants or against a high-latency database.

- Person-audit delivery runs only on demand (`--mode deliver`). No worker schedules it, and there is no
  metric or alert for pending or exhausted obligations. Nothing fans out to tenants yet, because persons
  are created before their first membership.
- Suspending or reactivating a person, and revoking a person's sessions across tenants, require the
  migration (owner) connection. The runtime role can only create persons.
- No organization switching, invitations, provider connections or enterprise sign-in. Those land with the
  shared authentication and cutover work, behind their own activation gates.
