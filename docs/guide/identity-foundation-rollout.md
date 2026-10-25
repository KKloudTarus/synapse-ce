# Identity foundation rollout

The identity foundation adds persons, tenant memberships, approved authenticators, connections and
exact-digest credential routing next to the existing `users` table. Until a tenant declares cutover,
`users` stays the only writer of record: bearer keys, browser sessions and roles keep coming from it, and
the new tables are a projection that can be dropped and rebuilt. A declared tenant may use its native
identity authority for enterprise browser sessions; that authority remains tenant-scoped.

This guide covers the order of operations, the backfill and shadow parity commands, guarded initial
organization provisioning, public organization sign-in, how to read results, and how to back out.

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

## Where the provider has to be reachable from

The API's OIDC client admits globally reachable destinations only. It resolves the issuer host and
checks every answer before dialling, so a provider on a loopback, private, unique-local or
cloud-metadata address is refused:

```
build authorization URL: OIDC discovery is cooling down: discover OIDC issuer:
Get "https://127.0.0.1:18543/realms/master/.well-known/openid-configuration":
OIDC destination address 127.0.0.1 is not public
```

The client is deliberately not configurable: it ignores ambient proxy settings, follows no provider
redirect, and there is no flag that admits a private address. One private answer among several is
enough to refuse the host, so split-horizon DNS that returns an internal address to the API does not
work either.

What this means in practice:

- A hosted provider (Entra ID, Okta, Auth0, Google) works as it is.
- A self-hosted provider has to be published on a public name with a certificate the API trusts.
  Keycloak, Authentik or Zitadel on an internal network cannot be reached from the API, and the
  failure appears at the connection test rather than at startup.
- A connection draft is accepted before any discovery runs, so a draft that stores cleanly says
  nothing about reachability. The test is what proves it.

## Exact issuer URLs

Keep the issuer exactly as the provider advertises it, including any trailing slash. For example,
`https://issuer.example` and `https://issuer.example/` are separate trust identifiers. Synapse checks
discovery metadata, signed token claims and approved subject links against that exact value.

Previously, configuration and new connection drafts removed trailing slashes. A configuration that
relied on that behavior must be corrected to match the provider. Existing stored connections and
approved links are not rewritten: correcting a connection issuer requires a new tested connection,
and fixed-provider subjects require explicit approval under the correct issuer.

## Initial organization provisioning

Initial provisioning creates the first identity connection and first administrator for one fresh,
configured tenant. It is entered locally at `/settings/authentication?operator=1`. That entrance accepts
only the deployment's bootstrap administrator credential; it does not grant the operator a membership in
the target tenant. A normal organization token cannot use it.

The bootstrap administrator runs the scoped sequence for the target tenant:

1. `POST /api/v1/identity/provisioning/begin` with `tenant_id` and the first administrator's `recipient`.
   It reserves the target, connection, and pinned administrator invitation, returning a safe
   `provisioning` view plus a short-lived capability when the reservation is still open.
2. `POST /api/v1/identity/provisioning/draft` with that capability and the connection fields
   (`display_name`, `issuer`, `client_id`, `client_secret`, optional
   `auth0_organization_id`, and `version`). The connection ID and tenant come from the reservation,
   not from the request. Use version `0` for the first save. Before activation, a secret correction
   uses the current connection version, creates a new revision, and requires a fresh provider Test.
   Issuer, client ID, callback, and organization restriction remain fixed.
3. `POST /api/v1/identity/provisioning/test` to obtain `authorization_url` and complete a real provider
   login. Its callback returns only to `/settings/authentication?provisioning_tenant=<target>`; it does
   not expose a capability, client secret, or invitation code in the URL.
4. `POST /api/v1/identity/provisioning/activate` with the capability, tested `revision`, and current
   `version`.
5. `POST /api/v1/identity/provisioning/invitation` with the capability. It returns the safe
   `provisioning` view and the one-time first-administrator `code`; keep both that code and the
   capability out of persistent client storage.
6. The invited person completes ordinary invitation enrollment, receives the target tenant membership,
   and then signs in through the active connection as that administrator.

`status` reads the same safe reservation view for a capability. The safe view contains the reservation
ID, tenant ID, recipient, state, version, and non-secret connection and invitation metadata. It never
returns the capability, sealed client secret, or invitation code. Every route is platform-bootstrap
administrator only. Begin and status may report a closed reservation; Begin omits its capability.
Mutations refuse a closed or conflicting reservation, an expired capability, a stale version, or an
untested revision. Provider cancellation returns to setup after validation of its sealed context.
The pinned first-administrator invitation expires after seven days and is not renewed automatically;
an expired invitation fails closed. Accepted invitations no longer participate in ordinary sign-in.

## Public organization sign-in

An ordinary sign-in can be bookmarked as `?tenant_id=<target>`. The client reads
`GET /api/auth/enterprise/context?tenant_id=<target>` and sends the same `tenant_id` only with
`POST /api/auth/enterprise/begin` where `purpose` is `login`. Omission keeps the legacy deployment
default behavior.

An explicit target must be a non-empty, bounded identifier without controls, occur only once in the
query, and name a tenant that is declared for identity and enabled for both reads and mutations in this
process. An unknown, undeclared, or unavailable target fails closed; it never falls back to the default
tenant or another connection. `test`, invitation, link, and step-up flows derive their target from their
server-held proof, code, or session and reject a caller-provided selector.

The callback uses the tenant sealed into its authorization nonce, not a callback query parameter. Its
ordinary login and invitation redirects may carry a non-secret `tenant_id` hint so the frontend can
retain the selected organization for a retry or logout recovery. That hint cannot override the sealed
target or create a session in another tenant.

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
- Initial provisioning creates only one fresh tenant's first connection and first administrator. Routine
  connection, invitation, membership, and recovery operations remain scoped to their authenticated
  tenant authority.
