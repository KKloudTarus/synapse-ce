# Troubleshooting

[Documentation home](README.md)

Every entry here is a failure that happened on a real deployment, with the symptom as the
operator saw it, why it happens, the command that confirms it, and the fix. They are grouped by
where you notice them, not by which subsystem is at fault, because the two rarely match: a scan
that reports "no dependency manifests" is usually a host setting, and a recon run that blames a
network namespace is usually a file permission.

Start with [the readiness checks](#readiness-checks) if you do not yet know which part is wrong.

## Readiness checks

Run these three before diagnosing anything specific. Each one answers a different question.

```bash
# 1. Which optional subsystems does this server actually serve?
curl -s -H "Authorization: Bearer $SYNAPSE_API_TOKEN" \
  http://localhost:8080/api/v1/capabilities | jq -r '.[] | "\(.enabled)\t\(.name)"'

# 2. Can this host run the sandbox and reach the network under it?
synapse-cli doctor .

# 3. Is the server serving at all, and under which identity?
curl -s http://localhost:8080/healthz
```

`capabilities` is the authority on what is switched on. A screen that renders is not proof the
feature behind it is reachable: several surfaces render their own "switched off" state, and one
of them used to name an environment variable that had nothing to do with it. When a feature is
missing, read this list first and believe it over the screen.

## Scanning

### The Supply Chain tab is empty, or the scan says "no recognized dependency manifests"

The target has a manifest (`package.json`, `composer.json`, `Gemfile`, `pyproject.toml`) but no
committed lockfile. A manifest alone declares version ranges, so there is nothing to pin and
nothing to match against advisories. Synapse resolves it by running the ecosystem's own lock tool
over a throwaway copy, and that step reaches the registry, so it only works when the sandbox can
open an egress namespace.

Confirm which step failed and why:

```bash
curl -s -H "Authorization: Bearer $SYNAPSE_API_TOKEN" \
  "http://localhost:8080/api/v1/engagements/$ENGAGEMENT/scan-status" \
| jq -r '.debug_events[] | "\(.step)\t\(.status)\t\(.message)\t\(.counts)"'
```

A healthy resolve reads `npm-resolve  succeeded  npm dependency tree resolved  {"components":1171,"edges":733}`.
The failures to expect, in the order they are most common:

| What the step says | Cause | Fix |
| --- | --- | --- |
| `spec carries an egress policy but egress enforcement is not configured` | the process has no egress applier, usually because it lacks `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` | run the execution tier with those capabilities, or accept that only lockfile-bearing targets resolve |
| `egress setup … ip_forward` | `net.ipv4.ip_forward` is `0` | `sudo sysctl -w net.ipv4.ip_forward=1`, and persist it in `/etc/sysctl.d/` |
| `npm resolve: no package-lock.json produced` | the lock tool ran and failed, usually no route to the registry | check the egress allow-list covers the registry host |
| the step is absent entirely | the resolver is not enabled | set `SYNAPSE_NPM_RESOLVE_ENABLED=true` (and the equivalent for other ecosystems) |

A resolved scan should also carry dependency **edges**, not only components. With zero edges every
vulnerability is reported as transitive with no path to a direct dependency, which is legal output
but much less useful:

```bash
curl -s -H "Authorization: Bearer $SYNAPSE_API_TOKEN" \
  "http://localhost:8080/api/v1/engagements/$ENGAGEMENT/scan" \
| jq '{components: (.sbom.Components|length), edges: (.sbom.Dependencies|length),
       with_path: ([.vulnerabilities[]|select(.Path)]|length)}'
```

### Starting a scan returns 409 conflict, and it never stops

One scan may run per engagement, enforced by a partial unique index
(`scan_jobs_one_running_per_engagement`). A scan the API was running in-process dies with the
process, and its row stays `running`, so every later scan is rejected. There is no route to cancel
a scan.

```bash
psql "$SYNAPSE_DB_DSN" -c \
  "SELECT id, status, stage, progress, started_at FROM scan_jobs WHERE status = 'running';"
```

The stale-scan sweeper reclaims a row whose run lease is free and whose start is older than
`SYNAPSE_SCAN_TIMEOUT + 5m`, and it ticks every five minutes on any PostgreSQL deployment. Waiting
is the supported fix. If you must not wait, finalize the row by hand and record why:

```sql
UPDATE scan_jobs
   SET status = 'failed', stage = 'stranded', error = 'reclaimed by operator', finished_at = now()
 WHERE id = '<the stranded id>';
```

Do not delete the row. The scan's evidence is chained to it.

### A scan times out part-way through

`SYNAPSE_SCAN_TIMEOUT` bounds the whole pipeline, and the default is generous for a small
repository and short for a large one. On a large JavaScript application the `derive-findings` step
alone can take six minutes. Raise the timeout rather than the memory limit first: an out-of-memory
kill reads differently in the step trace (the step disappears rather than reporting a deadline).

Change one variable at a time. Raising the timeout, the sandbox memory cap and the pid cap together
makes the next failure impossible to attribute.

## Recon and the sandbox

### Enabling live recon is refused

Live recon is the moment execution against a real target becomes possible, so a boolean is not
enough: the request must re-confirm the acceptable-use policy version and record a
lab-authorization attestation, both of which are written to the append-only audit log.

```bash
curl -s -X PUT -H "Authorization: Bearer $SYNAPSE_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"enabled":true,
       "aup_version":"1.0",
       "attestation":"Written authorization on file for 203.0.113.0/24, ref TICKET-1234."}' \
  "http://localhost:8080/api/v1/engagements/$ENGAGEMENT/live-recon"
```

Without `aup_version` the server answers `400 enabling live recon requires re-confirming the AUP
version`; disabling needs neither field. The target must also be in the engagement's scope and
inside its authorization window, both checked server-side before any tool runs.

### A recon run fails with `ip netns attach … No such file or directory`

The message names the symptom: the sandbox process was gone by the time the broker attached its
network namespace. The cause is on the line the sandbox wrote to stderr before it died, which the
run error now carries after the step that failed. Read the whole error:

```bash
curl -s -H "Authorization: Bearer $SYNAPSE_API_TOKEN" \
  "http://localhost:8080/api/v1/engagements/$ENGAGEMENT/recon/runs" | jq -r '.[0].error'
```

The most common cause is where the tool binary lives:

```
bwrap: Can't find source path /home/ubuntu/go/bin/httpx: Permission denied
```

`make tools RECON=1` installs through `go install`, which writes to `$(go env GOPATH)/bin`, usually
under a home directory. A home directory is mode `0750` on current Ubuntu, and the sandbox drops
privileges into a user namespace before it binds anything, so it cannot traverse the path. Put the
recon binaries somewhere the sandbox's read-only root already covers:

```bash
sudo cp "$(go env GOPATH)/bin/httpx" "$(go env GOPATH)/bin/subfinder" /usr/local/bin/
# and make sure /usr/local/bin precedes $GOPATH/bin on the server's PATH
```

The curated root binds `/usr`, `/bin`, `/sbin`, `/lib` and `/lib64` read-only and deliberately omits
`/home`, `/root`, `/opt`, `/var` and `/srv`, so host credentials are absent rather than merely
unreadable. A binary outside that set is bound as a single file when its path is absolute; it is
still subject to the permissions on every directory above it.

### Egress enforcement looks configured and nothing is reachable

The applier builds the namespace, the veth pair, the masquerade rule and the forward accepts
without needing `net.ipv4.ip_forward`, and with forwarding off the kernel silently drops every
packet crossing the veth. A destination the policy allowed is then exactly as unreachable as one it
denied, and the scan blames the target.

```bash
cat /proc/sys/net/ipv4/ip_forward     # must be 1
sudo sysctl -w net.ipv4.ip_forward=1
```

The probe refuses and names the setting rather than degrading silently, so a host in this state
reports the sandbox as unusable instead of pretending to enforce.

### `timeout` inside the sandbox does not bound anything, or a tool cannot fork

Both are seccomp allowlist gaps and both are fixed; they are recorded here because the symptoms are
confusing enough to send you looking elsewhere.

- GNU `timeout` has only `timer_create` and `alarm`. With both denied it printed one warning and
  returned success after the full duration, so a tool relying on it silently lost its bound.
- glibc issues `vfork` as its own syscall rather than routing it through `clone`. With `vfork`
  denied, a shell could run `echo x | cat` (a pipeline, which forks) but not `/bin/true` (a simple
  command, which vforks), so every tool that shells out failed with "Cannot fork".

If you see either on a build of your own, compare `internal/infrastructure/sandbox/seccomp_linux_amd64.go`
against the syscalls your libc uses.

### Sandbox resource limits are not applied

The runner puts each run in a delegated cgroup when it has one, and falls back to
`systemd-run --scope` when it does not. Neither exists when the process has no cgroup delegation at
all, and then `SYNAPSE_SANDBOX_MEM_MAX` and `SYNAPSE_SANDBOX_PIDS_MAX` have nothing to act on.

Run the execution tier as a systemd unit, or under `systemd-run --user`, so a delegated subtree
exists. In a container, the cgroup namespace must be delegated to it; most default container
runtimes do not.

## Database and startup

### The server refuses to start: "the DB role cannot enforce row level security"

Tenant isolation is enforced by PostgreSQL row-level security, and a superuser bypasses RLS
entirely. Serving tenant data as a role that cannot be constrained would make the isolation
decorative, so the server refuses rather than starting in that state.

Give the application its own role and keep the owner credential for migrations only:

```sql
CREATE ROLE synapse_app LOGIN PASSWORD '…' NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO synapse_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO synapse_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO synapse_app;
```

Then point `SYNAPSE_DB_DSN` at `synapse_app` and `SYNAPSE_DB_MIGRATION_DSN` at the owner.
`SYNAPSE_DB_HALT_WRITER_DSN`, when used, needs the same treatment.

### A down-migration refuses, or the PostgreSQL suite fails only on a second run

Migration 0085 refuses to roll back while any `audit_log` row carries `hash_version = 2`, because
rolling back would drop the column those rows depend on. A test fixture that leaves such a row
behind therefore breaks every down-migration test that runs after it, and only on the second pass
over the same database, which is exactly what CI does.

The audit log is append-only, enforced by a trigger, so an ordinary `DELETE` is rejected. A fixture
that must clean up suspends the trigger on its own connection and restores it:

```sql
SET session_replication_role = replica;
DELETE FROM audit_log WHERE tenant_id = '…';
SET session_replication_role = origin;
```

Never discard the error from that delete. A cleanup that silently stops working is what makes this
invisible until CI's second pass.

## Dashboard

### A tab reports its feature as switched off

Read `/api/v1/capabilities` first; it is the authority. Two cases are worth calling out because the
screen alone is misleading:

- **Data governance** (legal hold, subject-access export, erasure) rides the detection ledger,
  because its projection is the data being governed. It needs `SYNAPSE_FLEET_ENABLED=true` and
  `SYNAPSE_FLEET_DETECTION_INGEST_ENABLED=true`.
- **Cloud posture** and **OIDC browser login** are off by default and each needs its own
  configuration; see [configuration](configuration.md).

### A Code Quality project shows "No completed analysis yet" and an analysis exists

A project bound to a local path has no source ref, so its analyses are recorded under an empty
branch. Confirm the analysis is there and which branch it is on:

```bash
curl -s -H "Authorization: Bearer $SYNAPSE_API_TOKEN" \
  http://localhost:8080/api/v1/projects/$KEY/analyses | jq '.items[0] | {id, created_at, origin}'
curl -s -H "Authorization: Bearer $SYNAPSE_API_TOKEN" \
  http://localhost:8080/api/v1/projects/$KEY/branches
```

A branch list holding a single entry whose name is empty is the local-binding case, and the screen
shows it as "no branch". If the screen still asks you to run the first analysis, the request is
being made for a branch that has none; check the `branch` query parameter in the URL.

### An engagement screen is slow to open

One engagement's scan result is a single response, and on an application with a thousand resolved
components it is measured in megabytes. Every fresh page load fetches it once; switching tabs
inside the engagement does not refetch it. Over a slow link the first paint waits for that
response, which is worth knowing before you go looking for a server problem.

## Reporting something that is not here

Collect these four before opening an issue. Together they are usually enough to reproduce:

1. `GET /api/v1/capabilities` output.
2. The failing scan or run's full record, including `debug_events` for a scan and `error` for a run.
3. `synapse-cli doctor . --json` from the host that executes.
4. The server log lines around the failure, which carry the request id the API returned.
