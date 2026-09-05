# Fleet and runtime defense

[Documentation home](README.md) · Previous: [Cloud posture](cloud-posture.md) · Next: [AI triage review](ai-triage-review.md)

The fleet is Synapse's distributed blue-team layer. Agents inventory hosts and Kubernetes clusters, run
eBPF detections, and execute authorized work orders. A runtime detection is treated as evidence rather
than an alert: it is attributable, hash-chained, and joined to the same asset, finding, and attack path the
static pillars reason about.

The fleet is off by default and needs PostgreSQL plus `synapse-worker`. The development Compose stack does not enable fleet routes or run the worker, so `/fleet` shows an error there rather than representative coverage data. Capture a Fleet screenshot only from a deployment with the fleet flags, worker, enrolled demo agents, and sanitized inventory configured; do not publish an error state as product documentation.

```bash
SYNAPSE_FLEET_ENABLED=true                      # transport + agent-admin routes
SYNAPSE_FLEET_ASSETS_ENABLED=true               # asset model + attack paths
SYNAPSE_FLEET_HOST_INGEST_ENABLED=true          # accept host inventory
SYNAPSE_FLEET_CLUSTER_INGEST_ENABLED=true       # accept Kubernetes inventory
SYNAPSE_FLEET_KEY_REGISTRATION_ENABLED=true     # register purpose-bound agent signing keys
SYNAPSE_FLEET_DETECTION_INGEST_ENABLED=true     # independently signed P1 detection delivery
SYNAPSE_FLEET_TELEMETRY_INGEST_ENABLED=true     # signed raw telemetry + durable-gap transport
```

Telemetry transport needs the fleet transport plus key registration. Keep the telemetry ingest flag off if
the deployment has not applied the telemetry migrations; the server otherwise fails closed when the
required persistence or signing-key trust boundary is unavailable. Signed detection delivery similarly
requires both key registration and detection ingest to be enabled.

## Agents

| Binary | Runs on | Collects |
| --- | --- | --- |
| `synapse-agent` | Linux, macOS, and Windows hosts | Host inventory and, on Linux, eBPF runtime detections |
| `synapse-cluster-agent` | In-cluster or with a kubeconfig | Kubernetes workload, exposure, and identity inventory |

eBPF detection needs Linux with root or the equivalent capabilities. On other platforms the detection
engine stays off rather than degrading silently.

## Enrollment and identity

An agent enrolls once with a one-time token, then holds a client certificate:

```
POST /api/v1/agents/enrolment-tokens     mint a one-time token
POST /api/v1/fleet/enrol                  agent redeems it
POST /api/v1/agents/{id}/revoke           revoke an identity
```

```bash
# preferred: a root-readable token file, removed after first enrolment
export SYNAPSE_FLEET_URL="https://synapse.example.com"
export SYNAPSE_FLEET_ENROL_TOKEN_FILE=/run/secrets/synapse-enrol-token
./synapse-agent
```

Prefer the token file over `SYNAPSE_FLEET_ENROL_TOKEN`, and never use the equivalent command-line flag in
production: an argument is visible in process listings and shell history. After enrollment the agent
authenticates with its certificate and the token is no longer needed.

Certificate issuance requires `SYNAPSE_FLEET_CA_CERT` and `SYNAPSE_FLEET_CA_KEY`; treat the CA key as a
production secret. `SYNAPSE_FLEET_CERT_TTL` (default `24h`) bounds certificate lifetime.

Set `SYNAPSE_FLEET_CLIENT_CERT_HEADER` **only** behind a reverse proxy that terminates mTLS, verifies the
client certificate, and strips every client-supplied copy of that header before setting it. A proxy that
forwards an unverified header converts this into an authentication bypass.

HTTPS is required for the fleet URL except for a loopback host in development.

## Agent lifecycle

| State | Meaning |
| --- | --- |
| `active` | Enrolled and reporting within the freshness window |
| `stale` | Last seen longer ago than `SYNAPSE_FLEET_STALE_AFTER`; computed by coverage, not self-reported |
| `revoked` | Identity withdrawn by an operator |
| `compromised` | Marked untrusted; its recent reports are suspect |
| `tampered` | Reported state failed integrity checks |
| `decommissioned` | Cleanly uninstalled and retired |

`stale` is derived rather than declared, so an agent that stops reporting cannot appear healthy. Retire an
agent explicitly so its absence is a recorded decision instead of an unexplained gap:

```
POST /api/v1/fleet/decommission
```

## Inventory and heartbeat

```
POST /api/v1/fleet/heartbeat              liveness plus agent-reported state
POST /api/v1/fleet/inventory/host         host inventory snapshot
POST /api/v1/fleet/inventory/cluster      Kubernetes inventory snapshot
GET  /api/v1/fleet/agents                 operator view
GET  /api/v1/fleet/agents/{id}
```

Configure a host agent with `SYNAPSE_AGENT_ROOT` (filesystem root to inventory), `SYNAPSE_AGENT_NAME`, and
`SYNAPSE_AGENT_STATE_DIR`. Protect the state directory: it holds the agent credential and offline buffer,
including the telemetry WAL under `telemetry-spool/`.

The cluster agent requires `SYNAPSE_CLUSTER` as a stable identity keyed into every asset, and accepts
`SYNAPSE_CLUSTER_NAMESPACES` to narrow scope and `SYNAPSE_CLUSTER_RESYNC` (default `5m`) to set the
collection interval.

## Host vulnerabilities

A host agent reports the installed OS packages (dpkg, apk, rpm) with distro-qualified package URLs in
every inventory snapshot. The control plane records that list as the host's SBOM in a hidden per-host
engagement (the fleet twin of a Project's analysis context) and runs the SCA imported-SBOM pipeline
against it: the same advisory sources, OS version comparison, severity backfill, KEV/EPSS risk
ranking and deduplication a repository or image scan gets. Findings are re-evaluated by the
vulnerability reconciliation job when advisories change, so a host that never changes still picks up
new CVEs.

Recording is idempotent per package set. An unchanged host does not re-import or re-scan on its next
sweep; a changed set is recorded once the previous scan has finished, and at most once per ten
minutes per host. An inventory above 50,000 packages is refused, and one agent identity may create at
most 16 host assets (a reimaged machine gets a new machine id; an agent varying its facts does not get
unbounded hosts, contexts and scans). The cap is checked before the write and enforced again inside
it: a `fleet_assets` trigger (migration 0132) serialises new host rows per agent and refuses the row
past the cap, so two syncs racing past the first check cannot both create a host. A refusal is audited
as `host_inventory.host_cap_reached` and returned as 403. The `POST /api/v1/fleet/inventory/host` response carries a
`vulnerability_scan` object with the outcome (`engagement_id`, `job_id`, `components`, or `skipped`
with a `reason`). A scan-pipeline failure is audited as `host_inventory.vulnerability_scan_failed` and
reported in that object; it never fails the inventory sync itself. The host asset's attributes carry the
coverage gaps the agent declared (`coverage_gaps`, `coverage_gap_kinds`, `coverage_gap_details`), and
the host page's Coverage gaps tab lists them with what each one means for the findings. The advisory-revision reconciler
visits host contexts alongside projects, so a host whose packages never change still gains a finding
when a new advisory names one of them.

```
GET /api/v1/assets/hosts                          every host with its vulnerability summary
GET /api/v1/assets/{assetID}/vulnerabilities      one host: packages, latest scan, findings
```

The console lists hosts under Fleet, Hosts, worst first, and opens each host to its findings with
package, installed and fixed version, severity, CVSS and KEV. The hidden context does not appear in
the engagement list and is not reachable through the engagement routes.

## Detections

```bash
SYNAPSE_DETECT_CLASSES=process,network,file,privilege
SYNAPSE_DETECT_CPU_CEIL_PCT=25
SYNAPSE_DETECTION_ENGAGEMENT_ID=engagement-id
```

An empty class list disables the engine. When CPU exceeds the ceiling, classes are shed in a defined order
rather than dropped arbitrarily, and a shed class is recorded so coverage stays honest. Detections surface
per engagement:

```
GET /api/v1/engagements/{id}/detections
```

When `SYNAPSE_DETECTION_ENGAGEMENT_ID` is set, the agent generates a purpose-bound Ed25519 key,
persists the private half as `detection-transport.json` under the protected state directory, proves
possession to `POST /api/v1/fleet/keys`, and drains P1 independently to
`POST /api/v1/fleet/detections`. Enable both `SYNAPSE_FLEET_KEY_REGISTRATION_ENABLED=true` and
`SYNAPSE_FLEET_DETECTION_INGEST_ENABLED=true` on the control plane. The server derives the agent
identity from its credential, resolves the named key, verifies every content digest and signature,
then seals each detection exactly once.

A pending batch coordinate, membership, and engagement attribution are written before the network
request. If the agent restarts or loses the HTTP response, it retries the same sequence and membership;
the control plane idempotently skips what was already sealed. Changing the configured engagement while
a batch is pending fails closed instead of re-attributing it. The local P1 WAL is ACKed only after a
complete 2xx response, and per-epoch ACK history lets a reboot finish committing a batch whose WAL
records were already reclaimed. Keys rotate before expiry, and one `403` causes one new key registration
plus a retry of the same pending sequence. A second rejection stops that delivery lane instead of
generating keys indefinitely; the raw telemetry and durable-gap workers remain independent.

### Rate rules

A rule matches per event or per burst. A windowed rule (`Window{Count, Within, GroupBy}`) counts the
events its predicates match inside a sliding span, partitioned by the grouped fields, and fires once when
the count is reached; the detection carries the burst as evidence (the last 64 events when it is longer)
and the count restarts. `det.suspicious_dns_beacon` v2 is the first: 120 outbound DNS datagrams to one
destination inside a minute, grouped by `net.remote_addr`. v1 fired on every DNS packet, which is name
resolution, not beaconing. The same evaluator replays stored telemetry in retro hunts and release
evidence, so a windowed rule fires on the same bursts offline as it does live. Per rule the evaluator
tracks at most 1024 groups and evicts the stalest, so a sensor's memory stays bounded whatever an
attacker varies.

### Durable telemetry spool

Before the detection engine evaluates an eBPF event, the agent normalizes it to the canonical telemetry
envelope and appends it to a checksummed priority WAL. Confirmed detections enter the same spool at P1.
The shared WAL has four priority lanes; dedicated transports select only the lanes they own so one busy
lane cannot consume another transport's read budget:

| Priority | Signals | Disk-pressure behavior |
| --- | --- | --- |
| P0 | response verification, coverage, sensor state | never shed; producer backpressure plus a durable gap record |
| P1 | confirmed detections | never shed; independently signed detection delivery when an engagement is configured |
| P2 | privilege changes and critical-file telemetry | never shed; A3 raw telemetry delivery |
| P3 | background process and network telemetry | oldest P3 segment evicted first, only after its loss is durably journaled; A3 raw telemetry delivery |

`SYNAPSE_TELEMETRY_SPOOL_BYTES` sets the WAL-segment quota (default 512 MiB). The small state and gap
journals are outside that quota so a full data allocation cannot prevent the agent recording why data
was not retained. A restart reads both state generations, validates CRC32C frames, removes ACKed bytes,
repairs corrupt/torn segments, and continues the current `(priority, epoch, sequence)` coordinate. A
kernel reboot changes the Linux boot UUID, advances the epoch, and safely restarts sequence at one.

The WAL is the A2 durability boundary. Confirmed P1 detections have their own signed shipper when an
engagement is configured. A3 independently drains raw P2/P3 telemetry into signed transport batches and
ships the durable gap journal. Each worker owns only its lane/state and retains WAL on terminal failure,
so a rejected detection batch cannot silently delete or stop unrelated raw telemetry evidence.

Set `SYNAPSE_AGENT_METRICS_ADDR=127.0.0.1:9465` to expose `/metrics`. This listener is deliberately off
by default and has no authentication. Exported series have bounded labels (priority only):

- `synapse_agent_spool_records` and `synapse_agent_spool_record_bytes`
- `synapse_agent_spool_oldest_unacked_age_seconds`
- `synapse_agent_spool_next_sequence` and `synapse_agent_spool_highest_acked_sequence`
- `synapse_agent_spool_gap_records` and `synapse_agent_spool_gap_bytes`
- `synapse_agent_spool_evicted_records_total`
- `synapse_agent_spool_corruption_events_total`
- `synapse_agent_spool_fsync_total` and `synapse_agent_spool_fsync_duration_seconds_total`

## Alerting

Set `SYNAPSE_ALERT_WEBHOOK_URL` and the control plane posts a signed JSON alert to that URL every time
correlation opens an incident. Correlation itself runs after every detection batch that seals new
detections, off the agent's request, one run per engagement at a time (batches that arrive during a run
are folded into a single rerun), and on demand through `POST /api/v1/fleet/engagements/{id}/correlate`;
detections completed later by provenance reconciliation are correlated the same way. So with
`SYNAPSE_FLEET_DETECTION_INGEST_ENABLED`, `SYNAPSE_FLEET_CORRELATION_ENABLED` and a webhook set, a
detection on an agent becomes an incident and a notification without anyone calling an endpoint.

```bash
SYNAPSE_ALERT_WEBHOOK_URL=https://hooks.example.com/synapse
SYNAPSE_ALERT_WEBHOOK_SECRET=$(openssl rand -hex 24)     # optional; >= 16 bytes
SYNAPSE_ALERT_MIN_SEVERITY=medium                        # critical | high | medium | low | info
```

The body is `{"type": "incident.created", "sent_at": ..., "alert": {...}}` with the incident id, asset,
engagement, severity, title, a short summary and a console link (`/fleet/incidents/{id}`). It carries no
raw telemetry. With a secret set, `X-Synapse-Signature` is `sha256=<hex HMAC-SHA256>` over
`<X-Synapse-Timestamp>.<body>`; verify it and reject stale timestamps. Transient failures (network, 429,
5xx) are retried three times; a 4xx is final. Every attempt is audited as `alert.delivered` or
`alert.failed` with the sink and the error (the error never carries the webhook URL, whose path is the
credential for many chat hooks), so a missed page is in the audit log. Delivery runs on a bounded
worker set off the ingest path, so a slow receiver never holds an agent's request. A tenant is limited
to 60 delivered alerts per minute; the excess is audited as `alert.suppressed`, and a full queue as
`alert.dropped`. Delivery never blocks or rolls back the incident it reports.

`POST /api/v1/alerts/test` (administer) sends an `alert.test` alert that bypasses the severity floor and
returns how many sinks acknowledged it; use it after configuring the receiver. The webhook client refuses
private and link-local destinations unless `SYNAPSE_ALERT_WEBHOOK_ALLOW_PRIVATE=true`; `http` is accepted
only for a loopback receiver in development.

## Coverage

```
GET /api/v1/fleet/coverage
GET /api/v1/fleet/coverage/summary
GET /api/v1/fleet/coverage/export
```

Coverage answers what the fleet can actually see. It reports stale agents, missing classes, and shed
telemetry instead of implying complete visibility. `SYNAPSE_FLEET_COVERAGE_FRESHNESS_TARGET` (default
`24h`) sets the freshness objective.

## Work orders

```
POST /api/v1/fleet/work/claim
POST /api/v1/fleet/work/{id}/progress
POST /api/v1/fleet/work/{id}/result
```

Agents claim signed work, report progress, then report a result. The lifecycle is
`issued` → `claimed` → `running` → `succeeded` | `failed` | `refused` | `cancelled` | `expired`. An agent
that declines work records `refused` rather than failing quietly. Bound server-side dispatch with
`SYNAPSE_AGENT_CONCURRENCY`, `SYNAPSE_AGENT_QUEUE_DEPTH`, `SYNAPSE_AGENT_MAX_PARALLEL`, and
`SYNAPSE_AGENT_RECON_CONCURRENCY`.

Response actions are governed, reversible, and audited. They run through the same scope and authorization
enforcement as any other execution.

Wire the routes and a defender can drive the full loop: `POST /api/v1/blueteam/engagements/{id}/response/plan`
dry-runs an action (isolate_host, quarantine_file, stop_process) and its mandatory reversal and executes
nothing; `.../response/apply` applies it through the shared admission gate (server-side scope
authorization, a recorded human approver, a blast-radius check on the executed effect); `POST
/api/v1/blueteam/response/{id}/revert` reverses it; `GET /api/v1/blueteam/response` lists the
admitted-but-not-applied set the kill switch cancels. The action id is server-minted, and a second-approval
requirement answers 202. The default executor records the full admission -> approval -> apply -> verify ->
revert ledger without touching a host; a real host executor is a deliberate, review-gated extension point
(`internal/usecase/response/simulation.go`), so applying a real isolation still requires an explicit
execution-safety decision the platform does not make on its own. The `POST /api/v1/redteam/halt` kill switch
now cancels pending response actions as a fourth layer, so one operator action stops the whole estate.

## Rollout and upgrades

```
GET  /api/v1/agents/rollout
PUT  /api/v1/agents/rollout
POST /api/v1/agents/rollout/promote
POST /api/v1/agents/rollout/pause
POST /api/v1/agents/rollout/resume
```

A rollout advances in stages and can be paused or resumed. `SYNAPSE_FLEET_MIN_AGENT_VERSION` sets a version
floor and rejects agents below it; empty means no floor.

Self-update artifacts are verified against a built-in Ed25519 release key before any binary is swapped.
`SYNAPSE_UPDATE_PUBLIC_KEY` overrides that key and should only be used for a controlled private release
channel. Rotating the update key is asymmetric: already-deployed agents reject a new key until they receive
it, so ship the new public key in a release signed by the old one first.

For packaging, service integration, and uninstall contracts, see
[Fleet agent packaging](fleet-agent-packaging.md).

## Telemetry transport

Raw telemetry is deliberately isolated behind persistence ports so the finding, judgment, and evidence
paths never wait on a high-volume store. `ports.TelemetrySpool` is the agent-side WAL boundary;
`ports.TelemetryStore` is the control-plane columnar boundary; the A3 transport store owns delivery
sequence commitments, highest-contiguous ACK state, and persisted coverage gaps.

With `SYNAPSE_FLEET_KEY_REGISTRATION_ENABLED=true` and
`SYNAPSE_FLEET_TELEMETRY_INGEST_ENABLED=true`, the host agent registers a persisted purpose-bound Ed25519
key and drains recovered raw P2/P3 telemetry without requiring the detection producer to be running. The
P1 detection lane remains owned by the independent detection shipper described above. The agent rotates
the telemetry signing key before expiry and retries transient registration failures instead of disabling
transport until restart.

```
POST /api/v1/fleet/keys       register the purpose=telemetry-batch public key + proof of possession
POST /api/v1/fleet/telemetry  signed telemetry batch or signed durable-gap report
```

Normal batches use JSON (gzip on the wire). Durable spool-gap reports use the same authenticated endpoint
with `Content-Type: application/vnd.synapse.telemetry-gap+json`; their Ed25519 commitment is domain-separated
from batch signatures. The control plane treats the authenticated fleet principal and its reconciled host
asset as authoritative: supplied agent, host, session, asset, stream, key ID, schema version, and signature
must all pass validation before persistence. Unsupported schema versions and identity/signature failures
fail closed and are audited.

Batch ingest is idempotent per stream incarnation and sequence. A reboot advances the epoch, so a legitimate
reset to sequence one is distinct from replay. The response ACK is the highest sequence with no missing
predecessor; received sequences above a hole are durable but cannot advance deletion past the hole.

The server persists two different forms of coverage evidence:

- inferred delivery gaps, which close only when their missing sequence range actually arrives;
- agent-origin spool gaps (quota eviction, backpressure, corruption, torn writes, I/O failure, unsynced tail,
  or state recovery), which are immutable loss provenance and are **not** resolved by a later delivery ACK.

Retro-hunt coverage reads both sources. Any overlapping open delivery hole or agent-origin loss makes the
window incomplete instead of silently returning `Complete=true`. Agent-origin gaps survive server restart
and are tenant-isolated by PostgreSQL RLS.

Network errors, HTTP 429, and 5xx responses retain the local WAL/gap journal and retry with bounded backoff;
`Retry-After` is honored when present. Terminal 4xx responses retain the durable local evidence but stop the
transport loop rather than hot-looping a request the server has rejected.

The retention, sampling, and ingest-budget behavior described in the
[telemetry store ADR](repository/telemetry-store-adr.md) remains the columnar-tier contract; A3 adds the
live signed delivery path and the coverage-honesty bridge into that tier without changing A5's permanent
evidence/Merkle scope.

## Purple coverage

Emulation expectations are compared against observed detections, so a missing detection is reported as a
coverage gap. See [Governed assessments](governed-assessment-workflows.md#purple-coverage).

Next: [AI triage review](ai-triage-review.md)
