# Fleet and runtime defense

[Documentation home](README.md) · Previous: [Cloud posture](cloud-posture.md) · Next: [AI triage review](ai-triage-review.md)

The fleet is Synapse's distributed blue-team layer. Agents inventory hosts and Kubernetes clusters, run
eBPF detections, and execute authorized work orders. A runtime detection is treated as evidence rather
than an alert: it is attributable, hash-chained, and joined to the same asset, finding, and attack path the
static pillars reason about.

The fleet is off by default and needs PostgreSQL plus `synapse-worker`. The development Compose stack does not enable fleet routes or run the worker, so `/fleet` shows an error there rather than representative coverage data. Capture a Fleet screenshot only from a deployment with the fleet flags, worker, enrolled demo agents, and sanitized inventory configured; do not publish an error state as product documentation.

```bash
SYNAPSE_FLEET_ENABLED=true                # transport + agent-admin routes
SYNAPSE_FLEET_ASSETS_ENABLED=true         # asset model + attack paths
SYNAPSE_FLEET_HOST_INGEST_ENABLED=true    # accept host inventory
SYNAPSE_FLEET_CLUSTER_INGEST_ENABLED=true # accept Kubernetes inventory
```

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
a batch is pending fails closed instead of re-attributing it. The local WAL is ACKed only after a
complete 2xx response, and its per-epoch ACK history lets a reboot finish committing a batch whose WAL
records were already reclaimed. Keys rotate before expiry, and one `403` causes one new key registration
plus a retry of the same pending sequence. A second rejection stops delivery instead of generating keys
indefinitely.

### Durable telemetry spool

Before the detection engine evaluates an eBPF event, the agent normalizes it to the canonical telemetry
envelope and appends it to a checksummed priority WAL. Confirmed detections enter the same spool at P1.
The four lanes drain in P0 → P3 order:

| Priority | Signals | Disk-pressure behavior |
| --- | --- | --- |
| P0 | response verification, coverage, sensor state | never shed; producer backpressure plus a durable gap record |
| P1 | confirmed detections | never shed; producer backpressure plus a durable gap record |
| P2 | privilege changes and critical-file telemetry | never shed; producer backpressure plus a durable gap record |
| P3 | background process and network telemetry | oldest P3 segment evicted first, only after its exact sequence gap is fsynced |

`SYNAPSE_TELEMETRY_SPOOL_BYTES` sets the WAL-segment quota (default 512 MiB). The small state and gap
journals are outside that quota so a full data allocation cannot prevent the agent recording why data
was not retained. A restart reads both state generations, validates CRC32C frames, removes ACKed bytes,
repairs corrupt/torn segments, and continues the current `(priority, epoch, sequence)` coordinate. A
kernel reboot changes the Linux boot UUID, advances the epoch, and safely restarts sequence at one.

The WAL is the A2 durability boundary. Confirmed P1 detections have their own signed shipper when an
engagement is configured; the remaining raw-telemetry drain belongs to A3. Until that transport is
enabled, P3 rotates within the configured quota while P0/P2 can eventually backpressure. Operators
should therefore size the quota for the expected disconnected interval.

Set `SYNAPSE_AGENT_METRICS_ADDR=127.0.0.1:9465` to expose `/metrics`. This listener is deliberately off
by default and has no authentication. Exported series have bounded labels (priority only):

- `synapse_agent_spool_records` and `synapse_agent_spool_record_bytes`
- `synapse_agent_spool_oldest_unacked_age_seconds`
- `synapse_agent_spool_next_sequence` and `synapse_agent_spool_highest_acked_sequence`
- `synapse_agent_spool_gap_records` and `synapse_agent_spool_gap_bytes`
- `synapse_agent_spool_evicted_records_total`
- `synapse_agent_spool_corruption_events_total`
- `synapse_agent_spool_fsync_total` and `synapse_agent_spool_fsync_duration_seconds_total`

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

## Telemetry

Raw telemetry is deliberately isolated behind persistence ports so the finding, judgment, and evidence
paths never wait on a high-volume store. `ports.TelemetrySpool` is the agent-side WAL boundary;
`ports.TelemetryStore` is the control-plane columnar boundary. Architecture tests keep both concrete
stores out of domain packages.

The retention, sampling, and ingest-budget behavior described in the
[telemetry store ADR](repository/telemetry-store-adr.md) is the accepted design, but the operator
configuration for the control-plane tier is **not wired yet**. Agent-side durability and its quota are
wired as described above; A3 still owns transmission from that WAL to the existing columnar ingest.

## Purple coverage

Emulation expectations are compared against observed detections, so a missing detection is reported as a
coverage gap. See [Governed assessments](governed-assessment-workflows.md#purple-coverage).

Next: [AI triage review](ai-triage-review.md)
