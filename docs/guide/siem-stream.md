# SIEM streams

Synapse can export committed audit events and incident events to Splunk HEC,
Elasticsearch, syslog RFC 5424 over TLS, or Microsoft Sentinel. The stream is
separate from notification delivery. One bad destination does not decide
another tenant's cursor.

## What is exported

- Tenant audit rows on the v2 hash chain, from genesis unless an operator
  explicitly starts a new generation at the current head.
- Incident events captured in the same transaction as the append. A historical
  backfill uses a separate cursor and is not described as happening before the
  live stream.
- Legacy v1 audit rows are not part of the tenant chain. The status page says
  so. They are not marked verified.

Audit row ids are not a gap when they skip. Other tenants and rolled-back
inserts leave holes. A row whose previous hash does not match the cursor stops
that partition. Nothing is skipped automatically.

## Delivery

Export is at least once. A worker can crash after the destination accepts a
batch and before Synapse stores that result. The next attempt sends the batch
again. Record ids stay stable so the destination can collapse duplicates.
Splunk is not exactly once.

Splunk HTTP 200 is not enough. The HEC code must be success. Indexer
acknowledgement is used only when the sink is configured for it. Splunk Cloud
does not provide indexer acknowledgement; leave that mode off there. An
acknowledgement can expire or be lost, and it does not prove the event is
searchable.
The HEC receipt is stored in the open batch before polling. Later ticks,
including after a worker restart, poll the same receipt without another POST.
A crash between HEC acceptance and storing the receipt can still cause a
duplicate POST. After eight unsuccessful polls, the sink blocks for an
operator; resume continues polling the stored receipt.

Elasticsearch bulk responses are read item by item. The cursor moves only
through the contiguous successful prefix. HTTP 409 is not treated as proof
that the current document was stored. The target is one normal index, not a
data stream.

Syslog uses RFC 5424 messages with the RFC 5425 octet-counted TLS framing.
Each completed frame write advances the contiguous prefix, but syslog has no
application-level acknowledgement: a disconnect after a collector accepts a
frame can cause that frame to be replayed. The stable syslog `MSGID` lets a
collector correlate those duplicates; it is not proof that the collector has
indexed the record.


Microsoft Sentinel uses the Azure Monitor Logs Ingestion API for Azure public
cloud. Set the origin to the DCR direct-ingestion endpoint from a DCR created
with `kind: Direct`, or to a DCE whose logs-ingestion endpoint is publicly
reachable. The origin must be under `*.ingest.monitor.azure.com` on HTTPS
port 443. Private Link DCEs are not supported by this sink because outbound
SIEM dialing rejects private network addresses.

Set the target to `dcr-<immutable-id>/Custom-<stream>`. Azure Monitor custom
stream declarations must start with `Custom-`. The sealed credential is a
one-line JSON object with `tenant_id`, `client_id`, and `client_secret`;
the application needs the Monitoring Metrics Publisher role on the DCR.
Synapse requests the Azure public-cloud
`https://monitor.azure.com/.default` scope and advances only after the
ingestion endpoint returns HTTP 204.

Each Sentinel input row carries `TimeGenerated` as an RFC 3339 UTC
datetime derived from the exported event timestamp, `SynapseRecordId`,
`SynapseSourcePosition`, `SynapseSourceHash` when the source has one, and
the original redacted event as `SynapsePayload`. Declare those fields in the
DCR `streamDeclarations` entry and in the destination custom table:

| Column | Type |
| --- | --- |
| `TimeGenerated` | `datetime` |
| `SynapseRecordId` | `string` |
| `SynapseSourcePosition` | `dynamic` |
| `SynapseSourceHash` | `string` |
| `SynapsePayload` | `dynamic` |

With the same five columns on a table such as `SynapseSIEM_CL`, the DCR can
use the pass-through transformation `source`; no timestamp conversion is
required. The corresponding data flow uses the same custom stream name as the
target, for example `Custom-SynapseSIEM`, and an output stream matching the
custom table, for example `Custom-SynapseSIEM_CL`.

Azure Monitor replaces `TimeGenerated` with the receive time when the supplied
value is more than two days old or more than one day in the future. This can
happen during historical backfill. The original event timestamp remains in
`SynapsePayload.time` as Unix epoch milliseconds, so use that field when the
source event time must be preserved independently of Azure's time-window rule.

For incident streams, `SynapseSourcePosition.stream_seq` is contiguous and
can be used to surface a missing numeric sequence in Sentinel. Audit database
IDs can legitimately contain holes, so do not treat an audit ID jump as a
gap. Synapse verifies the audit hash chain before export;
`SynapseSourceHash` records the verified chain position for downstream
evidence. A simple incident-gap query for a table named `SynapseSIEM_CL` is:

```kusto
SynapseSIEM_CL
| extend Source = tostring(SynapseSourcePosition.source)
| extend StreamSeq = tolong(SynapseSourcePosition.stream_seq)
| where Source in ("live", "historical") and isnotnull(StreamSeq)
| sort by Source asc, StreamSeq asc
| serialize PreviousSource = prev(Source), PreviousStreamSeq = prev(StreamSeq)
| extend GapDetected = Source == PreviousSource and StreamSeq > PreviousStreamSeq + 1
| extend DuplicateDetected = Source == PreviousSource and StreamSeq == PreviousStreamSeq
| project TimeGenerated, SynapseRecordId, Source, StreamSeq, PreviousStreamSeq, GapDetected, DuplicateDetected, SynapseSourceHash
```

## Privacy

The sink data class defaults to signal. An engagement whose policy is unknown
does not rise above signal. A record with no engagement stays at signal.
`none` suppresses the record and is not a gap.
The current API and worker do not install a shared engagement policy, so the
settings page offers Signal only. An API request for Summary or Detail stores
that request but exports Signal until the shared policy is wired. Incident and
vulnerability events that lack required OCSF fields use the versioned Signal
envelope instead of disappearing into quarantine.

Signal carries the event type, severity, and a console link when
`SYNAPSE_SIEM_PUBLIC_BASE_URL` is configured. Summary can add a title, actor, and host. Detail can
add an advisory id, asset id, or comment. Raw audit metadata and raw incident
payloads are not serialized. Text passes through the shared secret scrubber.
For Microsoft Sentinel, both the sealed-credential plaintext and its decoded
`client_secret` value are registered as known secrets before an event is
serialized, so a source field containing the client secret is redacted too.
The source-chain hash in the payload is a reference to the local chain. It is
not a digest of the redacted body. The redacted body has its own digest.

## Finding export and schema validation

Finding workflow audit rows now map to OCSF detection findings (2004), or
vulnerability findings (2002) at Detail when the stored audit metadata includes a
CVE identifier. Create maps to Create; assignment, writeup and promotion map to
Update. Status and retest events use their recorded status: remediated or false
positive maps to Close; open, triage or confirmed maps to Update. Comments,
unknown verbs or missing/unknown status use the audit envelope with a fixed
`fallback_reason`. A missing finding identity also uses that envelope. Lower data
classes use detection findings without exporting advisory details. Incident
findings (2005) retain the existing owner and event-status requirements; missing
fields or a Signal ceiling produce an incident envelope with `fallback_reason`.

The source facts come only from the committed, hash-verified audit metadata or
captured incident event. The exporter never loads the current finding to fill a
missing title, severity or advisory. Existing Findings-service audit rows commonly
have no title; status, retest and promotion rows commonly have no severity.
Titles remain absent and severity is Unknown (0). Replay of the same facts,
policy, secrets and mapping version preserves the body, digest and record ID.
Record IDs remain tenant-specific. The mapping version is `synapse.siem.v2`.
Detection console links use `finding_info.src_url`.

Every newly prepared OCSF record passes the complete offline JSON Schema validator
before sealing. The vendored OCSF 1.5.0 schemas, upstream commit, checksums, profile
selection and license are documented in
`internal/infrastructure/siem/ocsf/schemas/README.md`. The existing `ValidateOCSF`
function adds producer and mapping constraints; it does not replace JSON Schema
validation. Invalid OCSF is quarantined with `schema_validation`; no payload or
source-valued validation error is sent or stored. Existing sealed batches retain
their prepared bytes across retries, including batches prepared by older versions.

## Credentials and hosts

Secrets are sealed with the vault key and associated data that includes the
tenant, sink, and provider. API responses return the origin, not the secret.
Replacing the secret keeps the cursor. Replacing the host pauses the sink,
drops prepared batches, and requires an explicit choice: continue from the
cursor, or start at the current head so the old backlog is not sent to the
new host.

Splunk and Elasticsearch destinations must be `https`; syslog destinations
must be `tls://host:port` and include a port (normally `6514`). All reject
userinfo, paths, queries, private, loopback, and metadata addresses. Syslog
uses the shared safe dialer, which resolves and checks the address actually
dialed; it verifies the certificate and hostname using TLS 1.2 or newer and
never disables verification.

The write-only syslog credential is a sealed JSON object. Use `{}` with the
system trust store, optionally add `ca_pem` for a private CA, and provide both
`client_cert_pem` and `client_key_pem` for mutual TLS. A lone certificate or
key is rejected. Private self-hosted collectors stay blocked until the shared
egress allowlist lands. Do not turn on private-network dialing to bypass that.

## Operations

Pause stops new sends and leaves cursors where they are. Resume clears a
blocked reason. The settings page offers Resume for a paused sink and for a
sink that is blocked while delivery is still enabled. If the source chain is
still broken, the next pass blocks again. Failed records in that blocked batch
are retried; records the destination already accepted are not sent again.

Export acknowledgements are not written back into the audit log. Configuration
changes are. Batch state and metrics are the operational record.

Set `SYNAPSE_SIEM_ENABLED=false` on all API/writer and worker replicas to stop
both incident capture and outbound sends. Events written while capture is off
do not enter the live partition; use a historical backfill before relying on
coverage after re-enabling. Pausing a sink only stops sends and keeps capture
active. Tenants without an enabled sink do not capture incident identities.

After seven days, a bounded sweep removes sealed batch payloads, completed
batch manifests, and obsolete credential versions. It prunes incident capture
rows only below every sink's committed cursor, including paused and blocked
sinks, while retaining one anchor row. Each removed identity is tombstoned.
Historical backfill does not assign a new sequence to a tombstoned event.
Events that were never captured, including those written while the kill switch
was off, can still be backfilled. A new sink starts from the retained anchor
if old capture rows were pruned. The incident counter is never reset. Capture,
prune, and backfill take the same per-tenant retention lock.

When metrics are enabled, SIEM delivery counters are on the worker `/metrics`
listener. If notification delivery metrics are also enabled, both series share
that listener. Give API and worker distinct metrics addresses if they share a
host; both default to `127.0.0.1:9090`. `SYNAPSE_SIEM_PUBLIC_BASE_URL` is a
bare `https` origin. It does not use the shared console-link builder, so a
deployment prefix on `SYNAPSE_PUBLIC_BASE_URL` is not applied to SIEM links.

## Who can manage sinks

Reading sinks and their status, and pausing, resuming or testing a sink, need the
`manage_integrations` permission, held by `admin` and `integration_admin`. Creating a
sink, editing it (data class, allowed hosts), rotating its secret and changing its host
need `administer`, which only `admin` holds. Machine roles hold neither.

## What this release does not prove

No Splunk, Elasticsearch, syslog, or Microsoft Sentinel service was available
while this was built, so there are no screenshots of received English or
Vietnamese events. Provider behavior is covered by contract tests against
local test servers. Browser screenshots of the settings page in light and dark
themes were not captured in a running console. The page uses the existing
settings components.
behavior is covered by contract tests against a local TLS server. Browser
screenshots of the settings page in light and dark themes were not captured in
a running console. The page uses the existing settings components.

These shared pieces were still open, so this stream does not replace them:

- dial-time host allowlists
- engagement data-class overrides beyond the fail-closed signal ceiling

