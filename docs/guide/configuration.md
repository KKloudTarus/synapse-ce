# Configuration

[Documentation home](README.md) · Previous: [Features](features.md) · Next: [CLI](cli.md)

Synapse reads its configuration from the process environment. It does not auto-load a file.
Pass settings with `docker run --env-file`, Compose `env_file`, a strict dotenv loader, or your
process manager. Do not shell-source an untrusted dotenv file: shell syntax in that file would execute.
A fully documented template lives in [`.env.example`](https://github.com/KKloudTarus/synapse-ce/blob/main/.env.example).

Conventions: an empty value means unset, so the built-in default applies. Booleans accept
`1/0/true/false`. Durations use Go syntax such as `30s`, `10m`, `1h`. Sizes are byte counts.

## Required

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_API_TOKEN` | (none) | Bootstrap-admin bearer token. The API exits if empty. Operational routes require it; liveness `GET /healthz` and readiness `GET /readyz` are intentionally public. Generate with `openssl rand -hex 32`. |
| `SYNAPSE_OIDC_ENABLED` | `false` | Enable the browser OIDC BFF. Requires the fixed HTTPS issuer, client credentials, callback URL, fixed frontend URL, fixed tenant, and allowlisted group-to-role mapping below. |
| `SYNAPSE_OIDC_ISSUER` | (none) | Absolute HTTPS issuer used for pinned discovery and ID-token validation. |
| `SYNAPSE_OIDC_CLIENT_ID`, `SYNAPSE_OIDC_CLIENT_SECRET`, `SYNAPSE_OIDC_REDIRECT_URL` | (none) | OAuth client settings. The callback must be the exact registered `https://<api-host>/api/auth/oidc/callback` URL. Never log the secret. |
| `SYNAPSE_OIDC_FRONTEND_URL` | (none) | Fixed absolute HTTPS dashboard URL for a successful callback redirect. Query strings, fragments, and credentials are rejected; request parameters never control this destination. |
| `SYNAPSE_OIDC_TENANT_ID` | (none) | The one fixed Synapse tenant accepted by this BFF instance. |
| `SYNAPSE_OIDC_GROUP_ROLE_MAPPING` | (none) | Comma-separated exact `provider-group=role` entries. Roles may only be `admin`, `consultant`, `reviewer`, or `readonly`; unmapped, duplicate, and multi-role group claims are rejected. |
| `SYNAPSE_OIDC_TRANSACTION_TTL`, `SYNAPSE_OIDC_SESSION_TTL` | `10m`, `8h` | Maximum authorization-transaction and opaque browser-session lifetimes. |

## Core and server

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_HTTP_ADDR` | `:8080` | Listen address. |
| `SYNAPSE_ENV` | `development` | Non-prod values: development, dev, local, test, ci. Any other value is treated as production and enables the strict, fail-closed gates. |
| `SYNAPSE_LOG_LEVEL` | `info` | Log verbosity. |
| `SYNAPSE_SINGLE_TENANT` | `true` | Single-tenant mode. |
| `SYNAPSE_AUP_VERSION` | `1.0` | Acceptable Use Policy version the operator accepts on first run. |
| `SYNAPSE_AUP_FILE` | `data/aup-accepted.json` | File-backed path, in-memory mode only. |
| `SYNAPSE_AUDIT_FILE` | `data/audit.jsonl` | File-backed path, in-memory mode only. |
| `SYNAPSE_MEASURE_CURSOR_SECRET` | Ephemeral in development; required in production | HMAC key for signing Measures pagination cursors; minimum 32 bytes |

## Observability

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_METRICS_ENABLED` | `false` | Expose Prometheus metrics on a SEPARATE listener (`SYNAPSE_METRICS_ADDR`). Off by default; the listener is never bearer-protected and is never itself instrumented. |
| `SYNAPSE_METRICS_ADDR` | `127.0.0.1:9090` | Metrics listener address. Loopback-only by default; widen it only onto a private scrape network, never a public interface. |
| `SYNAPSE_ACCESS_LOG_ENABLED` | `true` | Emit one structured `http access` log event per request (method, matched route, status, latency, request id, and — once authenticated — the resolved principal id). Never logs raw paths, query strings, headers, bodies, tenant ids, remote addresses, user agents, or secrets. |

Metric names and label cardinality:

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `synapse_http_requests_total` | counter | `method`, `route`, `status_class` | Total HTTP requests. `route` is the matched `net/http` `ServeMux` pattern (e.g. `GET /api/v1/engagements/{id}`), never the raw path — path *values* collapse into one bounded label. An unmatched request reports `route="unmatched"`. `status_class` is `2xx`/`3xx`/`4xx`/`5xx`. |
| `synapse_http_request_duration_seconds` | histogram | `method`, `route`, `status_class` | Request handling latency. |
| `synapse_job_queue_queued` | gauge | none | Aggregate queued durable jobs, across every tenant. Present only when the configured job queue supports aggregate stats (Postgres and in-memory both do). |
| `synapse_job_queue_in_flight` | gauge | none | Aggregate claimed/in-flight durable jobs, across every tenant. |
| `synapse_job_queue_oldest_active_age_seconds` | gauge | none | Age of the oldest still-queued-or-claimed job (`ports.JobStats.OldestActiveAt`), `0` when the queue is empty. |
| `synapse_job_queue_scrape_errors_total` | counter | none | Failed attempts to read aggregate durable job queue stats for a scrape. The three `synapse_job_queue_*` gauges above are omitted from that scrape (never a stale or bogus value) when this increments. |
| `synapse_sca_scan_duration_seconds` | histogram | `outcome` | Completed synchronous or asynchronous SCA execution duration. For an async scan, measured from worker execution start, not from `StartScan`/enqueue time. Queue failures, dead letters, stale sweeps, and blocked gates do not record a duration. |
| `synapse_sca_scan_outcomes_total` | counter | `outcome` | Terminal SCA outcomes: `success`, `failed`, or `blocked`. Queue failures, dead letters, and stale sweeps count as `failed` without a duration. `blocked` is recorded only for an execution-gate denial reached after a genuine scan attempt — never for a pre-gate validation failure. |

No metric or access-log field ever carries a tenant id, engagement id, target, raw path, or free-form error text — the label sets above are exhaustive and deliberately bounded (unlike, for example, embedding a full URL path) to avoid unbounded label cardinality on the collector.

Example Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: synapse-api
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

The metrics listener has no authentication of its own. Keep `SYNAPSE_METRICS_ADDR` on loopback or a private network reachable only by your scrape infrastructure; do not put it behind the same reverse-proxy path as the bearer-protected API, and do not widen it to a public interface. Startup logs a WARN if `SYNAPSE_METRICS_ENABLED` is set and `SYNAPSE_METRICS_ADDR` does not resolve to a loopback address.

## Persistence

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_DB_DSN` | (in-memory) | Runtime PostgreSQL connection URL. Empty runs an in-memory dev store, so nothing is durable. |
| `SYNAPSE_DB_MIGRATION_DSN` | `SYNAPSE_DB_DSN` in development | Optional owner-level PostgreSQL DSN used only by `synapse-migrate`, separating migration authority from the least-privileged runtime DSN. In production it must use a database user distinct from the runtime DSN. |
| `SYNAPSE_DB_AUTO_MIGRATE` | `true` in development | Long-running services apply embedded migrations only in development. Production requires `false`; run `synapse-migrate` first. Use backward-compatible, phased, migrate-first changes: the API accepts only an applied forward migration strictly above its embedded maximum and exposes a stale or divergent schema through `/readyz`; worker and MCP refuse startup until the schema is current because they have no readiness endpoint. |
| `SYNAPSE_DB_MAX_CONNS` | `32` | pgx pool maximum connections. |
| `SYNAPSE_DB_MIN_CONNS` | `0` | pgx pool minimum connections. |
| `SYNAPSE_DB_MAX_CONN_LIFETIME` | `1h` | Connection lifetime. |
| `SYNAPSE_DB_MAX_CONN_IDLE` | `30m` | Idle connection timeout. |

## Evidence blob store (S3 or MinIO)

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_BLOB_ENDPOINT` | (in-memory) | Host and port without a scheme. Empty runs an in-memory blob store. |
| `SYNAPSE_BLOB_ACCESS_KEY` | `synapse` | Access key. |
| `SYNAPSE_BLOB_SECRET_KEY` | `synapse-secret` | Secret key. |
| `SYNAPSE_BLOB_BUCKET` | `synapse-evidence` | Bucket for evidence artifacts. |
| `SYNAPSE_BLOB_USE_SSL` | `false` | Set true for https endpoints. |

## Restore verification (synapse-verify-restore)

`synapse-verify-restore` is a read-only recovery tool. It reuses `SYNAPSE_DB_DSN` and the evidence
blob-store settings above, and requires a database identity permitted to read every tenant's
evidence chain; a least-privilege runtime role fails closed rather than reporting an empty restore
as intact.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_RESTORE_VERIFY_TIMEOUT` | `2m` | Maximum duration for one restore-verification run before it fails. |
| `SYNAPSE_RESTORE_VERIFY_EXPECTED_STATE` | (none) | Path to an independently captured expected-state manifest (audit head, per-engagement evidence heads and counts, expected applied migration versions). Equivalent to `--expected-state`. Without it a run reports `completeness: incomplete_no_expected_state`, because an emptied database cannot be distinguished from an intact one. |

## Custody, signing, and anchoring (required in production)

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_VAULT_MASTER_KEY` | (ephemeral) | AES-256 credential-vault master key, 64 hex chars or base64 of 32 bytes. Empty uses an ephemeral dev key, so stored secrets do not survive a restart. Never logged. |
| `SYNAPSE_EVIDENCE_SIGNING_SEED` | (ephemeral) | ed25519 seed attesting evidence and audit chain heads. Never logged. |
| `SYNAPSE_TSA_URL` | (none) | RFC-3161 timestamp authority for external anchoring. Empty leaves the chain signed but not anchored, still tamper-evident. |

## Software composition analysis

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_SBOM_PRODUCER` | `syft` | `syft` (pinned binary, full coverage, dep-graph edges) or `ownsbom` (detection-independent owned parsers, components only). |
| `SYNAPSE_SYFT_BIN` | `syft` | Syft executable, resolved on PATH. |
| `SYNAPSE_GRYPE_BIN` | `grype` | Grype executable. Missing means detection degrades to the live source only. |
| `SYNAPSE_GRYPE_DB_DIR` | (online) | Pin Grype's vulnerability database to a pre-synced directory for offline, reproducible scans. |
| `SYNAPSE_SCAN_TIMEOUT` | `10m` | Per-scan timeout. 0 disables. |
| `SYNAPSE_FINDING_MIN_SEVERITY` | `info` | Lowest severity promoted to a finding: critical, high, medium, low, info. The default promotes everything; set `high` to tighten the floor and drop medium/low/info. |
| `SYNAPSE_MAX_WORKSPACE_BYTES` | `2147483648` | Maximum prepared workspace size. A bigger target or archive is rejected. |
| `SYNAPSE_OWNED_ADVISORY` | `true` | Match the SBOM against the owned advisory store, alongside the live and offline sources. Populate it first with `synapse-cli sync-advisories`. |
| `SYNAPSE_JARHASH_ONLINE_ENABLED` | `false` | Recover the coordinate of a shaded or metadata-less JAR by its SHA-1. |
| `SYNAPSE_OSV_URL`, `SYNAPSE_OSV_BULK_URL`, `SYNAPSE_DEPSDEV_URL`, `SYNAPSE_KEV_URL`, `SYNAPSE_EPSS_URL` | (public) | Feed overrides for tests or mirrors. |

## Extra scanners and detection tuning (opt-in)

Most of these ship ON by default (safe, best-effort). See [Features](features.md) for what each one does.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_SECRET_SCAN_ENABLED` | `true` | Secret scanning over the workspace (regex plus entropy). Matches are redacted; the raw secret never reaches logs, evidence, or the report. |
| `SYNAPSE_MISCONFIG_ENABLED` | `true` | Misconfiguration and IaC scanning of Dockerfiles and Kubernetes manifests. |
| `SYNAPSE_CSPM_ENABLED` | `false` | Enable durable read-only cloud posture runs. Requires PostgreSQL, fleet assets, `synapse-worker`, sandbox, and kernel egress enforcement. |
| `SYNAPSE_CSPM_PROVIDERS` | empty | Comma-separated provider allowlist: `aws`, `azure`, `gcp`. |
| `SYNAPSE_CSPM_RATE` | `0` | Requests per second, `1..100`; `0` selects provider defaults. |
| `SYNAPSE_CSPM_HELPER_BIN` | `synapse-cspm` | CSPM requires this to be an absolute path and authoritatively pinned in `SYNAPSE_TOOL_HASHES`; the helper executes inside bubblewrap. |
| `SYNAPSE_CSPM_EGRESS_HOSTS` | empty | Comma-separated `provider=hostname` HTTPS allowlist. Empty fails CSPM startup closed. |
| `SYNAPSE_FP_TRIAGE_ENABLED` | `false` | Enable advisory LLM false-positive analysis over production-scope SAST/misconfig findings. Secrets never enter the LLM. A proposer alone or a scan without an evidence ledger never changes a gate. |
| `SYNAPSE_FP_TRIAGE_MODEL` | `SYNAPSE_LLM_MODEL` | Proposer model for false-positive analysis. |
| `SYNAPSE_FP_TRIAGE_PROVIDER` | `SYNAPSE_LLM_PROVIDER` | Explicit provider identity for the triage proposer model. |
| `SYNAPSE_FP_TRIAGE_MODE` | `shadow` | `shadow` records `would_gate_exempt` but always keeps the finding gating. `enforce` permits the verified-consensus policy to set `gate_exempt`. Empty or unknown values fail closed to shadow. |
| `SYNAPSE_FP_TRIAGE_MAX_FINDINGS` | `100` | Hard per-scan cap on eligible findings sent to AI triage (range `1..1000`). When capped, deterministic policy-impact/severity/risk ordering selects work; skipped findings remain reported and gating, and counts are exposed in `ai_triage_budget`. Invalid values restore the finite default. |
| `SYNAPSE_FP_TRIAGE_CONCURRENCY` | `6` | Maximum simultaneous AI finding assessments (range `1..32`). A distinct verifier makes at most two provider calls per attempted finding. Invalid values restore the finite default. |
| `SYNAPSE_FP_TRIAGE_MAX_TOKENS` | `1000000` | Conservative per-scan token reservation ceiling. Both proposer/verifier requests are reserved before a finding is scheduled; work that does not fit remains gating. |
| `SYNAPSE_FP_TRIAGE_MAX_COST_MICRO_USD` | `0` | Optional per-scan cost ceiling in integer micro-USD (`0` disables cost enforcement). When enabled, all active role prices must be configured or triage fails closed without provider calls. |
| `SYNAPSE_FP_TRIAGE_PROPOSER_INPUT_MICRO_USD_PER_MILLION` | `0` | Proposer input price in micro-USD per million tokens, for deterministic cost reservation and observed-cost metrics. |
| `SYNAPSE_FP_TRIAGE_PROPOSER_OUTPUT_MICRO_USD_PER_MILLION` | `0` | Proposer output price in micro-USD per million tokens. |
| `SYNAPSE_FP_TRIAGE_VERIFIER_INPUT_MICRO_USD_PER_MILLION` | `0` | Verifier input price in micro-USD per million tokens. |
| `SYNAPSE_FP_TRIAGE_VERIFIER_OUTPUT_MICRO_USD_PER_MILLION` | `0` | Verifier output price in micro-USD per million tokens. |
| `SYNAPSE_FP_TRIAGE_CIRCUIT_FAILURES` | `5` | Consecutive provider/parse failures before that role's circuit opens (range `1..100`). An open circuit is advisory-only and cannot exempt findings. |
| `SYNAPSE_FP_TRIAGE_CIRCUIT_COOLDOWN` | `1m` | Open-circuit cooldown before one half-open probe (maximum `24h`). |
| `SYNAPSE_FP_TRIAGE_ALERT_MIN_SAMPLES` | `10` | Minimum per-scan samples before a safety-rate baseline alert is emitted. |
| `SYNAPSE_FP_TRIAGE_DISAGREEMENT_BASELINE_BPS` | `1500` | Expected proposer/verifier disagreement rate in basis points (`10000` = 100%). |
| `SYNAPSE_FP_TRIAGE_EXEMPTION_BASELINE_BPS` | `1000` | Expected gate-exemption rate in basis points. |
| `SYNAPSE_FP_TRIAGE_PARSE_FAILURE_BASELINE_BPS` | `200` | Expected model parse-failure rate in basis points. |
| `SYNAPSE_FP_TRIAGE_ALERT_DEVIATION_BPS` | `1000` | Absolute deviation from a configured baseline that emits a persisted warning and structured alert metric. |
| `SYNAPSE_LLM_PROVIDER` | `openai-compatible` | Explicit proposer-provider audit identity. It is not inferred from the URL because gateways may route multiple providers. |
| `SYNAPSE_VERIFIER_BASE_URL` | `SYNAPSE_LLM_BASE_URL` | Independent OpenAI-compatible endpoint for the verifier. |
| `SYNAPSE_VERIFIER_API_KEY` | `SYNAPSE_LLM_API_KEY` | Independent verifier credential; never logged. |
| `SYNAPSE_VERIFIER_PROVIDER` | `SYNAPSE_FP_TRIAGE_PROVIDER` | Explicit verifier-provider audit identity. It defaults to the proposer identity so provider independence remains advisory-only until an operator deliberately selects a different verifier provider. |
| `SYNAPSE_VERIFIER_MODEL` | `SYNAPSE_LLM_MODEL` | Must name a different canonical model family for AI gate exemptions. The verifier is blind to the proposer result. Provider/date aliases and Amazon Bedrock inference-profile IDs fail closed as the same family. Two-model consensus remains subject to high/critical, secret, and dangerous-CWE human-review floors. |
| `SYNAPSE_FP_TRIAGE_INDEPENDENCE` | `model_family` | `model_family` requires different canonical model families. `provider` additionally requires different non-empty provider identities. Empty defaults to model-family compatibility; unknown values fail closed to advisory-only. |
| `SYNAPSE_DETECTION_PRIORITY` | `comprehensive` | `comprehensive` reports every match. `precise` quarantines single-source, non-KEV findings into a needs-verify queue that is still reported and sealed but exempt from the `--fail-on` gate. |
| `SYNAPSE_OFFLINE` | `false` | Skip the live advisory source and detect with the offline database only. |
| `SYNAPSE_IGNORE_UNFIXED` | `false` | Drop vulnerabilities that have no fixed version. |
| `SYNAPSE_DB_MAX_AGE_DAYS` | `30` | Warn when a dated reference database (KEV, EPSS, or the Grype DB) is older than this many days. 0 disables the check. |
| `SYNAPSE_SUPPRESSION_ENABLED` | `true` | Honor a `.synapseignore` file. Acceptance exempts only the `--fail-on` gate; the finding is still reported, persisted, and evidence-sealed. |
| `SYNAPSE_VEX_ENABLED` | `true` | Consume an in-repo OpenVEX document (`.synapse.vex.json`) at scan time, on the same retain-and-mark surface as suppression. |
| `SYNAPSE_COMPLIANCE_ENABLED` | `true` | Compliance benchmark. Re-projects findings onto a control specification and reports per-control PASS or FAIL. |
| `SYNAPSE_SCAN_CACHE_ENABLED` | `true` | Enables content-addressed scan caches. SBOM entries key on content plus producer version. Tenant-bound API AI-triage entries key on tenant, project/engagement scope, finding fingerprint, complete-source hash, prompt-context hash, proposer/verifier models, prompt version, and policy version. Cached AI claims are always rebound to the current finding, re-authorized by server policy, and linked to newly sealed scan evidence; missing tenant identity and provider failures are not cached. The directory must be operator-owned, since a shared-writable cache would allow poisoning. |
| `SYNAPSE_SCAN_CACHE_DIR` | (per-user) | Cache location. Empty uses a per-user cache directory; AI-triage entries live in its owner-only `ai-triage` subdirectory and contain typed claims, never source text or credentials. |
| `SYNAPSE_IMAGE_ROOTFS_ENABLED` | `true` | Materialize a container image root filesystem so the owned OS-package catalogers (dpkg, apk, and the rpm sqlite database) and installed-binary catalogers (Go build info, Python dist-info) can run. Best-effort. |

## Project Code artifact retention and historical comparisons

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_PROJECT_SOURCE_ARTIFACT_DIR` | `data/project-source-artifacts` | Operator-owned local storage for immutable, gzip-compressed Project Code head/base artifacts. Restrict OS access, encrypt/back up it according to source-data policy, and do not place it on a shared writable volume. The full Compose stack mounts its dedicated `project-source-artifacts` named volume here. |
| `SYNAPSE_PROJECT_SOURCE_RETENTION` | `2160h` (90 days) | How long captured analysis artifacts remain available. Startup cleanup removes expired analysis directories; project deletion removes all of that project's artifacts. Legacy analyses are never backfilled. |
| `SYNAPSE_PROJECT_SOURCE_MAX_FILE_BYTES` | `2097152` | Maximum captured source file size. Bigger files are retained as unavailable metadata. |
| `SYNAPSE_PROJECT_SOURCE_MAX_FILES` | `10000` | Maximum source files captured for one analysis. |
| `SYNAPSE_PROJECT_SOURCE_MAX_BYTES` | `524288000` | Total source-artifact capture budget per analysis. |
| `SYNAPSE_PROJECT_GIT_COMPARISON_DEPTH` | `256` | Maximum Git history depth fetched to resolve a persisted comparison base. A missing/too-old base leaves source readable but comparison/unified/split capabilities unavailable. |

Historical Code reads are analysis-scoped and private-cacheable. Source and diff APIs never fetch the current repository or read mutable local paths. Git comparison requires configured, validated head/base/default-branch refs; local and archive scans intentionally expose source-only capability. Generated files are hidden by default from the Code inventory but remain retained and explicitly addressable. Binary/non-UTF-8/limited artifacts expose an unavailable reason instead of content.

For `docker run`, mount durable storage at the image's configured artifact path (the API image uses `/project-source-artifacts`): `--mount type=volume,source=synapse-project-source-artifacts,target=/project-source-artifacts`. Removing that volume permanently removes retained historical Code source and diffs.

## Fleet attack paths

Attack paths are available when `SYNAPSE_FLEET_ASSETS_ENABLED=true`. They correlate the tenant's
asset relationships with explicitly attributed findings and reachability judgments. Every response
reports whether traversal was truncated; lowering a bound never produces a result that looks complete.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_ATTACKPATH_MAX_LEN` | `12` | Maximum number of steps in one path. Must be positive. |
| `SYNAPSE_ATTACKPATH_MAX_PATHS` | `100` | Maximum retained paths per requested target or finding. Must be positive. |
| `SYNAPSE_ATTACKPATH_WALLCLOCK` | `2s` | Wall-clock traversal budget. Must be positive. |

## Reachability tiers (opt-in per language)

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_REACHABILITY_ENABLED` | `true` | Go Tier-2 call-graph reachability proof (best-effort). |
| `SYNAPSE_JVM_REACHABILITY_ENABLED` | `true` | JVM (Java/Kotlin) reachability. |
| `SYNAPSE_PYREACH_ENABLED` | `false` | Python Tier-1 import-reachability (a dead dependency becomes an OpenVEX `not_affected`). |
| `SYNAPSE_JSREACH_ENABLED` | `false` | JS/TS Tier-1 import-level reachability. |
| `SYNAPSE_JSREACH_TIER2_ENABLED` | `false` | JS/TS Tier-2 symbol-level reachability. |

## Fleet, leader election, and DAST

All off by default. The fleet needs PostgreSQL + `synapse-worker`; agents run on Linux hosts / Kubernetes. Enable leader election when running more than one API/worker so scheduled work fires once.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_FLEET_ENABLED` | `false` | Fleet transport + agent-admin routes. |
| `SYNAPSE_FLEET_ASSETS_ENABLED` | `false` | Fleet asset model + attack paths. |
| `SYNAPSE_FLEET_HOST_INGEST_ENABLED` | `false` | Accept host-inventory from `synapse-agent`. |
| `SYNAPSE_FLEET_CLUSTER_INGEST_ENABLED` | `false` | Accept Kubernetes inventory from `synapse-cluster-agent`. |
| `SYNAPSE_FLEET_TELEMETRY_INGEST_ENABLED` | `false` | Accept signed agent telemetry batches (A3, `POST /api/v1/fleet/telemetry`); verified + idempotently sequenced server-side. |
| `SYNAPSE_FLEET_DETECTION_INGEST_ENABLED` | `false` | Accept signed agent detection batches (A4, `POST /api/v1/fleet/detections`); sealed once into the evidence chain. |
| `SYNAPSE_FLEET_KEY_REGISTRATION_ENABLED` | `false` | Serve agent signing-key registration (`POST /api/v1/fleet/keys`) + operator key list/revoke (A4, A0.2). |
| `SYNAPSE_FLEET_STALE_AFTER` | `10m` | An agent older than this reads as stale (`<=0` disables the staleness view). |
| `SYNAPSE_FLEET_COVERAGE_FRESHNESS_TARGET` | `24h` | Coverage freshness SLO. |
| `SYNAPSE_FLEET_MIN_AGENT_VERSION` | empty | Reject agents below this version (empty = no floor). |
| `SYNAPSE_FLEET_CA_CERT` / `_CA_KEY` / `_CERT_TTL` | empty | Enrolment PKI for agent client certificates (never logged). |
| `SYNAPSE_FLEET_SIGNER_KEY` | empty | Signing key for agent packages/updates (never logged). |
| `SYNAPSE_LEADER_ENABLED` | `false` | Fence scheduled dispatch to one node via a Postgres lease. |
| `SYNAPSE_LEADER_RESOURCE` | `scheduler` | Lease name. |
| `SYNAPSE_LEADER_TERM` | `15s` | Lease term. |
| `SYNAPSE_LEADER_RENEW` | `5s` | Renew interval. |
| `SYNAPSE_WORKER_CONCURRENCY` | `1` | Durable queue claim loops per `synapse-worker` process; must be from 1 through 64. Jobs remain active on every worker, while maintenance sweepers are leader-gated when election is enabled. |
| `SYNAPSE_VULNERABILITY_SCHEDULER_ENABLED` | `false` | Dispatch due vulnerability-source syncs and recover stale runs. PostgreSQL deployments must also enable leader election. |
| `SYNAPSE_VULNERABILITY_SCHEDULER_POLL` | `1m` | Scheduler polling interval. |
| `SYNAPSE_VULNERABILITY_SCHEDULER_STALE_AFTER` | `30m` | Age after which a queued/running sync is eligible for checkpoint-based recovery. |
| `SYNAPSE_VULNERABILITY_SCHEDULER_JITTER_PERCENT` | `10` | Stable per-source cadence jitter, from 0 through 100 percent. |
| `SYNAPSE_VULNERABILITY_SCHEDULER_DISPATCH_LIMIT` | `10` | Maximum new source runs dispatched per scheduler tick. |
| `SYNAPSE_VULNERABILITY_SCHEDULER_MAX_QUEUE_DEPTH` | `100` | Stop dispatching when the vulnerability-sync queue reaches this depth. |
| `SYNAPSE_VULNERABILITY_SCHEDULER_RECOVERY_LIMIT` | `10` | Maximum stale runs recovered per scheduler tick. |
| `SYNAPSE_VULNERABILITY_PROVIDER_SYNC_ENABLED` | `false` | Permit provider sync execution. This global gate also blocks already queued runs after rollback. |
| `SYNAPSE_VULNERABILITY_OCCURRENCE_WRITES_ENABLED` | `false` | Permit tenant-scoped occurrence mutations for allowlisted tenants. |
| `SYNAPSE_VULNERABILITY_FINDING_PROJECTION_ENABLED` | `false` | Permit machine-owned finding projection updates for allowlisted tenants. |
| `SYNAPSE_VULNERABILITY_ACTIONS_ENABLED` | `false` | Permit risk-change action creation for allowlisted tenants. |
| `SYNAPSE_VULNERABILITY_NOTIFICATIONS_ENABLED` | `false` | Permit notification-outbox writes for allowlisted tenants. |
| `SYNAPSE_VULNERABILITY_DRY_RUN_ENABLED` | `true` | Persist reconciliation diffs and counts without occurrence, finding, action, or notification mutations. |
| `SYNAPSE_VULNERABILITY_TENANT_ALLOWLIST` | empty | Comma-separated tenant IDs allowed to use tenant-scoped gates and dry-run; `*` enables every tenant. Empty fails closed. |
| `SYNAPSE_SLA_ENABLED` | `false` | Enable versioned risk-based remediation deadlines, immutable assessment history, human-only lifecycle transitions, and continuous-intelligence reassessment. See [Remediation SLA governance](sla-governance.md). |
| `SYNAPSE_DAST_RATE_PER_SEC` | `5` | DAST crawler request rate. |
| `SYNAPSE_DAST_CONCURRENCY` | `4` | DAST crawler concurrency. |
| `SYNAPSE_DAST_MAX_DEPTH` | `8` | Maximum crawl depth. |
| `SYNAPSE_DAST_MAX_PAGES` | `2000` | Maximum pages crawled. |
| `SYNAPSE_DAST_MAX_WALL_CLOCK` | `30m` | Maximum crawl wall-clock. |
| `SYNAPSE_DAST_HELPER_BIN` | `synapse-dast-helper` | Sandboxed DAST helper binary. |

## Recon and execution sandbox (sandbox required in production)

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_SANDBOX_ENABLED` | `false` | Run tool execution and acquisition in the bubblewrap sandbox. Production requires `true`; if bubblewrap is missing, startup fails closed. |
| `SYNAPSE_SANDBOX_MEM_MAX` | `536870912` | Per-run memory limit in bytes. |
| `SYNAPSE_SANDBOX_PIDS_MAX` | `256` | Per-run pid limit. |
| `SYNAPSE_TOOL_HASHES` | (TOFU) | Authoritative sha256 pins. The sandbox refuses a binary whose hash does not match. |
| `SYNAPSE_RECON_TIMEOUT` | `3m` | Per-run recon timeout. |
| `SYNAPSE_RECON_CONCURRENCY` | `3` | Recon worker pool size. |
| `SYNAPSE_RECON_ALLOW_CAPABILITY_SENSITIVE` | `false` | Permit tools that need raw sockets. |
| `SYNAPSE_TOOL_EXECUTION_MODE` | (role default) | Explicit process execution posture: `dispatch-only`, `worker`, or `in-process`. Production `synapse-api` defaults to `dispatch-only` and refuses `in-process`, so untrusted tools run only on `synapse-worker`; `dispatch-only` requires PostgreSQL. Leave unset unless overriding the role default. |
| `SYNAPSE_RECON_VIA_WORKER` | `false` | Route recon through the durable queue to synapse-worker. Requires PostgreSQL. |

## Signed egress grants (native worker tier)

Scoped network access for an untrusted process is authorized by the control plane, not by the
worker. The API signs a short-lived grant bound to the exact process and namespace; a root-owned
broker verifies it and configures that namespace before the sandboxed child is released. The
signing seed stays in the control plane and the broker holds only the public verification key. See
[Deployment](deployment.md) and [Security](security.md).

Set the issuer variables on `synapse-api` and the client variables on `synapse-worker`.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_EGRESS_GRANT_AUTHORITY_ADDR` | (none) | API: listen address for the machine-only grant listener, for example `:8082`. Publish it through a private TLS load balancer reachable only from the worker security group, never through the browser ingress. |
| `SYNAPSE_EGRESS_GRANT_ISSUER_TOKEN` | (none) | API: bearer credential the worker machine identity presents to the grant listener. Keep it distinct from `SYNAPSE_API_TOKEN` so a worker holds no human API authority. Never logged. |
| `SYNAPSE_EGRESS_GRANT_SIGNING_SEED` | (none) | API: Ed25519 seed that signs grants. Rotate in two phases so in-flight grants stay verifiable. Never logged. |
| `SYNAPSE_EGRESS_GRANT_AUTHORITY_URL` | (none) | Worker: private HTTPS URL of the grant listener. |
| `SYNAPSE_EGRESS_GRANT_AUTHORITY_TOKEN` | (none) | Worker: machine bearer credential for the grant listener. Never logged. |
| `SYNAPSE_EGRESS_BROKER_SOCKET` | (none) | Worker: path to the root-owned broker's Unix socket. The protocol carries only a run id and canonical CIDR/port rules; it has no command or argv field. |

## AI agent orchestration (off by default)

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_AGENT_ENABLED` | `false` | Turn on the agent orchestrator. |
| `SYNAPSE_LLM_BASE_URL` | (none) | OpenAI-compatible Chat Completions endpoint. |
| `SYNAPSE_LLM_API_KEY` | (none) | Provider key. Never logged. |
| `SYNAPSE_LLM_PROVIDER` | `openai-compatible` | Explicit provider identity retained for audit and separation-of-duties checks. |
| `SYNAPSE_LLM_MODEL` | (none) | Required when the agent is enabled. |
| `SYNAPSE_LLM_TIMEOUT` | `60s` | Per-request timeout. |
| `SYNAPSE_AGENT_APPROVAL_MODE` | `manual` | Human-in-the-loop approval: manual, filter, or auto. |
| `SYNAPSE_AGENT_APPROVAL_TIMEOUT` | `30m` | Fail-closed approval timeout. |
| `SYNAPSE_AGENT_MAX_STEPS` | `16` | Per-run step bound. |
| `SYNAPSE_AGENT_TOKEN_BUDGET` | `0` | 0 means unbounded. |
| `SYNAPSE_AGENT_MAX_DURATION` | `10m` | Per-run duration bound. |
| `SYNAPSE_AGENT_VIA_WORKER` | `false` | Durable agent on synapse-worker. Requires the recon worker and PostgreSQL. |

## AI analysis brain (opt-in, best-effort)

`SYNAPSE_JUDGMENTS_ENABLED` (on by default) is the prerequisite for the analyzers that mint judgments.
All are best-effort and no-op without inputs. Set a flag to `false` to opt out.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_JUDGMENTS_ENABLED` | `true` | Judgment lifecycle routes (verify, accept, list). |
| `SYNAPSE_SAST_ENABLED` | `true` | Pattern SAST in the scan pipeline. |
| `SYNAPSE_REACHABILITY_ENABLED` | `true` | Call-graph reachability proof (Go, Tier-2). Needs judgments. |
| `SYNAPSE_PYREACH_ENABLED` | `false` | Python import-reachability (Tier-1 dead-dependency → OpenVEX). Needs judgments. |
| `SYNAPSE_TAINT_ENABLED` | `false` | Taint proposals. Needs judgments and the sandbox. |
| `SYNAPSE_CROSSCHECK_ENABLED` | `true` | Detection-source disagreement judgments. |
| `SYNAPSE_SBOM_CROSSCHECK_ENABLED` | `true` | Dual-producer SBOM cross-check. |
| `SYNAPSE_GOMODGRAPH_ENABLED` | `true` | Transitive Go dependency edges via `go mod graph`. |
| `SYNAPSE_WRITEUP_DRAFTS_ENABLED` | `false` | Agent write-up draft tool. A distinct human signs off. |

## Additional operator settings

The settings below are intentionally grouped by owning process. They are real operator controls even
when they are used only by a CLI, helper, or optional subsystem.

### Database, project storage, and maintenance

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_DB_MIGRATION_DSN` | `SYNAPSE_DB_DSN` | Optional owner-level PostgreSQL DSN used only for embedded migrations. Use it to keep the runtime DSN least-privileged. |
| `SYNAPSE_PROJECT_UPLOAD_DIR` | `data/project-uploads` | Server-owned directory for uploaded project source bundles. |
| `SYNAPSE_PROJECT_ANALYSIS_COMPLETION_TIMEOUT` | `1m` | Maximum wait for project-analysis completion; non-positive values reset to one minute. |
| `SYNAPSE_APPROVAL_SWEEP_INTERVAL` | `1m` | Sweep interval for expired pending approvals. |
| `SYNAPSE_PROMOTION_RECONCILE_INTERVAL` | `1m` | Interval for deterministic promotion-rule reevaluation. |

### Advisory, NVD, and resolver access

Network-backed manifest resolution is disabled by default. When enabled, set the associated host
allowlist; an empty or overly broad allowlist must not become an implicit network policy.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_NVD_API_URL` | public NVD API | NVD API endpoint override for an approved mirror. |
| `SYNAPSE_NVD_API_KEY` | empty | NVD API key. Keep it in the process environment or secret manager; never put it in source. |
| `SYNAPSE_NVD_BUDGET` | `20s` | Per-request NVD enrichment budget. |
| `SYNAPSE_NVD_CVSS_DB` | empty | CLI path to an offline CVSS database built with `build-cvss-db`. |
| `SYNAPSE_MAVEN_RESOLVE_ENABLED` | `false` | Resolve Maven metadata from allowlisted repositories. |
| `SYNAPSE_MAVEN_REPO_HOSTS` | empty | Comma-separated Maven host allowlist. |
| `SYNAPSE_MAVEN_LOCAL_REPO` | platform default | Local Maven repository override. |
| `SYNAPSE_GRADLE_RESOLVE_ENABLED` | `false` | Resolve Gradle metadata. Requires an isolated Gradle home and approved hosts. |
| `SYNAPSE_GRADLE_HOME` | empty | Isolated Gradle user-home directory. |
| `SYNAPSE_GRADLE_HTTP_TIMEOUT_MS` | implementation default | Gradle HTTP timeout in milliseconds. |
| `SYNAPSE_NPM_RESOLVE_ENABLED` | `false` | Resolve npm manifests from allowlisted registries. |
| `SYNAPSE_NPM_REGISTRY_HOSTS` | empty | Comma-separated npm registry host allowlist. |
| `SYNAPSE_MANIFEST_RESOLVE_ENABLED` | `false` | Enable remaining external manifest resolvers. |
| `SYNAPSE_MANIFEST_REGISTRY_HOSTS` | empty | Comma-separated host allowlist for those resolvers. |
| `SYNAPSE_JARHASH_BASE_URL` | empty | Approved jar-hash service or mirror URL. |
| `SYNAPSE_JARHASH_DB_PATH` | empty | Offline jar-hash database path. |

Tool binary overrides use `SYNAPSE_AST_BIN`, `SYNAPSE_GOVULNCHECK_BIN`, `SYNAPSE_GO_BIN`,
`SYNAPSE_MVN_BIN`, `SYNAPSE_GRADLE_BIN`, `SYNAPSE_NPM_BIN`, `SYNAPSE_COMPOSER_BIN`,
`SYNAPSE_BUNDLE_BIN`, `SYNAPSE_POETRY_BIN`, and `SYNAPSE_TAINT_CALLGRAPH_BIN`. Defaults are the
corresponding command names on `PATH`; production sandbox deployments should use absolute, pinned paths.

### Recon and DAST limits

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_RECON_MAX_OUTPUT` | `8388608` | Maximum captured output per recon run, in bytes. |
| `SYNAPSE_RECON_QUEUE` | `64` | Recon work queue depth. |
| `SYNAPSE_DAST_MAX_REAUTH` | `2` | Maximum governed reauthorization cycles for a DAST session. |
| `SYNAPSE_DAST_MAX_REQUESTS` | `20000` | Hard request ceiling for a DAST session. |
| `SYNAPSE_DAST_SECRET_<NAME>` | unset | Helper-only projection of a named vault placeholder. The parent constructs and scrubs these values; operators should store the source secret in the vault instead of setting this prefix manually. |

`SYNAPSE_DAST_AUTH_REQUEST_FD`, `SYNAPSE_DAST_AUTH_DECISION_FD`,
`SYNAPSE_CSPM_CREDENTIAL_FD`, `SYNAPSE_CSPM_AUTH_REQUEST_FD`, and
`SYNAPSE_CSPM_AUTH_DECISION_FD` are inherited-pipe descriptors managed by the parent process. They are
not operator settings and must not be injected manually.

### Fleet control plane

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_FLEET_CA_KEY` | empty | Private key for the fleet client-certificate CA. Required with the fleet CA certificate; treat as a production secret. |
| `SYNAPSE_FLEET_CERT_TTL` | `24h` | Lifetime of issued fleet client certificates. |
| `SYNAPSE_FLEET_CLIENT_CERT_HEADER` | empty | Trusted reverse-proxy header carrying the verified client certificate. Enable only behind a proxy that strips all client-supplied copies and sets the header after mTLS verification. |
| `SYNAPSE_UPDATE_PUBLIC_KEY` | built-in release key | Hex Ed25519 public-key override for fleet self-update verification. Use only for a controlled private release channel. |
| `SYNAPSE_AGENT_CONCURRENCY` | `8` | Total server-side agent work concurrency. |
| `SYNAPSE_AGENT_QUEUE_DEPTH` | `256` | Pending agent-work queue depth. |
| `SYNAPSE_AGENT_MAX_PARALLEL` | `1` | Maximum parallel actions per agent; serial by default. |
| `SYNAPSE_AGENT_RECON_CONCURRENCY` | `3` | Recon work admitted within the agent budget. |

### Host and Kubernetes agents

The following variables are read by `synapse-agent` and `synapse-cluster-agent`, not by the API:

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_FLEET_URL` | empty | Fleet API base URL. HTTPS is required except for loopback development. |
| `SYNAPSE_FLEET_ENROL_TOKEN` | empty | One-time enrollment token. Environment use is supported, but a token file is preferred; the equivalent command-line flag is visible in process listings and shell history. |
| `SYNAPSE_FLEET_ENROL_TOKEN_FILE` | empty | Preferred file containing the one-time token. Remove it after successful enrollment. |
| `SYNAPSE_AGENT_STATE_DIR` | platform default | Credential and offline-buffer directory; `/var/lib/synapse-cluster-agent` for the cluster agent. Protect it from other users. |
| `SYNAPSE_AGENT_ROOT` | `/` | Host filesystem root inventoried by the VM agent. |
| `SYNAPSE_AGENT_NAME` | hostname | Human-readable agent display name. |
| `SYNAPSE_INVENTORY_SWEEP_ENABLED` | `true` | Ship host inventory continuously on a cadence (A8, #629), not only on a `scan.host` work order. Ingest is idempotent server-side (host upsert-by-natural-key), so a re-sweep of an unchanged host is a no-op. Set `false` to disable. |
| `SYNAPSE_INVENTORY_SWEEP_INTERVAL` | `1h` | Cadence of the continuous host-inventory sweep. Clamped to a 1-minute floor so a misconfiguration cannot busy-loop the collector over the filesystem. |
| `SYNAPSE_DETECT_CLASSES` | empty | Comma-separated eBPF classes: `process`, `network`, `file`, `privilege`. Empty disables the engine; Linux root/capabilities are required. |
| `SYNAPSE_DETECT_CPU_CEIL_PCT` | `0` | CPU ceiling for deterministic class shedding; zero disables shedding. |
| `SYNAPSE_DETECTION_ENGAGEMENT_ID` | empty | Engagement receiving signed detection batches. Empty keeps confirmed detections durably local and does not start the remote detection shipper. |
| `SYNAPSE_DETECTION_SHIP_INTERVAL` | `1s` | Poll interval while the independent P1 detection delivery lane is empty. Network/429/5xx retry uses separate capped exponential backoff. |
| `SYNAPSE_TELEMETRY_SPOOL_BYTES` | `536870912` | Maximum bytes of checksummed telemetry WAL segments (minimum 1 MiB). P3 is evicted first with durable gap evidence; P0–P2 backpressure instead of shedding. |
| `SYNAPSE_AGENT_METRICS_ADDR` | empty | Optional private Prometheus listener for agent spool metrics. It has no authentication; bind to loopback or a protected scrape network. |
| `SYNAPSE_CLUSTER` | empty (required) | Stable cluster identity attached to every Kubernetes asset. |
| `SYNAPSE_CLUSTER_NAMESPACES` | empty | Comma-separated namespace scope; empty means all authorized namespaces. |
| `SYNAPSE_CLUSTER_RESYNC` | `5m` | Interval between Kubernetes inventory collections. |

### CLI integration

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_API_URL` | empty | Server base URL used by `synapse-cli publish-source`; overridden by `--server`. |
| `SYNAPSE_REACH_RUST` | `false` | Enable conservative Rust manifest/import reachability. |
| `SYNAPSE_REACH_RUBY` | `false` | Enable conservative Ruby manifest/import reachability. |
| `SYNAPSE_REACH_PHP` | `false` | Enable conservative PHP manifest/import reachability. |

## MCP server (synapse-mcp)

Read and propose only. It never executes. The token and engagement ID are required to start it.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_MCP_TOKEN` | (none) | Bearer token. Never logged. |
| `SYNAPSE_MCP_ENGAGEMENT_ID` | (none) | The engagement the MCP server is scoped to. |
| `SYNAPSE_MCP_ADDR` | `:8081` | Listen address. |

Next: [CLI](cli.md)
