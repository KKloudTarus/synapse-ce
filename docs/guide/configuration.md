# Configuration

[Documentation home](README.md) · Previous: [Features](features.md) · Next: [CLI](cli.md)

Synapse reads its configuration from the process environment. It does not auto-load a file.
Load your settings first, for example `set -a; source .env; set +a`, or pass them with
`docker run --env-file`, Compose `env_file`, or your process manager. A fully documented
template lives in [`.env.example`](../../.env.example).

Conventions: an empty value means unset, so the built-in default applies. Booleans accept
`1/0/true/false`. Durations use Go syntax such as `30s`, `10m`, `1h`. Sizes are byte counts.

## Required

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_API_TOKEN` | (none) | Bootstrap-admin bearer token. The API exits if empty. There is no anonymous access. Generate with `openssl rand -hex 32`. |

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

## Persistence

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_DB_DSN` | (in-memory) | PostgreSQL connection URL. Empty runs an in-memory dev store, so nothing is durable. |
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
| `SYNAPSE_FINDING_MIN_SEVERITY` | `high` | Lowest severity promoted to a finding: critical, high, medium, low, info. |
| `SYNAPSE_MAX_WORKSPACE_BYTES` | `2147483648` | Maximum prepared workspace size. A bigger target or archive is rejected. |
| `SYNAPSE_OWNED_ADVISORY` | `false` | Match the SBOM against the owned advisory store, alongside the live and offline sources. Populate it first with `synapse-cli sync-advisories`. |
| `SYNAPSE_JARHASH_ONLINE_ENABLED` | `false` | Recover the coordinate of a shaded or metadata-less JAR by its SHA-1. |
| `SYNAPSE_OSV_URL`, `SYNAPSE_OSV_BULK_URL`, `SYNAPSE_DEPSDEV_URL`, `SYNAPSE_KEV_URL`, `SYNAPSE_EPSS_URL` | (public) | Feed overrides for tests or mirrors. |

## Recon and execution sandbox (sandbox required in production)

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_SANDBOX_ENABLED` | `false` | Run tool execution and acquisition in the bubblewrap sandbox. If set but bubblewrap is missing, startup fails closed. |
| `SYNAPSE_SANDBOX_MEM_MAX` | `536870912` | Per-run memory limit in bytes. |
| `SYNAPSE_SANDBOX_PIDS_MAX` | `256` | Per-run pid limit. |
| `SYNAPSE_TOOL_HASHES` | (TOFU) | Authoritative sha256 pins. The sandbox refuses a binary whose hash does not match. |
| `SYNAPSE_RECON_TIMEOUT` | `3m` | Per-run recon timeout. |
| `SYNAPSE_RECON_CONCURRENCY` | `3` | Recon worker pool size. |
| `SYNAPSE_RECON_ALLOW_CAPABILITY_SENSITIVE` | `false` | Permit tools that need raw sockets. |
| `SYNAPSE_RECON_VIA_WORKER` | `false` | Route recon through the durable queue to synapse-worker. Requires PostgreSQL. |

## AI agent orchestration (off by default)

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_AGENT_ENABLED` | `false` | Turn on the agent orchestrator. |
| `SYNAPSE_LLM_BASE_URL` | (none) | OpenAI-compatible Chat Completions endpoint. |
| `SYNAPSE_LLM_API_KEY` | (none) | Provider key. Never logged. |
| `SYNAPSE_LLM_MODEL` | (none) | Required when the agent is enabled. |
| `SYNAPSE_LLM_TIMEOUT` | `60s` | Per-request timeout. |
| `SYNAPSE_AGENT_APPROVAL_MODE` | `manual` | Human-in-the-loop approval: manual, filter, or auto. |
| `SYNAPSE_AGENT_APPROVAL_TIMEOUT` | `30m` | Fail-closed approval timeout. |
| `SYNAPSE_AGENT_MAX_STEPS` | `16` | Per-run step bound. |
| `SYNAPSE_AGENT_TOKEN_BUDGET` | `0` | 0 means unbounded. |
| `SYNAPSE_AGENT_MAX_DURATION` | `10m` | Per-run duration bound. |
| `SYNAPSE_AGENT_VIA_WORKER` | `false` | Durable agent on synapse-worker. Requires the recon worker and PostgreSQL. |

## AI analysis brain (opt-in, best-effort)

`SYNAPSE_JUDGMENTS_ENABLED` is the prerequisite for the analyzers that mint judgments. All are
best-effort and no-op without inputs.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_JUDGMENTS_ENABLED` | `false` | Judgment lifecycle routes (verify, accept, list). |
| `SYNAPSE_SAST_ENABLED` | `false` | Pattern SAST in the scan pipeline. |
| `SYNAPSE_REACHABILITY_ENABLED` | `false` | Call-graph reachability proof. Needs judgments. |
| `SYNAPSE_TAINT_ENABLED` | `false` | Taint proposals. Needs judgments and the sandbox. |
| `SYNAPSE_CROSSCHECK_ENABLED` | `false` | Detection-source disagreement judgments. |
| `SYNAPSE_SBOM_CROSSCHECK_ENABLED` | `false` | Dual-producer SBOM cross-check. |
| `SYNAPSE_GOMODGRAPH_ENABLED` | `false` | Transitive Go dependency edges via `go mod graph`. |
| `SYNAPSE_WRITEUP_DRAFTS_ENABLED` | `false` | Agent write-up draft tool. A distinct human signs off. |

## MCP server (synapse-mcp)

Read and propose only. It never executes. Both variables are required to start it.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_MCP_TOKEN` | (none) | Bearer token. Never logged. |
| `SYNAPSE_MCP_ENGAGEMENT_ID` | (none) | The engagement the MCP server is scoped to. |
| `SYNAPSE_MCP_ADDR` | `:8081` | Listen address. |

Next: [CLI](cli.md)
