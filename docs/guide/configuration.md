# Configuration

[Documentation home](README.md) · Previous: [Features](features.md) · Next: [CLI](cli.md)

Synapse reads its configuration from the process environment. It does not auto-load a file.
Load your settings first, for example `set -a; source .env; set +a`, or pass them with
`docker run --env-file`, Compose `env_file`, or your process manager. A fully documented
template lives in [`.env.example`](https://github.com/KKloudTarus/synapse-ce/blob/main/.env.example).

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
| `SYNAPSE_MEASURE_CURSOR_SECRET` | Ephemeral in development; required in production | HMAC key for signing Measures pagination cursors; minimum 32 bytes |

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
| `SYNAPSE_OWNED_ADVISORY` | `true` | Match the SBOM against the owned advisory store, alongside the live and offline sources. Populate it first with `synapse-cli sync-advisories`. |
| `SYNAPSE_JARHASH_ONLINE_ENABLED` | `false` | Recover the coordinate of a shaded or metadata-less JAR by its SHA-1. |
| `SYNAPSE_OSV_URL`, `SYNAPSE_OSV_BULK_URL`, `SYNAPSE_DEPSDEV_URL`, `SYNAPSE_KEV_URL`, `SYNAPSE_EPSS_URL` | (public) | Feed overrides for tests or mirrors. |

## Extra scanners and detection tuning (opt-in)

Most of these ship ON by default (safe, best-effort). See [Features](features.md) for what each one does.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_SECRET_SCAN_ENABLED` | `true` | Secret scanning over the workspace (regex plus entropy). Matches are redacted; the raw secret never reaches logs, evidence, or the report. |
| `SYNAPSE_MISCONFIG_ENABLED` | `true` | Misconfiguration and IaC scanning of Dockerfiles and Kubernetes manifests. |
| `SYNAPSE_DETECTION_PRIORITY` | `comprehensive` | `comprehensive` reports every match. `precise` quarantines single-source, non-KEV findings into a needs-verify queue that is still reported and sealed but exempt from the `--fail-on` gate. |
| `SYNAPSE_OFFLINE` | `false` | Skip the live advisory source and detect with the offline database only. |
| `SYNAPSE_IGNORE_UNFIXED` | `false` | Drop vulnerabilities that have no fixed version. |
| `SYNAPSE_DB_MAX_AGE_DAYS` | `30` | Warn when a dated reference database (KEV, EPSS, or the Grype DB) is older than this many days. 0 disables the check. |
| `SYNAPSE_SUPPRESSION_ENABLED` | `true` | Honor a `.synapseignore` file. Acceptance exempts only the `--fail-on` gate; the finding is still reported, persisted, and evidence-sealed. |
| `SYNAPSE_VEX_ENABLED` | `true` | Consume an in-repo OpenVEX document (`.synapse.vex.json`) at scan time, on the same retain-and-mark surface as suppression. |
| `SYNAPSE_COMPLIANCE_ENABLED` | `true` | Compliance benchmark. Re-projects findings onto a control specification and reports per-control PASS or FAIL. |
| `SYNAPSE_SCAN_CACHE_ENABLED` | `true` | SBOM scan cache, addressed by content plus producer version. The cache directory must be operator-owned, since a shared-writable cache would allow poisoning. |
| `SYNAPSE_SCAN_CACHE_DIR` | (per-user) | Cache location. Empty uses a per-user cache directory. |
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

## MCP server (synapse-mcp)

Read and propose only. It never executes. Both variables are required to start it.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_MCP_TOKEN` | (none) | Bearer token. Never logged. |
| `SYNAPSE_MCP_ENGAGEMENT_ID` | (none) | The engagement the MCP server is scoped to. |
| `SYNAPSE_MCP_ADDR` | `:8081` | Listen address. |

Next: [CLI](cli.md)
