# Deployment

[Documentation home](README.md) · Previous: [Architecture](architecture.md) · Next: [Security model](security.md)

Synapse ships as a set of Go binaries plus a web dashboard. The provided Compose stack is the quickest local-development deployment. It is not the recommended production topology: it publishes development service ports and runs the API sandbox-off.

## Full stack with Docker Compose

The `deploy/docker-compose.full.yml` stack runs everything: PostgreSQL, an S3-compatible object
store, the API server with Syft and Grype bundled, and the web dashboard.

The stack requires explicit database credentials and complete runtime/migration DSNs. From the repository root:

```bash
cat > deploy/.env.local <<'EOF'
DB_ADMIN_PASSWORD=replace-with-a-strong-local-admin-password
DB_APP_PASSWORD=replace-with-a-different-local-app-password
BLOB_PASSWORD=replace-with-a-third-local-password
SYNAPSE_API_TOKEN=replace-with-a-random-token
SYNAPSE_DB_DSN=postgres://synapse_app:replace-with-a-different-local-app-password@postgres:5432/synapse?sslmode=disable
SYNAPSE_DB_MIGRATION_DSN=postgres://synapse_admin:replace-with-a-strong-local-admin-password@postgres:5432/synapse?sslmode=disable
EOF

docker compose --env-file deploy/.env.local \
  -f deploy/docker-compose.full.yml up -d --build --wait
```

`--env-file` is intentional: Compose does not infer `deploy/.env.local` merely because the Compose file lives in `deploy/`. Keep the file out of version control. Use URL-safe example passwords, or percent-encode reserved characters in complete DSNs. PostgreSQL stores its initial credentials in `pgdata`; changing the env file does not rewrite an existing role password. Keep the original credentials, rotate them in PostgreSQL, or reset disposable local state with `down -v`.

Treat this profile as local development only. Its ports bind beyond loopback by default, MinIO has administrative access to the evidence bucket, and `SYNAPSE_SANDBOX_ENABLED=false` means source-acquisition and tool processes lack Synapse's required production containment. Restrict it with host firewall rules and use only trusted fixture targets. A production deployment must enable the fail-closed Linux sandbox, keep data services private, terminate TLS, and follow the checklist below.

| Service | Port | Purpose |
| --- | --- | --- |
| `synapse-api` | 8080 | HTTP API |
| `web` | 5173 | Web dashboard |
| `postgres` | 5432 | Database |
| `minio` | 9000, 9001 | Object store and console |

Init containers (`postgres-init`, `minio-init`, `project-source-artifacts-init`) prepare the database,
bucket, and source-artifact volume before the API starts.

## Beyond a single API

The Compose stack is the smallest useful deployment. Three components run separately in a real
installation:

**`synapse-worker`** is required for durable recon, scheduled vulnerability-intelligence work, CSPM runs,
and fleet dispatch. It is lease-based, so enable `SYNAPSE_LEADER_ENABLED` and run it alongside the API
rather than inside it.

**Fleet agents** run on the hosts being defended, not on the control plane. `synapse-agent` needs Linux
with eBPF for runtime detections; `synapse-cluster-agent` runs in-cluster or with a kubeconfig. Both enroll
with a one-time token and then authenticate with a client certificate. See
[Fleet and runtime defense](fleet-blue-team.md) and
[Fleet agent packaging](fleet-agent-packaging.md).

**Sandboxed helpers** (`synapse-callgraph`, `synapse-ast`, `synapse-cspm`, `synapse-dast-helper`) are
executed by the server as pinned binaries. They need to be present on the host or image, and in production
should be referenced by absolute path with hashes pinned in `SYNAPSE_TOOL_HASHES`.

The stack reads its settings from environment variables with dev defaults. Change them for
anything but local development. Put real values in a `.env` file next to the Compose file, or
export them in your shell.

## Image targets

`deploy/Dockerfile` builds two images.

- **api**: a minimal distroless image with only the `synapse-api` binary. Smallest and most
  locked-down. Scan against an SBOM you provide, or keep Syft and Grype on PATH.
- **full**: a Debian-based image that bundles pinned Syft and Grype for an end-to-end scan.

```bash
docker build -t synapse-api:latest --target api -f deploy/Dockerfile .
docker build -t synapse:full --target full -f deploy/Dockerfile .
```

The build is cgo-free, so the distroless image works with a pure-Go SQLite driver and no
system libraries.

## Production checklist

Required, by variable name. Any `SYNAPSE_ENV` value other than `development`, `dev`, `local`, `test`, or
`ci` is treated as production and activates the fail-closed gates:

| Variable | Requirement |
| --- | --- |
| `SYNAPSE_ENV` | Left at its production value, so the strict gates stay on |
| `SYNAPSE_API_TOKEN` | A strong random value; the server refuses to start without it |
| `SYNAPSE_DB_DSN` | Managed PostgreSQL with TLS |
| `SYNAPSE_VAULT_MASTER_KEY` | Credential-vault master key. Without it, stored secrets do not survive a restart |
| `SYNAPSE_EVIDENCE_SIGNING_SEED` | Ed25519 seed giving the evidence and audit chain a stable key ID |
| `SYNAPSE_MEASURE_CURSOR_SECRET` | HMAC key signing measure pagination cursors |
| `SYNAPSE_SANDBOX_ENABLED` | `true` on a Linux host. If set and bubblewrap is missing, startup fails closed |
| `SYNAPSE_BLOB_ENDPOINT` | Object store for evidence artifacts |

Recommended hardening:

- Give migrations a separate owner-level identity with `SYNAPSE_DB_MIGRATION_DSN`, keeping the runtime DSN
  least-privileged.
- Pin tool hashes with `SYNAPSE_TOOL_HASHES` so the sandbox refuses an unexpected binary. Empty means
  trust-on-first-use.
- Set `SYNAPSE_TSA_URL` to anchor the evidence chain externally, making it tamper-proof rather than only
  tamper-evident.
- Enable `SYNAPSE_LEADER_ENABLED` when running more than one API or worker, so scheduled dispatch runs
  exactly once.
- Terminate TLS at your load balancer or reverse proxy in front of the API.
- Back up the database and the evidence object store together; a report depends on both.

`GET /healthz` is unauthenticated by design. Every other API route requires the bearer token.

## Health check

The API exposes an unauthenticated `GET /healthz` for liveness and readiness probes.

```bash
curl -s http://localhost:8080/healthz
```

Next: [Security model](security.md)
