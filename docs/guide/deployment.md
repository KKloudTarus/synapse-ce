# Deployment

[Documentation home](README.md) · Previous: [Architecture](architecture.md) · Next: [Security model](security.md)

Synapse ships as a set of Go binaries plus a web dashboard. The recommended way to run it is
with the provided container images and Compose stack.

## Full stack with Docker Compose

The `deploy/docker-compose.full.yml` stack runs everything: PostgreSQL, an S3-compatible object
store, the API server with Syft and Grype bundled, and the web dashboard.

```bash
docker compose -f deploy/docker-compose.full.yml up --build
```

| Service | Port | Purpose |
| --- | --- | --- |
| `synapse-api` | 8080 | HTTP API |
| `web` | 5173 | Web dashboard |
| `postgres` | 5432 | Database |
| `minio` | 9000, 9001 | Object store and console |

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

- `SYNAPSE_ENV` is left at its production value. Any value other than development, dev, local,
  test, or ci enables the strict, fail-closed gates.
- `SYNAPSE_API_TOKEN` is a strong random value.
- `SYNAPSE_DB_DSN` points at a managed PostgreSQL with TLS.
- The credential-vault master key and the signing seed are set. Both are required in production.
- The object store is configured for evidence artifacts.
- Run on a Linux host so the execution sandbox and egress scoping are available.
- Terminate TLS at your load balancer or reverse proxy in front of the API.
- Back up the database and the evidence object store.

## Health check

The API exposes an unauthenticated `GET /healthz` for liveness and readiness probes.

```bash
curl -s http://localhost:8080/healthz
```

Next: [Security model](security.md)
