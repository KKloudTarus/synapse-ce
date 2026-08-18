# Quickstart

[Documentation home](README.md) · Previous: [Installation](installation.md) · Next: [Features](features.md)

This guide takes you from a clone to a running dashboard, then through a first scan.

## 1. Start the stack

The fastest path is Docker, which runs PostgreSQL, MinIO, the API, and the dashboard. Create a local env file first; the Compose stack deliberately has no default database passwords or DSNs:

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
  -f deploy/docker-compose.full.yml up --build
```

Keep `deploy/.env.local` out of version control and use URL-safe passwords in these example DSNs. For passwords containing URL-reserved characters, percent-encode the password component or supply a correctly encoded complete DSN. Reusing an existing PostgreSQL volume with different credentials causes authentication failures; preserve the original credentials or, for disposable local data only, reset with `docker compose --env-file deploy/.env.local -f deploy/docker-compose.full.yml down -v` before starting again.

This Compose profile is for an isolated local development machine. It publishes the API, PostgreSQL, MinIO, and dashboard ports and deliberately disables the Linux sandbox because plain containers cannot run bubblewrap. Do not expose it to an untrusted network or submit untrusted targets. Use the hardened deployment requirements in [Deployment](deployment.md) for real assessments.

Or run it natively for development:

```bash
make install
make tools
export PATH="$PWD/bin:$PATH"

export SYNAPSE_API_TOKEN="$(openssl rand -hex 32)"   # required, no anonymous access
make dev                                             # API on :8080, dashboard on :5173
```

`SYNAPSE_API_TOKEN` is the only required development setting. The server refuses to start without it.
Operational API routes require it; liveness `GET /healthz` and dependency readiness `GET /readyz` are
intentionally public so probes work without a credential.

A blank `SYNAPSE_DB_DSN` runs the development persistence: in-memory stores plus a few local files such as
`data/audit.jsonl`. It is not durable and not suitable for real work, but it is not purely ephemeral
either. Set a DSN for PostgreSQL. Development applies embedded migrations automatically. Production runs
`synapse-migrate` with `SYNAPSE_DB_MIGRATION_DSN` before starting services with `SYNAPSE_DB_AUTO_MIGRATE=false`.

## 2. Log in

Open <http://localhost:5173>. Paste the API token. On first run you accept the Acceptable Use
Policy, which records that you understand Synapse is for authorized testing only.

## 3. Create an engagement

An engagement is the container for a piece of authorized work. Create one with:

- a name and client,
- an in-scope target (for example a domain),
- an authorization window (from and to timestamps).

Nothing runs outside that scope and window.

## 4. Run a scan

You have two ways to feed the scanner.

**Scan a target directly.** From the dashboard, point the scan at a local path or a git reference. Synapse
generates the SBOM and runs detection.

Two constraints are enforced server-side, so it is worth knowing them before the first attempt:

- A local target must be an **absolute path** that the API process can read. A relative path is rejected.
- Container image and archive targets are **not yet supported on this endpoint**. To scan an image today,
  use the CLI: `synapse-cli scan alpine:3.19 --image`.

**Import a client SBOM.** If the client handed you a CycloneDX SBOM, use Import SBOM on the
engagement. That makes their inventory a first-class, attested artifact. To then compute
vulnerabilities against it, run a scan on the engagement with an empty target. Synapse reuses
the imported SBOM and runs the detection half of the pipeline.

## 5. Review

- **Vulnerabilities** are ranked by real risk, not raw CVSS.
- **Findings** are the tracked units you triage, as a table or a board.
- **Licenses** show SPDX categories and a risk posture.
- **Components** and the **dependency graph** show the full inventory.
- **Evidence** shows the hash-chained custody record.
- **Audit log** records every action, attributable to a person or an agent id.

## 6. Report

Assemble a report from the stored data. Reports are templated and deterministic. Export as
PDF, or in a standard format such as SARIF, CycloneDX, SPDX, or OpenVEX.

## Gate CI instead

For pipelines, skip the UI and use the [CLI](cli.md). It runs the same pipeline with no server or database,
and accepts a relative path:

```bash
./bin/synapse-cli scan . --fail-on high
```

Exit `0` means nothing met the threshold, `1` means the gate fired, and `2` means the invocation itself was
invalid. See the [exit-code contract](cli.md#exit-codes).

## Where to go next

- [Project code quality](project-code-quality.md) to track a codebase over time and gate merges.
- [Governed assessments](governed-assessment-workflows.md) for scope, evidence, and reporting.
- [Configuration](configuration.md) for the full environment reference.
- [Deployment](deployment.md) before running this anywhere real.

Next: [Features](features.md)
