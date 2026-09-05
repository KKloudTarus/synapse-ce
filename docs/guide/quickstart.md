# Quickstart

[Documentation home](README.md) · Previous: [Installation](installation.md) · Next: [Features](features.md)

This guide takes you from a clone to a running dashboard, then through a first scan.

## 1. Start the stack

The fastest path is Docker, which runs PostgreSQL, MinIO, the API, and the dashboard. Create a local env file first; the Compose stack deliberately has no default database passwords or DSNs, so that a first run cannot come up on a credential that is printed in this guide:

```bash
umask 077
DB_ADMIN_PASSWORD="$(openssl rand -hex 16)"
DB_APP_PASSWORD="$(openssl rand -hex 16)"
BLOB_PASSWORD="$(openssl rand -hex 16)"
cat > deploy/.env.local <<EOF
DB_ADMIN_PASSWORD=$DB_ADMIN_PASSWORD
DB_APP_PASSWORD=$DB_APP_PASSWORD
BLOB_PASSWORD=$BLOB_PASSWORD
SYNAPSE_API_TOKEN=$(openssl rand -hex 32)
SYNAPSE_DB_DSN=postgres://synapse_app:$DB_APP_PASSWORD@postgres:5432/synapse?sslmode=disable
SYNAPSE_DB_MIGRATION_DSN=postgres://synapse_admin:$DB_ADMIN_PASSWORD@postgres:5432/synapse?sslmode=disable
EOF

docker compose --env-file deploy/.env.local \
  -f deploy/docker-compose.full.yml up -d --build --wait
```

`--env-file` is required: Compose does not read `deploy/.env.local` merely because the Compose file lives in `deploy/`. `--wait` holds until every service is healthy, including the one-shot containers that create the database role and the evidence bucket. The first build compiles the Go binaries and the dashboard bundle, so expect it to take a while; later runs reuse the layers.

Confirm both surfaces before moving on:

```bash
curl localhost:8080/readyz                                  # {"status":"ready",...}
curl -s -o /dev/null -w '%{http_code}\n' localhost:5173/    # 200
```

`SYNAPSE_DB_DSN` names `synapse_app`, a `NOSUPERUSER NOBYPASSRLS` role, and `SYNAPSE_DB_MIGRATION_DSN` names the schema owner. Both are required and must differ: the API refuses to serve under a role that can bypass row level security, and it grants the runtime role its table privileges after migrating as the owner.

Keep `deploy/.env.local` out of version control; `.gitignore` already covers `.env.local`. Hex passwords are URL-safe; percent-encode reserved characters in any DSN you write by hand. Reusing an existing PostgreSQL volume with different credentials causes authentication failures; preserve the original credentials or, for disposable local data only, reset with `docker compose --env-file deploy/.env.local -f deploy/docker-compose.full.yml down -v` before starting again.

This Compose profile is for an isolated local development machine. It publishes the API, PostgreSQL, MinIO, and dashboard ports and deliberately disables the Linux sandbox because plain containers cannot run bubblewrap. Do not expose it to an untrusted network or submit untrusted targets. Use the hardened deployment requirements in [Deployment](deployment.md) for real assessments.

Or run it natively for development:

```bash
make install
make tools
export PATH="$PWD/bin:$PATH"

export SYNAPSE_API_TOKEN="$(openssl rand -hex 32)"   # required, no anonymous access
make dev                                             # API on :8080, dashboard on :5173
```

To back the native API with PostgreSQL instead of the in-memory stores, start the dependency stack and export both DSNs. Its one-shot `postgres-init` container creates the `synapse_app` role that the API connects as.

```bash
docker compose -f deploy/docker-compose.yml up -d   # Postgres + MinIO, project synapse-dev
# The stack's own defaults; set these in deploy/.env to use anything else.
export DB_PASSWORD="${DB_PASSWORD:-synapse}" DB_APP_PASSWORD="${DB_APP_PASSWORD:-synapse-app}"
export SYNAPSE_DB_DSN="postgres://synapse_app:${DB_APP_PASSWORD}@localhost:5432/synapse?sslmode=disable"
export SYNAPSE_DB_MIGRATION_DSN="postgres://synapse:${DB_PASSWORD}@localhost:5432/synapse?sslmode=disable"
make dev
```

These are throwaway local credentials. Pointing `SYNAPSE_DB_DSN` at the `synapse` superuser stops startup with `rls: runtime DB role cannot enforce isolation: role is SUPERUSER`, which is the server refusing to pretend that tenant isolation holds.

Skip `--wait` on this stack: Compose treats the exited `postgres-init` container as not running and reports a failure even when it exited 0. `docker compose -f deploy/docker-compose.yml run --rm postgres-init` blocks until the role exists and is idempotent.

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
- either an in-scope linked target or an uploaded source package,
- an authorization window (from and to timestamps).

The dashboard accepts `.zip`, `.tar`, `.tar.gz`, and `.tgz` source packages up to 512 MiB. Synapse stores
the package as an Engagement-owned artifact, verifies its SHA-256 before every scan, and extracts it into a
bounded temporary workspace. In API + worker deployments, both processes must point at the same S3/MinIO
bucket through the `SYNAPSE_BLOB_*` settings.

Nothing runs outside that scope and window.

## 4. Run a scan

You have two ways to feed the scanner.

**Upload source with the engagement.** Choose source upload while creating the engagement and select a
supported archive. Create & Scan starts the scan against that immutable package; no server filesystem path
or repository URL is exposed to the browser.

**Scan a target directly.** From the dashboard, point the scan at a local path or a git reference. Synapse
generates the SBOM and runs detection.

Two constraints are enforced server-side, so it is worth knowing them before the first attempt:

- A local target must be an **absolute path** that the API process can read. A relative path is rejected.
- A **container image** target is supported: set the kind to `image` and give a reference such as
  `docker.io/library/alpine:3.19`. The server pulls it daemonlessly (crane) and reports its OS and
  language package CVEs. The image must be in the engagement scope. The CLI form is
  `synapse-cli scan alpine:3.19 --image`.
- An **archive** is not scanned by reference on this endpoint; upload it through the source-upload flow.
- A **private git repository** is cloned when its host has a source-control connector configured in
  Settings (a personal access token, sealed server-side). Without a connector, only public repos clone.

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
