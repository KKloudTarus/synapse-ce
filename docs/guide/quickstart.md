# Quickstart

[Documentation home](README.md) · Previous: [Installation](installation.md) · Next: [Features](features.md)

This guide takes you from a clone to a running dashboard, then through a first scan.

## 1. Start the stack

The fastest path is Docker, which runs everything:

```bash
docker compose -f deploy/docker-compose.full.yml up --build
```

Or run it natively for development:

```bash
make install
make tools
export PATH="$PWD/bin:$PATH"

export SYNAPSE_API_TOKEN="$(openssl rand -hex 32)"   # required, no anonymous access
make dev                                             # API on :8080, dashboard on :5173
```

`SYNAPSE_API_TOKEN` is the only required setting. The server refuses to start without it.
A blank `SYNAPSE_DB_DSN` runs an in-memory dev store, so nothing is persisted. Database
migrations are embedded and applied automatically at startup.

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

**Scan a target directly.** Point the scan at a local path, a git reference, or a container
image. Synapse generates the SBOM and runs detection.

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
PDF, or in a standard format such as SARIF, SPDX, or OpenVEX.

## Gate CI instead

For pipelines, skip the UI and use the [CLI](cli.md):

```bash
./bin/synapse-cli scan . --fail-on high
```

Next: [Features](features.md)
