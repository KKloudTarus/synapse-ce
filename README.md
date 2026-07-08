<div align="center">

<img src="assets/logo-full-black.png#gh-light-mode-only" alt="Synapse" width="380">
<img src="assets/logo-full-white.png#gh-dark-mode-only" alt="Synapse" width="380">

### Verify Everything. Trust Nothing.

**A governed control plane for software composition analysis, recon, evidence, and reporting.**

Turn a fragmented, manual security process into a controlled, auditable workflow, with
server-side scope enforcement, hardened tool execution, tamper-evident evidence, and
deterministic reports.

[![License](https://img.shields.io/badge/license-Apache--2.0-6d5bff)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8)](go.mod)
[![Docs](https://img.shields.io/badge/docs-live-6d5bff)](https://synapse.kkloudtarus.net/)

[Landing page](https://synapse.kkloudtarus.net/) · [Documentation](docs/guide/README.md) · [Quickstart](#quickstart) · [Features](#features) · [Configuration](docs/guide/configuration.md)

</div>

---

> [!IMPORTANT]
> **Authorized use only.** Synapse is built for authorized security testing, pentest
> engagements, and defensive security work. Every engagement enforces an explicit scope and
> a legal authorization window, server-side, before any tool runs. You are responsible for
> holding written permission to test any target.

<div align="center">
<img src="assets/engagements-overview-part1.png" alt="Synapse engagements overview" width="900">
</div>

## What is Synapse

Synapse runs the security-assessment lifecycle behind one governed control plane: software
composition analysis, recon, evidence capture, findings, and reporting.

It is deterministic-first. Scanning, matching, license classification, and reporting are
pure, reproducible Go with nothing else in the path. Where automated analysis is offered it
stays strictly bounded: a proposal is only ever proposed, a typed Go state machine validates
and executes, scope and authorization are checked in the execution layer, secrets never leave
the server, every artifact is hash-chained into a tamper-evident custody record, and a human
approves anything intrusive.

## Features

- **SBOM generation** across many ecosystems (npm, PyPI, Maven, Gradle, Go, Cargo, RubyGems,
  Composer, NuGet, Hex, Dart and more), with owned per-ecosystem lockfile parsers.
- **Vulnerability detection** from a live advisory API and an offline database,
  cross-correlated and de-duplicated, plus an owned advisory store that ingests OSV, GHSA and
  CSAF feeds for detection independence.
- **Risk-based prioritization**: findings are ordered by exploitability (known-exploited
  catalog, then exploit-prediction score, then CVSS), never by raw CVSS alone.
- **License compliance**: declared-license resolution, SPDX expression parsing, a curated
  category and risk model, and coordinate recovery for shaded or metadata-less JARs.
- **Reachability**: a deterministic call-graph engine decides whether a vulnerable symbol is
  actually reachable from application code.
- **Tamper-evident evidence**: every artifact is hash-chained. A broken chain blocks the
  report. Audit and evidence logs are append-only.
- **Hardened execution**: tools are shelled out via argv arrays inside a Linux sandbox with
  egress scoping. Scope and the authorization window are enforced before any tool runs.
- **RBAC and tenant isolation** through a single authorization chokepoint.
- **Standards native**: CycloneDX and SPDX with PURL, SARIF, OpenVEX and CSAF, plus KEV and EPSS.
- **Deterministic reports** templated from stored data, with a curated CWE to OWASP, PCI and
  ISO compliance mapping.
- **Bounded AI analysis** (optional): the agent proposes, a distinct verifier or a human
  confirms. No model ever sits in the report path.

See the full walkthrough with screenshots on the [documentation site](https://synapse.kkloudtarus.net/#screens).

## Quickstart

### Prerequisites

- Go 1.26 (pinned in `go.mod`), Node and pnpm (use pnpm, not npm or yarn).
- Syft (required for any scan) and Grype (optional, adds the offline database). `make tools`
  installs both, pinned and checksum-verified, into `./bin`.
- Docker is optional and is the easiest way to run the full stack.
- The hardened sandbox and live recon need a Linux host. Without them the API still runs
  (SCA, findings, reports); sandboxed execution fails closed rather than running unsandboxed.

### Run the full stack with Docker

```bash
docker compose -f deploy/docker-compose.full.yml up --build
# then open http://localhost:5173
```

### Run natively (development)

```bash
make install                       # Go modules + web deps
make tools                         # syft + grype into ./bin
export PATH="$PWD/bin:$PATH"

export SYNAPSE_API_TOKEN="$(openssl rand -hex 32)"   # required, no anonymous access
make dev                           # API on :8080, dashboard on :5173
```

Open <http://localhost:5173>, paste the token, accept the Acceptable Use Policy. A blank
`SYNAPSE_DB_DSN` runs an in-memory dev store, so nothing is persisted. Migrations are embedded
and applied automatically at startup.

## Command line

`synapse-cli` runs the same pipeline as the server, ideal for CI gating.

```bash
make build
./bin/synapse-cli scan ./path/to/project --fail-on high
```

The exit code is 0 when no finding meets the threshold, non-zero otherwise.

## Binaries

| Binary | Role |
| --- | --- |
| `synapse-api` | HTTP API server, the primary service |
| `synapse-cli` | Run an SCA scan from the command line, CI-friendly |
| `synapse-worker` | Durable job runner for recon and background jobs, lease-based |
| `synapse-callgraph` | Sandboxed call-graph builder for reachability analysis |
| `synapse-mcp` | Read-only, propose-only integration server, never executes |

## Architecture

Clean architecture with a strict, inward-only dependency rule:

```
domain  <-  usecase  <-  adapter / infrastructure
```

All external I/O (database, tools, storage, sandbox) goes through ports, which are interfaces
in `internal/usecase/ports`. `cmd/*` is the composition root, with dependency injection in
`main` and no business logic.

## Configuration

Synapse reads its configuration from the process environment. Copy `.env.example` and adjust.
The only required variable is `SYNAPSE_API_TOKEN`. See the
[configuration reference](docs/guide/configuration.md) for the full list.

Full documentation lives in [`docs/guide/`](docs/guide/README.md): introduction, installation,
quickstart, features, configuration, CLI, architecture, deployment, and the security model.

## Contributors

Synapse was built by its founding team.

| | Contributor | Role |
| --- | --- | --- |
| <img src="https://github.com/nghiadaulau.png?size=80" width="46" height="46" alt="nghiadaulau"> | [**nghiadaulau**](https://github.com/nghiadaulau) | Engineer |
| <img src="https://github.com/nnatuan03.png?size=80" width="46" height="46" alt="nnatuan03"> | [**nnatuan03**](https://github.com/nnatuan03) | Engineer |
| <img src="https://github.com/lethanhsang188.png?size=80" width="46" height="46" alt="lethanhsang188"> | [**lethanhsang188**](https://github.com/lethanhsang188) | Engineer |
| <img src="https://github.com/tuu-ngo.png?size=80" width="46" height="46" alt="tuu-ngo"> | [**tuu-ngo**](https://github.com/tuu-ngo) | Brand identity designer |

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), the
[Code of Conduct](CODE_OF_CONDUCT.md), and report vulnerabilities per the
[Security Policy](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
