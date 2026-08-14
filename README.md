<div align="center">

<img src="assets/logo-full-black.png#gh-light-mode-only" alt="Synapse" width="380">
<img src="assets/logo-full-white.png#gh-dark-mode-only" alt="Synapse" width="380">

### Verify Everything. Trust Nothing.

**A governed control plane for the whole security-assessment lifecycle — supply chain, code,
cloud, offensive, and runtime defense.**

Turn a fragmented, manual security process into one controlled, auditable workflow: SCA, SAST,
secret and IaC scanning, reachability, recon and governed exploitation, cloud posture, and a
distributed blue-team agent fleet — all behind server-side scope enforcement, hardened tool
execution, tamper-evident evidence, and deterministic reports.

[![License](https://img.shields.io/badge/license-Apache--2.0-6d5bff)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8)](go.mod)
[![Docs](https://img.shields.io/badge/docs-live-6d5bff)](https://synapse.kkloudtarus.net/)
[![CI](https://github.com/KKloudTarus/synapse-ce/actions/workflows/ci.yml/badge.svg)](https://github.com/KKloudTarus/synapse-ce/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/KKloudTarus/synapse-ce)](https://goreportcard.com/report/github.com/KKloudTarus/synapse-ce)

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

## Why Synapse

- ✅ **Deterministic first.** Scanning, matching, and reporting are pure, reproducible Go. No model sits in the report path.
- ✅ **Evidence you can trust.** Every artifact is hash-chained into a tamper-evident custody record. A broken chain blocks the report.
- ✅ **One platform, every angle.** Supply chain, code, cloud, offensive, and runtime defense behind a single gate.
- ✅ **Reachability aware.** A deterministic call graph decides whether a vulnerable symbol is actually reachable from your code.
- ✅ **Detection independent.** Owns its SBOM parsers and advisory matching, and ingests OSV, GHSA, CSAF and OVAL.
- ✅ **A detection is evidence, not an alert.** Runtime detections are attributable, hash-chained, and joined to the same asset, finding, and attack path the static pillars reason about.
- ✅ **CI ready.** `synapse-cli` is a single static binary that gates a build and emits SARIF for code scanning.
- ✅ **Safe by construction.** argv-only execution in a Linux sandbox, server-side scope and authorization before any tool runs, secrets never leave the server.

## What is Synapse

Synapse runs the whole security-assessment lifecycle behind one governed control plane, across
both point-in-time analysis (SCA, SAST, code quality, IaC) and runtime analysis (a distributed
agent fleet, eBPF detections, response actions), over container and VM estates, with a single
asset model, one authorization model, one hash-chained evidence chain, and one prioritized queue.

It is deterministic-first. Scanning, matching, license classification, scoring, and reporting are
pure, reproducible Go with nothing else in the path. Where automated analysis is offered it stays
strictly bounded: a proposal is only ever proposed, a typed Go state machine validates and
executes, scope and authorization are checked in the execution layer, secrets never leave the
server, every artifact is hash-chained into a tamper-evident custody record, and a human approves
anything intrusive.

## Features

**Software supply chain**
- **SBOM generation** across many ecosystems (npm, PyPI, Maven, Gradle, Go, Cargo, RubyGems,
  Composer, NuGet, Hex, Dart, pnpm, Poetry, yarn and more) with owned per-ecosystem lockfile parsers.
- **Vulnerability detection** from a live advisory API and an offline database, cross-correlated
  and de-duplicated, plus an owned advisory store that ingests OSV, GHSA, CSAF and OVAL for
  detection independence.
- **Risk-based prioritization** ordered by exploitability (CISA KEV, then EPSS, then CVSS), never
  by raw CVSS alone.
- **License compliance**: declared-license resolution, SPDX expression parsing, a curated category
  and risk model, and coordinate recovery for shaded or metadata-less JARs.
- **Reachability**: a deterministic call-graph engine (Go, plus JVM and JS/TS tiers) decides
  whether a vulnerable symbol is actually reachable from application code.

**Code & configuration**
- **First-party SAST** with source-code rules across many languages, plus a taint engine over the
  sandboxed call graph.
- **Secret scanning** and **IaC misconfiguration** (Terraform, CloudFormation, ARM, Kubernetes,
  Helm, Dockerfile, Compose).
- **Code quality** rules, quality gates and profiles, and third-party **SARIF ingest** into the
  same governance path.

**Offensive**
- **Recon** in a hardened sandbox, an **attack-path graph** over the asset inventory, **chained
  exploitation with per-step proof**, and **adversary emulation** with expected-detection output —
  all gated by a written offensive policy and a kill switch.
- **DAST**: authenticated crawling and a first-party check corpus with sessions from the credential vault.

**Runtime defense (blue team)**
- A distributed **agent fleet** (host and Kubernetes cluster inventory, coverage/freshness,
  signed packaging and updates) with certificate enrolment and fenced leadership.
- An **eBPF detection engine**, **detections sealed as hash-chained evidence**, a **columnar
  telemetry tier** with retention, **governed response actions** (same admission + evidence as
  exploitation), and **purple-team coverage** measured from emulation-expected vs actually-fired.

**Cloud posture (CSPM)**
- Read-only **AWS, Azure and GCP** posture connectors behind a sandboxed helper, with vault-ref
  credentials over an inherited FD, per-operation server-side authorization, and IaC-vs-live drift findings.

**Governance & evidence**
- **Tamper-evident evidence**: every artifact is hash-chained (RFC-3161 anchored); a broken chain
  blocks the report. Audit and evidence logs are append-only.
- **Hardened execution**: tools run via argv arrays inside a Linux sandbox with egress scoping;
  scope and the authorization window are enforced before any tool runs.
- **RBAC, tenant isolation (Postgres RLS), and separation of duties** through a single authorization chokepoint.
- **The Judgment primitive**: every AI/analysis claim is propose → verify → confirm; gated
  capabilities promote only on a distinct verifier's sealed verdict.

**AI analysis (optional, bounded)**
- **AI false-positive triage** grounded in deterministic evidence citations, with provider-independent
  proposer/verifier separation of duties, budgets, circuit breakers, observability, and a fail-closed
  adversarial counterfactual gate for model/prompt promotion.
- The agent proposes; a distinct verifier or a human confirms. **No model ever sits in the report path.**

**Standards & reports**
- **Standards native**: CycloneDX and SPDX with PURL, SARIF, OpenVEX and CSAF, plus KEV and EPSS.
- **Deterministic reports** templated from stored data, with a curated CWE → OWASP, PCI and ISO compliance mapping.

See the full walkthrough with screenshots on the [documentation site](https://synapse.kkloudtarus.net/#screens).

## How it compares

Detection is at parity with the popular scanners, and sometimes ahead. On one representative
real-world repository, Synapse reported 261 unique CVEs to Trivy's 239 (235 in common) and
attached a license to 1443 packages to Trivy's 1394. Numbers move with the project, so treat
these as illustrative rather than a benchmark claim.

The lasting difference is what sits around the finding:

| Capability | Synapse | Most scanners |
| --- | --- | --- |
| SCA, license, IaC misconfig, secret scanning | Yes | Yes |
| First-party SAST (source-code rules) | Yes | Usually no |
| Reachability via a call graph | Yes | Rarely |
| Offensive: attack paths, chained exploitation, emulation, DAST | Yes | No |
| Runtime blue team: agent fleet, eBPF detections, response actions | Yes | No |
| Detections sealed as hash-chained evidence, joined to the same asset | Yes | No |
| Cloud posture (AWS/Azure/GCP), IaC-vs-live drift | Yes | Varies |
| Hash-chained, tamper-evident evidence | Yes | No |
| Server-side scope and authorization before a tool runs | Yes | No |
| RBAC, tenant isolation (RLS), separation of duties | Yes | No |
| Deterministic, model-free report path | Yes | Varies |

## Quickstart

### Prerequisites

- Go 1.26 (pinned in `go.mod`), Node and pnpm (use pnpm, not npm or yarn).
- Syft (required for any scan) and Grype (optional, adds the offline database). `make tools`
  installs both, pinned and checksum-verified, into `./bin`.
- Docker is optional and is the easiest way to run the full stack.
- The hardened sandbox and live recon need a Linux host. Without them the API still runs
  (SCA, findings, reports); sandboxed execution fails closed rather than running unsandboxed.

### Install a released build

Grab a prebuilt binary from the [Releases page](https://github.com/KKloudTarus/synapse-ce/releases)
(linux, macOS and Windows; amd64 and arm64) and verify it against `checksums.txt`. Each archive bundles
the packaged commands.

```bash
# Example: linux/amd64
curl -fsSL -o synapse.tar.gz \
  https://github.com/KKloudTarus/synapse-ce/releases/latest/download/synapse-ce_<version>_linux_amd64.tar.gz
tar -xzf synapse.tar.gz synapse-cli
./synapse-cli scan ./path/to/project --fail-on high
```

Or scan with zero install using the container image (bundles `synapse-cli` plus syft and grype):

```bash
docker run --rm -v "$PWD:/scan:ro" ghcr.io/kkloudtarus/synapse-cli scan /scan --fail-on high
```

Gate a repository in CI with the reusable action (see [`docs/guide/cli.md`](docs/guide/cli.md#github-action)):

```yaml
- uses: KKloudTarus/synapse-ce@v1
  with:
    fail-on: high
```

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
| `synapse-cli` | Run an SCA/SAST scan from the command line, CI-friendly (SARIF, `--fail-on`) |
| `synapse-worker` | Durable job runner for recon and background jobs, lease-based, leader-gated |
| `synapse-callgraph` | Sandboxed `go/ssa` call-graph builder for reachability and taint |
| `synapse-ast` | Sandboxed tree-sitter AST helper for source-code analysis |
| `synapse-cspm` | Sandboxed cloud-posture helper (AWS/Azure/GCP), read-only, FD-passed credentials |
| `synapse-dast-helper` | Sandboxed DAST crawler/check helper |
| `synapse-agent` | Fleet agent: host inventory and eBPF runtime detections |
| `synapse-cluster-agent` | Fleet agent: Kubernetes workload/exposure/identity inventory |
| `synapse-fptriage-eval` | Offline evaluation harness for AI false-positive triage |
| `synapse-fptriage-compare` | Deterministic candidate-vs-baseline gate for AI model/prompt promotion review |
| `synapse-fptriage-release` | Versioned PM/Security-approved promotion and rollback ledger for AI triage |
| `synapse-fptriage-curate` | Offline privacy- and label-reviewed feedback curation for AI false-positive evaluation |
| `synapse-fptriage-drift` | Offline language/CWE/project distribution drift evidence for AI triage |
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
The only required variable in development is `SYNAPSE_API_TOKEN`. In production, `SYNAPSE_MEASURE_CURSOR_SECRET` is also required (generated via `openssl rand -hex 32`). See the
[configuration reference](docs/guide/configuration.md) for the full list.

Full documentation lives in [`docs/guide/`](docs/guide/README.md): introduction, installation,
quickstart, features, configuration, CLI, architecture, deployment, and the security model.
See [`CHANGELOG.md`](CHANGELOG.md) for what has changed.

## Roadmap

Synapse is under active development. Near-term directions:

- **Continuous vulnerability intelligence and risk management** ([epic #514](https://github.com/KKloudTarus/synapse-ce/issues/514)): keep the advisory corpus current, detect newly affected components without re-scanning, and recalculate risk when intelligence changes.
- **Correlation**: one unified risk story per asset, and cross-pillar promotion rules through the judgment gate.
- Broader ecosystem coverage: more owned lockfile parsers (Conda, R, Julia, Conan).
- More first-party SAST rules and reachability for more language ecosystems.
- Richer SARIF output, including remediation in code-scanning alerts.
- More curated, model-free compliance profiles, and more CI recipes and integration examples.

Have a request? Open an issue or start a discussion. Issues tagged
[`good first issue`](https://github.com/KKloudTarus/synapse-ce/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
and [`help wanted`](https://github.com/KKloudTarus/synapse-ce/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
are a good place to start.

## Team & contributors

Synapse is built by its founding team and contributors.

| | Member | Role |
| --- | --- | --- |
| <img src="https://github.com/nghiadaulau.png?size=80" width="46" height="46" alt="nghiadaulau"> | [**nghiadaulau**](https://github.com/nghiadaulau) | Founder |
| <img src="https://github.com/nnatuan03.png?size=80" width="46" height="46" alt="nnatuan03"> | [**nnatuan03**](https://github.com/nnatuan03) | Co-founder |
| <img src="https://github.com/pho-veteran.png?size=80" width="46" height="46" alt="pho-veteran"> | [**pho-veteran**](https://github.com/pho-veteran) | Lead maintainer |
| <img src="https://github.com/VietSory.png?size=80" width="46" height="46" alt="VietSory"> | [**VietSory**](https://github.com/VietSory) | Engineer |
| <img src="https://github.com/lethanhsang188.png?size=80" width="46" height="46" alt="lethanhsang188"> | [**lethanhsang188**](https://github.com/lethanhsang188) | Engineer |
| <img src="https://github.com/tuu-ngo.png?size=80" width="46" height="46" alt="tuu-ngo"> | [**tuu-ngo**](https://github.com/tuu-ngo) | Brand identity designer |
| <img src="https://github.com/H1eu232.png?size=80" width="46" height="46" alt="H1eu232"> | [**H1eu232**](https://github.com/H1eu232) | AI engineer (contributor) |
| <img src="https://github.com/XUanhoa04.png?size=80" width="46" height="46" alt="XUanhoa04"> | [**XUanhoa04**](https://github.com/XUanhoa04) | AI engineer (contributor) |
| <img src="https://github.com/thx2an.png?size=80" width="46" height="46" alt="thx2an"> | [**thx2an**](https://github.com/thx2an) | AI engineer (contributor) |

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), the
[Code of Conduct](CODE_OF_CONDUCT.md), and report vulnerabilities per the
[Security Policy](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
