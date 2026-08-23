# Architecture

[Documentation home](README.md) · Previous: [CLI](cli.md) · Next: [Deployment](deployment.md)

Synapse is clean-architecture Go. Dependencies point inward only.

```
domain  <-  usecase  <-  adapter / infrastructure
```

## The dependency rule

| Layer | Path | May import |
| --- | --- | --- |
| domain | `internal/domain/*` | only domain and the standard library; `golang.org/x/net/idna` is the sole sanctioned pure-Go standards exception for canonical IDNA processing |
| usecase | `internal/usecase/*` | domain and the ports it defines |
| adapter | `internal/adapter/*` | usecase and domain |
| infrastructure | `internal/infrastructure/*` | the ports it implements, plus domain |
| platform | `internal/platform/*` | standard library, domain and ports |
| composition | `internal/composition/*` | usecase, infrastructure, and platform packages needed for shared composition |

All external I/O (database, tools, LLM, sandbox, storage) goes through ports, which are
interfaces in `internal/usecase/ports`. The domain stays pure, with no framework, database, or
tool types in it. `cmd/*` remains the composition root: it wires concrete implementations into the
interfaces in `main`, and holds no business logic. Shared wiring that is reused by multiple binaries
lives in `internal/composition/*`, above the platform and infrastructure packages it composes.

## Projects and engagements

A **Project** is a long-lived code-quality identity: it binds source and configuration and will
own its analysis history. An **Engagement** is a time-bounded security assessment whose scope,
authorization window, and lifecycle gate all execution. They are independent aggregates; neither
owns the other. Both may invoke the same analysis pipeline, while future project analyses reference
their Project instead of duplicating or forking that engine.

## Binaries

`cmd/` holds 15 composition roots. They fall into four groups.

**Services**

| Binary | Role |
| --- | --- |
| `synapse-api` | HTTP API server, the primary service and largest composition root. |
| `synapse-worker` | Durable, lease-based job runner for recon, scheduled provider work, and background jobs. Leader-gated. |
| `synapse-mcp` | Read and propose-only MCP integration. It has no executor and no gate, so it never executes. |

**Command line**

| Binary | Role |
| --- | --- |
| `synapse-cli` | CI-oriented scanner and code-quality gate using the same pipeline as the server. |

**Sandboxed helpers**

Each isolates a capability-sensitive or untrusted-input workload out of the server process.

| Binary | Role |
| --- | --- |
| `synapse-callgraph` | `go/ssa` call-graph builder for reachability and taint. |
| `synapse-ast` | tree-sitter AST parsing of untrusted source. Exit code 3 means the backend is unavailable in a CGO-free build. |
| `synapse-cspm` | Cloud posture collection for AWS, Azure, and GCP. Read-only, with credentials passed by inherited file descriptor. |
| `synapse-dast-helper` | Governed DAST crawling and checks under kernel-enforced egress confinement. |

**Fleet agents**

| Binary | Role |
| --- | --- |
| `synapse-agent` | Host inventory and, on Linux, eBPF runtime detections. |
| `synapse-cluster-agent` | Kubernetes workload, exposure, and identity inventory. |

**AI-triage evaluation tools**

Offline governance utilities. None participates in a live scan.

| Binary | Role |
| --- | --- |
| `synapse-fptriage-eval` | Offline evaluation harness against golden datasets. |
| `synapse-fptriage-compare` | Deterministic candidate-versus-baseline promotion gate. |
| `synapse-fptriage-release` | Versioned promotion and rollback ledger. |
| `synapse-fptriage-curate` | Privacy- and label-reviewed reviewer-feedback curation. |
| `synapse-fptriage-drift` | Input distribution drift detection. |

## Tool integration

Light, pure-Go tools run in process as libraries. Heavy or capability-sensitive tools are
shelled out to pinned binaries via argv arrays: Syft and Grype for SBOM and vulnerabilities,
and recon tools where enabled. The same rule isolates heavy analysis of untrusted source. The
call-graph builder runs only inside the sandboxed `synapse-callgraph` binary, never in the
server process.

## The AI analysis layer

The analysis layer is a cross-cutting concern that turns raw scanner and agent output into
confirmed findings. It is deterministic-first and gated. Every claim is a typed judgment with a
lifecycle of propose, verify, confirm. Gated capabilities promote only on a distinct verifier's
sealed verdict above the evidence threshold. The agent is propose-only, so it can never confirm
its own claim. No model ever sits in the report path.

## Persistence and migrations

Persistence is PostgreSQL when a DSN is set, and an in-memory store otherwise. Migrations are
numbered SQL files embedded in the binary. Development services apply them automatically; production
uses the dedicated `synapse-migrate` command with the owner credential before API, worker, and MCP
start with their runtime credential. A shipped migration is never edited. A new numbered file is appended.

Production rollouts are migrate-first and migrations must be backward-compatible and phased: apply the
schema expansion before deploying binaries that use it, and defer destructive changes until every older
binary is gone. The API remains live but reports stale schema through `/readyz`; workers and the MCP
server refuse startup on stale schema because they have no readiness endpoint to withdraw. Readiness
accepts only an applied database migration newer than the binary's embedded maximum, which permits
that migrate-first overlap while rejecting a missing, down, or divergent required migration.

Next: [Deployment](deployment.md)
