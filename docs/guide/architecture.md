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

All external I/O (database, tools, LLM, sandbox, storage) goes through ports, which are
interfaces in `internal/usecase/ports`. The domain stays pure, with no framework, database, or
tool types in it. `cmd/*` is the composition root: it wires concrete implementations into the
interfaces in `main`, and holds no business logic.

## Projects and engagements

A **Project** is a long-lived code-quality identity: it binds source and configuration and will
own its analysis history. An **Engagement** is a time-bounded security assessment whose scope,
authorization window, and lifecycle gate all execution. They are independent aggregates; neither
owns the other. Both may invoke the same analysis pipeline, while future project analyses reference
their Project instead of duplicating or forking that engine.

## Binaries

| Binary | Role |
| --- | --- |
| `synapse-api` | HTTP API server, the primary service. |
| `synapse-cli` | Run an SCA scan from the command line, CI-friendly. |
| `synapse-worker` | Durable job runner for recon and background jobs, lease-based. |
| `synapse-callgraph` | Sandboxed call-graph builder for reachability analysis. It keeps the heavy analysis library out of the server. |
| `synapse-mcp` | Read-only, propose-only integration server. It never executes. |

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
numbered SQL files, embedded in the binary, and applied automatically at startup. There is no
separate migrate step. A shipped migration is never edited. A new numbered file is appended.

Next: [Deployment](deployment.md)
