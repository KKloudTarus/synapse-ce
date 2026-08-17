# MCP integration

[Documentation home](README.md) · Previous: [CLI](cli.md) · Next: [Code quality rule authoring](code-quality-rules.md)

`synapse-mcp` exposes Synapse's agent tool catalog to an external AI client over the Model Context
Protocol. It is **read and propose only**, and the restriction is architectural rather than a policy
setting: the MCP server is constructed without an executor and without an execution gate, so there is no
code path through which it can run a tool.

## Start the server

```bash
export SYNAPSE_MCP_TOKEN="$(openssl rand -hex 32)"
export SYNAPSE_MCP_ENGAGEMENT_ID="eng_..."
./bin/synapse-mcp
```

| Variable | Default | Description |
| --- | --- | --- |
| `SYNAPSE_MCP_TOKEN` | (none) | Bearer token. Required. Never logged. |
| `SYNAPSE_MCP_ENGAGEMENT_ID` | (none) | The single engagement this server is scoped to. Required. |
| `SYNAPSE_MCP_ADDR` | `:8081` | Listen address. |

The session is engagement-locked at construction. A client cannot select or reach another engagement's
data, because the engagement is not a request parameter.

## Protocol surface

The server implements three methods: `initialize`, `tools/list`, and `tools/call`. `tools/list` returns the
catalog with each tool's JSON Schema; `tools/call` dispatches one tool. Every dispatch is audited under the
synthetic agent session ID, so MCP activity is attributable in the audit log like any other machine
principal.

Read tools cap their result rows and report the true total alongside a `truncated` flag, so a large
engagement cannot silently return a partial picture as if it were complete.

## Read-only tools

| Tool | Returns |
| --- | --- |
| `list_findings` | Findings for the engagement: ID, title, severity, kind, status, priority, KEV |
| `get_finding_detail` | Bounded detail for one finding, with a redacted description. Never raw source or evidence content |
| `list_sast_validation` | SAST candidates as a validation-closure table with blockers and counterevidence |
| `list_evidence` | Evidence-chain metadata: ID, kind, hash, previous hash, creator, timestamp. Never evidence content |
| `verify_custody` | Chain integrity: `{ok, count, head_hash}` |
| `list_recon_tools` | Recon tools that may be proposed, with accepted target kinds and risk class |
| `reachability_context` | Dependency-graph reachability facts |
| `evidence_sufficiency` | Advisory assessment of what a finding still needs to become publishable |
| `plan_runtime_verification` | A safe, read-only verification plan for a SAST finding. Executes nothing |

`evidence_sufficiency` is explicitly advisory. It sets no score; only a distinct verifier's sealed verdict
moves a finding's evidence score.

## Proposal tools

Every tool below records a proposal at evidence score 0. None of them changes state that matters, and none
can confirm itself.

| Tool | Proposes |
| --- | --- |
| `propose_plan` | A multi-step recon plan as a DAG. Runs nothing |
| `start_recon` | A recon run against a target. Creates an approval-required proposal, not an execution |
| `propose_finding` | An unproven exploitation claim |
| `propose_attack_chain` | An attack-chain hypothesis, gated until a human verifies |
| `propose_reachability` | A reachability judgment |
| `propose_sast_validation` | A gated SAST judgment for verifier review |
| `propose_critique` | An adversarial critique against an existing finding |
| `propose_risk_narrative` | A risk narrative for human acceptance |
| `propose_threat` | A STRIDE threat over the architecture model |
| `propose_vex_justification` | An OpenVEX `not_affected` justification |
| `propose_writeup_draft` | Finding write-up prose awaiting human sign-off |

A `tools/call` response for a proposal carries `"proposal_requires_human_approval": true`. Treat it as a
queued request for review, not as work that happened.

Judgment proposal tools require `SYNAPSE_JUDGMENTS_ENABLED`, and `propose_writeup_draft` requires
`SYNAPSE_WRITEUP_DRAFTS_ENABLED`. A tool whose dependency is not wired is simply absent from
`tools/list` rather than present and failing.

## Why proposals cannot become executions

Three independent controls hold, and none of them depends on the MCP client behaving correctly:

1. **No executor.** The MCP server has no execution gate wired, so `start_recon` can only create an
   approval record.
2. **Server-side scope enforcement.** When a human later approves a proposal, the normal execution
   chokepoint still rechecks the active engagement, authorization window, exact target scope, and rules of
   engagement before anything runs.
3. **Distinct verifier.** A judgment's verifier may not be its proposer, and its acceptor may not be its
   proposer. A machine identity cannot promote its own claim regardless of how it was submitted.

Secrets are never exposed to a client: credentials stay in the vault, substitution happens server-side at
execution time, and evidence content is not a readable field in any tool result.

Next: [Code quality rule authoring](code-quality-rules.md)
