# Governed assessments

[Documentation home](README.md) · Previous: [Project code quality](project-code-quality.md) · Next: [Vulnerability intelligence](vulnerability-intelligence.md)

An **Engagement** is a time-bounded security assessment. Its scope, authorization window, and rules of
engagement gate every execution server-side before any tool runs. This guide covers the workflows that
hang off an engagement: evidence, imported artifacts, threat models, work orders, write-ups, purple
coverage, and asset correlation.

For the long-lived code-quality identity, see [Project code quality](project-code-quality.md). The two
are independent aggregates.

## Scope and authorization

```
POST /api/v1/engagements                              create
PUT  /api/v1/engagements/{id}/status                   lifecycle transition (also PATCH /api/v1/engagements/{id})
PUT  /api/v1/engagements/{id}/scope                    in-scope and out-of-scope targets
PUT  /api/v1/engagements/{id}/authorization-window     legal start and end
PUT  /api/v1/engagements/{id}/roe                      rules of engagement
PUT  /api/v1/engagements/{id}/live-recon                enable or disable live recon
```

The lifecycle is draft, active, completed, archived. Draft goes to active or archived, active goes
to completed or archived, completed goes to archived, and archived is terminal. Send the target
state as `{"status": "active"}`; an illegal transition is rejected with `400`. Both spellings apply
the same change through the same `operate` gate and write the same audit record.

Every execution path checks the active engagement, the authorization window, the exact target scope, and
the rules of engagement before running anything. The same chokepoint serves human-initiated runs and
agent-initiated proposals, so an agent cannot route around it.

Synapse validates scope data but cannot verify legal authorization. Keep written permission for every
target.

## Findings and triage

```
GET   /api/v1/engagements/{id}/findings
POST  /api/v1/engagements/{id}/findings
PATCH /api/v1/engagements/{id}/findings/{fid}
PUT   /api/v1/engagements/{id}/findings/{fid}/assignee
POST  /api/v1/engagements/{id}/findings/{fid}/verify
POST  /api/v1/engagements/{id}/findings/{fid}/comments
POST  /api/v1/engagements/{id}/findings/{fid}/retests
```

A finding is the tracked, de-duplicated unit of work. Re-scans update findings in place rather than
creating duplicates. Retests record whether a remediation actually held.

## Evidence

```
GET  /api/v1/engagements/{id}/evidence
GET  /api/v1/engagements/{id}/evidence/{sha}
POST /api/v1/engagements/{id}/evidence
GET  /api/v1/engagements/{id}/bundle
GET  /api/v1/audit
GET  /api/v1/audit/verify
```

Evidence and audit records are append-only and hash-chained. Report generation verifies the chain first
and refuses when verification fails, so a report always rests on evidence that validates. Evidence
content is never exposed to a model.

## Imported artifacts

A client-supplied artifact becomes a first-class, attested inventory rather than an unattributed import:

```
POST /api/v1/engagements/{id}/sbom            ingest a CycloneDX SBOM
GET  /api/v1/engagements/{id}/sbom
POST /api/v1/engagements/{id}/sarif           ingest a third-party SARIF report
GET  /api/v1/engagements/{id}/imported-findings
POST /api/v1/engagements/import
```

SARIF ingest records the authenticated principal as the ingesting actor and refuses results it cannot
attribute. Validate a report locally first with
[`synapse-cli validate-sarif`](cli.md#validate-a-third-party-sarif-report), which reports what the server
would accept or refuse and persists nothing.

To compute vulnerabilities against an imported SBOM, start a scan with an empty target: Synapse reuses the
imported inventory and runs the detection half of the pipeline.

## Threat models

```
GET /api/v1/engagements/{id}/threat-model
PUT /api/v1/engagements/{id}/threat-model
```

A threat model records the assessed elements and their threats so coverage claims are explicit rather than
implied by whichever tools happened to run.

## Work orders

Work orders carry authorized work to fleet agents. Their lifecycle is a closed state machine:

`issued` → `claimed` → `running` → `succeeded` | `failed` | `refused` | `cancelled` | `expired`

An agent claims work, reports progress, then reports a result. `refused` is a first-class outcome: an
agent that will not run something records that decision rather than silently failing. `expired` bounds
work that was never claimed. See [Fleet and runtime defense](fleet-blue-team.md) for the agent side.

## Write-up drafts

```
GET  /api/v1/engagements/{id}/writeup-drafts
POST /api/v1/engagements/{id}/writeup-drafts/{did}/edit
POST /api/v1/engagements/{id}/writeup-drafts/{did}/accept
POST /api/v1/engagements/{id}/writeup-drafts/{did}/reject
GET  /api/v1/writeups
```

A draft moves `draft` → `proposed` → `accepted` | `rejected`. An agent can only propose; a distinct human
edits, accepts, or rejects. Accepted prose is stored data, and reports render deterministically from
stored data with no model in the path. Enable the agent tool with `SYNAPSE_WRITEUP_DRAFTS_ENABLED`.

## Purple coverage

```
GET /api/v1/engagements/{id}/purple-coverage
```

Purple coverage compares the detections an emulation was expected to produce against what the fleet
actually observed, so a detection gap is reported as a gap instead of being absent from the record.

## Asset correlation and risk stories

```
GET /api/v1/appsec/assets
GET /api/v1/appsec/assets/{assetID}/posture
GET /api/v1/appsec/assets/{assetID}/coverage
GET /api/v1/engagements/{id}/risk-stories
GET /api/v1/engagements/{id}/risk-stories/{assetID}
GET /api/v1/assets
GET /api/v1/assets/edges
GET /api/v1/attack-paths
```

A risk story is one unified narrative per asset, joining supply-chain, code, cloud, offensive, and runtime
signals. Cross-pillar priority changes go through deterministic
[promotion rules](repository/promotion-rules.md) and the judgment gate; they are proposals, never direct
mutations.

Attack-path traversal always enforces and reports its three bounds
(`SYNAPSE_ATTACKPATH_MAX_LEN`, `SYNAPSE_ATTACKPATH_MAX_PATHS`, `SYNAPSE_ATTACKPATH_WALLCLOCK`), so a
truncated result is visible rather than silently partial.

## Judgments

```
GET  /api/v1/engagements/{id}/judgments
POST /api/v1/engagements/{id}/judgments/{jid}/verify
POST /api/v1/engagements/{id}/judgments/{jid}/accept
POST /api/v1/engagements/{id}/judgments/auto-verify
POST /api/v1/engagements/{id}/judgments/{jid}/runtime-verification
```

Every claim is a typed judgment with a propose, verify, confirm lifecycle. A gated capability promotes
only on a distinct verifier's sealed verdict above the evidence threshold: the verifier may not be the
proposer, and the acceptor may not be the proposer. A machine identity can never confirm its own claim.

Runtime verification can confirm a SAST hypothesis with a safe probe, but only inside scope and window,
only with kernel-enforced egress confinement, and only after explicit human approval.

## Credentials

```
GET    /api/v1/engagements/{id}/credentials
POST   /api/v1/engagements/{id}/credentials
DELETE /api/v1/engagements/{id}/credentials/{name}
```

Credentials are stored in the vault and referenced by placeholder. Substitution happens server-side at
execution time, and resolved values are scrubbed from captured output. Secrets never reach logs,
transcripts, or model-visible payloads. Set `SYNAPSE_VAULT_MASTER_KEY` in production, or stored secrets do
not survive a restart.

## Reports and exports

```
GET /api/v1/engagements/{id}/report.pdf
GET /api/v1/engagements/{id}/report.html
GET /api/v1/engagements/{id}/report.docx
GET /api/v1/engagements/{id}/export/sarif
GET /api/v1/engagements/{id}/export/openvex
GET /api/v1/engagements/{id}/export/cyclonedx
GET /api/v1/engagements/{id}/export/spdx
```

Reports are deterministic functions of stored data. Evidence-chain verification failures block report
generation. Exports cover SARIF, OpenVEX, CycloneDX, and SPDX; CSAF is an advisory **ingest** format, not
an export.

## Offensive work

Governed exploitation and emulation run only through the allowlist in the
[offensive policy](repository/offensive-policy.md), which `synapse-api` loads and validates at startup
(an invalid register stops the process) and exposes read-only at `GET /api/v1/redteam/policy` with each
technique's risk class, approval mode, blast radius and prohibited/production-safe flags. A technique
absent from the register is refused. The
kill switch stops issuance estate-wide:

```
POST /api/v1/redteam/halt
```

Next: [Vulnerability intelligence](vulnerability-intelligence.md)
