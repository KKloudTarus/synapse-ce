# Project code quality

[Documentation home](README.md) · Next: [Governed assessments](governed-assessment-workflows.md)

A **Project** is a long-lived code-quality identity that accumulates analysis history. It is a separate
aggregate from an [Engagement](governed-assessment-workflows.md), which is a time-bounded security
assessment. Neither owns the other, and both can invoke the same analysis pipeline.

Use a Project when you want to track a codebase over time: issues, security hotspots, measures, ratings,
duplication, coverage, and a quality gate that can block a merge.

![Code Quality project portfolio showing the empty state and project creation action](assets/project-code-quality.png)

*The Code Quality portfolio keeps long-lived projects separate from time-bounded engagements. This sanitized local view contains no repository or customer data.*

## Analyses

An analysis is one deterministic run against a revision. Create one, then read its results:

```
POST /api/v1/projects                                   create a project
POST /api/v1/projects/{key}/analyses                     start an analysis
GET  /api/v1/projects/{key}/analysis-status               poll progress
GET  /api/v1/projects/{key}/analyses                     list history
GET  /api/v1/projects/{key}/analyses/{id}                one analysis
```

Analysis history is append-only, so a rating change is always attributable to a specific run.
`SYNAPSE_PROJECT_ANALYSIS_COMPLETION_TIMEOUT` bounds how long the server waits for completion.

### Source code views

Uploaded project sources land in `SYNAPSE_PROJECT_UPLOAD_DIR`. When an analysis has retainable source,
the dashboard can render annotated code:

```
GET  /api/v1/projects/{key}/analyses/{id}/code/files      inventory
GET  /api/v1/projects/{key}/analyses/{id}/code/file       one file
GET  /api/v1/projects/{key}/analyses/{id}/code/diff       new-code diff
POST /api/v1/projects/{key}/analyses/{id}/source          publish source
```

Only files the analysis listed as retainable are accepted. Publish them from CI with
[`synapse-cli publish-source`](cli.md#publish-analysis-source), which verifies the returned manifest
digest.

## Issues

An issue is a maintainability or reliability finding tracked across analyses. Its lifecycle is a closed
set of human transitions:

| Status | Meaning |
| --- | --- |
| `open` | Newly reported, not yet triaged |
| `confirmed` | A reviewer agrees it is real |
| `accepted` | Knowingly retained; no longer counted as new debt |
| `false_positive` | Not a real defect |
| `wont_fix` | Real, but deliberately not being fixed |
| `fixed` | Resolved and no longer detected |

```
GET  /api/v1/projects/{key}/issues
GET  /api/v1/projects/{key}/issues/{id}
GET  /api/v1/projects/{key}/issues/{id}/history
POST /api/v1/projects/{key}/issues/{id}/transitions
```

Every transition is recorded, so `history` explains how an issue reached its current status and who
decided.

## Security hotspots

A hotspot is security-sensitive code that requires a human judgment rather than an automatic verdict.
Its review lifecycle is deliberately separate from issues:

| Status | Meaning |
| --- | --- |
| `to_review` | Awaiting a reviewer |
| `acknowledged` | Reviewed, needs follow-up work |
| `safe` | Reviewed and judged not exploitable in this context |
| `fixed` | Changed so the sensitive pattern is gone |

```
GET  /api/v1/projects/{key}/hotspots?status=to_review&severity=high
GET  /api/v1/projects/{key}/hotspots/{id}
GET  /api/v1/projects/{key}/hotspots/{id}/history
POST /api/v1/projects/{key}/hotspots/{id}/transitions
```

Hotspots are never auto-resolved. `to_review` is the honest default, and the
`new_security_hotspots_reviewed` gate condition can require reviews on new code before a merge.

## Measures, ratings, and overview

```
GET /api/v1/projects/{key}/overview     current ratings and headline measures
GET /api/v1/projects/{key}/measures     paginated metric history
```

Measure pagination cursors are signed with `SYNAPSE_MEASURE_CURSOR_SECRET`, which is required in
production. Ratings are A–E grades for security, reliability, and maintainability, computed
deterministically from stored findings.

A metric is reported as unavailable rather than guessed when its analyzer could not run. Complexity and
structural metrics need the `synapse-ast` sidecar; without it they degrade to Go-only counts instead of
reporting a false zero.

## Quality gates

A gate is a named set of conditions evaluated against an analysis. Gates are managed centrally and then
bound to a project:

```
GET    /api/v1/quality-gates
POST   /api/v1/quality-gates
GET    /api/v1/quality-gates/{key}
PUT    /api/v1/quality-gates/{key}
DELETE /api/v1/quality-gates/{key}
PUT    /api/v1/projects/{key}/gate          bind a gate to a project
```

Available metrics include `new_critical`, `new_high`, `new_medium`, `new_issues`, `new_vulnerability`,
`new_secret`, `new_misconfig`, `new_coverage`, `coverage`, `new_duplication`, `duplication_density`,
`maintainability_rating`, and `new_security_hotspots_reviewed`.

Conditions on `new_*` metrics implement Clean as You Code: a legacy codebase can adopt a strict gate for
changed lines without first repaying all existing debt.

## Quality profiles

A profile decides which rules are active for a language and at what severity:

```
GET    /api/v1/quality-profiles
GET    /api/v1/quality-profiles/{key}
POST   /api/v1/quality-profiles/{key}/copy
POST   /api/v1/quality-profiles/{key}/activate
POST   /api/v1/quality-profiles/{key}/deactivate
POST   /api/v1/quality-profiles/{key}/severity
DELETE /api/v1/quality-profiles/{key}
PUT    /api/v1/projects/{key}/profiles/{language}
```

Built-in profiles are not edited in place. Copy one, adjust the copy, then bind it. To author new rules,
see [Code quality rule authoring](code-quality-rules.md).

## Gate the same rules in CI

The CLI runs the same analyzers without a server or database, so a pipeline can enforce the gate before
a merge:

```bash
synapse-cli gate . --new-code-only --base origin/main --coverage coverage.info
```

See the [CLI guide](cli.md#code-quality-gate-clean-as-you-code) for the gate flags, the code-health
commands, and the exit-code contract.

Next: [Governed assessments](governed-assessment-workflows.md)
