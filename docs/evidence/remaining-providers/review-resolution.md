# Provider review resolution

This ledger addresses the [20 October request for changes](https://github.com/KKloudTarus/synapse-ce/pull/1599#pullrequestreview-5586922462)
against `0ac64458`. The corrective candidate passes the final Docker and tier 0
review gate. The [verification summary](verification-summary.json) identifies the
source fingerprint, log hashes, current results and historical provenance.

| Finding | Correction | Evidence |
| --- | --- | --- |
| Sharing loss classified through two Confluence code strings | A provider-neutral observed-loss flag distinguishes actual ACL/identity contradictions from unavailable or incomplete proof. Ambiguous observations remain unverifiable. | Real Confluence, Drive and Graph negative contracts plus the monitor classification matrix; the monitor regressions failed before the correction. |
| Pre-request status-zero refusals recorded as uncertain | Non-ambiguous refusals reject with their safe code; ambiguous failures retain uncertain recovery. | Four SCM refusal regressions and a mutation that makes all four fail. |
| Ordinary provider endpoint guards untested | Constructor tests exercise hostile Azure, Linear and ServiceNow endpoints, table restrictions and pinned clients. | Adapter contract/race checks. |
| Lease-expiry assertion was masked by a dirty checkpoint | Clean checkpoint boundary cases and mutation verification. | Memory/PostgreSQL clean-boundary tests pass; deleting the memory expiry predicate makes the regression fail. |
| Jira wording in native provider errors | Generic request/fallback errors identify ticket delivery. | Safe error regression. |
| Linear used as a default provider | Explicit Linear cases and fail-closed unknown providers. | Unsupported-provider no-request regression. |
| Native payloads could fall back to Jira serialization | Refuse native adapters without their payload builder. | Workflow regression. |
| Ticket support duplicated as a provider-ID list | The trusted registry descriptor supplies the ticket capability. | Capability selection tests. |
| Drive/Graph canonicalizers diverged | One strict canonicalizer rejects attributes, nested/unbalanced links and images. | Shared hostile markup and round-trip contracts. |
| Use-case remote URLs checked only origin | Exact GitHub, GitLab and Azure ticket path shapes are checked at acknowledgement. | Native workflow hostile URL table. |
| Graph remote state returned configured container | Return the validated observed parent identity. | Combined-reader identity drift regression. |
| SharePoint path accepted query/fragment/whitespace | Reject ambiguous configured proof paths and resource parsing. | Path/parser contract tests. |
| ServiceNow encoded target path contract implicit | Name and document the adapter/use-case browser URL encoding contract. | Existing encoded target tests retained. |
| Migration test filename inconsistent | Follow the numbered migration test convention. | Migration 0262 test renamed; migration 0263 upgrade/rollback/reapply checks pass. |
| Dead label loop and Linear wrapper | Remove the unreachable validation loop and test-only wrapper. | Ticket package checks. |
| Document step loop claimed unreachable | Verify the attachment-complete continuation before removing a safety bound. | Retained: the attachment-complete branch changes the step to body and uses a live `continue`. Publication recovery tests exercise the path; removing the loop as claimed would remove that continuation. |
| Settings icons bypassed the web icon convention | Use the existing Settings icon set. | Full web gate passes: 1,450 tests, typecheck/build, zero lint errors and twenty existing warnings. Twenty-six fresh previews cover both themes and mobile/error/loading/permission states. |
| Raw document access-token lifetime unclear | Document exact credential types, no automatic refresh, provider-issued expiry and operator rotation for both Microsoft audiences. | Document-publishing operator guide. |
| Repeated full document proof | Combine one fresh identity/revision/ACL read at the use-case boundary; keep a separate fresh adapter check immediately before outward writes. | Drive combined read: nine requests. Graph: sixteen with no attachments, thirty-eight for the eleven-attachment direct monitor proof, 2.041s at synthetic 100ms RTT. Final adapter race tests pass; these are not native SLOs. |
| Inbound polling had no floor or Retry-After | Durable due claims and fenced completion. | Focused memory/PostgreSQL conformance and restart checks pass. Real Workflow Tick tests prove the longer read-429 delay across a new instance, zero early I/O, exact due retry, identity-429 suppression and no unverified proposal. Per-target scheduling is not a global quota limiter. |
| Document 429 could exhaust retries | Durable provider-directed deferral with lease/progress/queue fences. Uncertain remote effects retain their operation and receipts. | Progress is persisted with its claimed version/lease before provider work. Real Execute tests cover all four pre-write 429 steps, preserving receipts and attempts; crash tests cover both sides of binding and require marker recovery once an operation is outstanding. Atomic due claims, stale/expired fences, returned-command parity and migration rollback refusal pass focused checks. Independent combined acceptance recheck passed. |
| Command JSONB amplification and terminal queue starvation unverified | Measure the actual queries against seeded PostgreSQL; preserve fair due selection. | Terminal starvation rejected by seeded queue evidence. Split eligible-state query plus partial index avoids the confirmed terminal-history scan. Yield/defer avoid their second artifact scan. See the measured plans and retained size-dependent validation cost below. |

## Findings from the corrective gate

The independent corrective review also reproduced and fixed the following cases:

| Finding | Correction and regression |
| --- | --- |
| Expired initial shell lease encountered a preflight 429 while still in flight | Settle the expired lease before provider work. Both sides of progress binding preserve the delay, make no early provider call, and resume a single first shell. Live leases make no provider call. |
| A retryable failed shell could not persist a preflight 429 | Recheck current release authority before reactivating the rejected intent, then retry before preflight. The nine-minute delay survives without consuming another attempt. Revoked authority preserves the failed state and version and performs no provider I/O. |
| Azure hardening rejected canonical encoded spaces | Allow bounded project names with spaces and Unicode, while binding acknowledgements to the exact decoded organization/project. Constructors and acknowledgement/reconciliation regressions retain hostile separator, double-encoding and path checks. |
| Graph ambiguity/readback wrappers lost provider delay metadata | Preserve typed status and Retry-After while retaining ambiguity after effects. Real attachment contracts exercise six readback phases and collision recovery; purge ownership reads retain the throttle before any delete. |
| Complete Read plus Contribute role bindings looked like missing proof | Validate every binding structurally before comparing the complete grant set. Additional/empty valid bindings prove restriction loss; omitted, null, malformed or paginated bindings remain unverifiable. |
| GitHub rate-limit 403 looked like an inaccessible issue | Recognize typed rate-limit refusals before the ordinary 403/404 path, for both ticket and identity reads. The 403 and 429 workflow cases preserve restart delays and suppress later same-integration targets. |

## Query cost and retained limit

The [queue plan excerpts](queue-query-plans.md) and [measurements](queue-cost.json)
use an isolated PostgreSQL 17 fixture with 100,005 commands, 100,002 terminal rows
and three eligible rows. The final candidate query was also checked under a
non-superuser `NOBYPASSRLS` role with FORCE RLS and the tenant setting. Candidate
selection uses the eligible index and avoids terminal history; the selected CTE
measured 0.163ms and 28 buffers. These results are diagnostic, not a service SLO.

An independent rolled-back fixture with 100,000 future-deferred active commands
selected the three due commands in 164.441ms without starvation. The queue remains
O(A) in active intents, including future-deferred work. This is a retained backlog
limit; it does not establish production throughput.

The existing artifact CHECK validates JSONB on every command-row update, including
fairness metadata. A ten-MiB PDF-field fixture accepted by stored-artifact validation exposed that cost. Removing the
constraint only inside a rolled-back diagnostic transaction reduced a large-row
metadata update from 177.917ms to 0.564ms, with identical WAL. The constraint was
restored; it is retained in production to preserve artifact validation. The full
plan and scan-allocation measurements distinguish this from a TOAST rewrite.
Separating immutable artifacts from hot queue metadata is a concrete follow-up
if measured deployment capacity requires it. This PR removes redundant yield/deferral return reads and the history scan.
Persisting the new claim-bound progress adds one full artifact read per executor
slice, so no net per-slice artifact-read reduction is claimed. Fresh List/Execute
reads and bounded artifact-size checks remain. Size workers using actual report sizes, backlog age and
provider latency rather than these warm synthetic measurements.

The native acceptance provenance remains in the [live ledger](live/README.md).
These corrections do not claim that historical live captures were rerun against
the corrective binary. Microsoft live acceptance remains in #1576; Notion is
excluded from this PR. The seven implementation leaves retain their closing
keywords. This PR does not close #1576 or authorize a merge.

## Final corrective verification

The final source fingerprint is
`10b22b6f6d8d808a237e4ce8972a3a433090ab78324e57c24d600712f48328f6`.
The machine summary records the selection and hashing algorithm. Final backend
build, vet, full Go tests, typecheck, hostile tenant harness and seven focused race
packages passed in Docker. Go lint reports zero issues. Full PostgreSQL persistence,
RLS and migration verification passed 1,153 tests with four skips in 2,188.447s;
its dependency inputs did not change afterward. Full web verification passed
212 files / 1,450 tests, typecheck, production build and lint with zero errors and
twenty existing warnings. Twenty-six regenerated synthetic console captures and
their script lint passed.

Combined implementation acceptance and the final QA, security, performance,
reliability, frontend and architecture reviews passed after corrections. No
material finding remains open. Retained active-backlog and artifact costs are
qualified above; no native latency or production capacity guarantee is claimed.
