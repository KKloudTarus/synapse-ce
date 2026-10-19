# Review remediation

This ledger tracks the changes requested against `a5bf0239`. A row is complete
only after the final tree has current verification evidence. Earlier provider
captures remain historical observations of their recorded tree and configuration;
they do not independently establish acceptance of subsequent code changes.

| Finding | Acceptance for the correction | State |
| --- | --- | --- |
| Migration deadline and growing backfill | No whole-table backfill or new blocking index build in 0251; tenant-keyset catch-up is bounded, restart-safe, concurrent-safe and retains forced RLS. | Addressed; current checks pass |
| Shared Jira breaker | Per-ticket 400/404 status failures leave unrelated creates and status work dispatchable; create mapping and credential failures retain their intended fences. | Addressed; current checks pass |
| Verification provenance | Fresh checks identify the exact source tree, commands and timestamps; prior records are retained with their actual scope. | Addressed; current checks pass |
| Provider acceptance provenance | Separate historical live observations, current automated contract checks, rerun live observations and unavailable items explicitly. No mock result substitutes for live acceptance. | Addressed; current checks pass |
| Missing migration tests | Each new migration has upgrade/reapply evidence; backfill, protected rollback and constraint repair have behavioral coverage. | Addressed; current checks pass |
| Deletion watermark | Equal or older replays cannot clear a known deletion watermark; a strictly newer readable observation can. If no provider timestamp was known, the first timestamped readable observation establishes the baseline. | Addressed; current checks pass |
| Refused field refresh | A definite refusal fences only its target without repeated discovery or blind replay; operator recovery remains explicit. | Addressed; current checks pass |
| Post-publication sharing drift | A one-link tenant sweep checks active links with a 10 s observation / 12 s pass budget, reports lost/unverifiable sharing, preserves history and does not write remote content. Actual Cloud verified/lost checkpoints and console warning captured. | Addressed; current checks pass |
| Policy ambiguity | Known control and vendor audit fields are explicitly typed; unknown, conditioned or duplicate fields cannot establish unconditional protection. | Addressed; current checks pass |
| Rendered-template secrets | Unicode format characters cannot hide credential keywords; Vietnamese text and template syntax survive. | Addressed; current checks pass |
| Hostile egress harness | Every new route family pins cross-tenant rejection and prevents provider side effects. | Addressed; current checks pass |
| Migration teardown | Cold isolated-database cleanup uses a bounded realistic deadline and force drop; cleanup failure stays visible. | Addressed; current checks pass |
| Test budget | Keep finite cold-suite headroom without dropping assertions or changing the production migration deadline. | Addressed; current checks pass |
| Changelog | Add the user-visible integration and report-delivery entry requested by the reviewer and this remediation request. | Addressed; current checks pass |

The safety invariants remain tenant/RLS isolation, human permissions, idempotency,
legal holds, redacted credentials, proposal-only inbound processing, exact Jira
`statusCategory.key == "done"`, and restricted sharing before content upload.
OAuth cleanup remains paused until the user reports the PR merged. This work does
not merge the PR, change billing or touch school resources.

The final source baseline, full frontend (208 files / 1408 tests), build, affected
race suites and hostile harness passed with unchanged source inputs. The full Go
pass with PostgreSQL passed on an earlier remediation snapshot; its unchanged
persistence/schema passed again on the same retained test database at the final source fingerprint.
One intervening repeat ended with `signal: killed`; it is not represented as a pass.
Final check provenance is recorded separately rather than inferred from commit dates.

Current fresh Cloud evidence covers create/update/hash-skip, verified sharing,
calendar page version 4, three PDF downloads/previews, normal purge and six HTTP 404
readbacks. Missing DC, native callback, multi-asset producer and mail reruns keep
all eight issue references at `Refs`; historical captures do not retract those gaps.
