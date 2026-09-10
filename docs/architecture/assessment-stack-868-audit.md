# Assessment lifecycle stack audit

## Current delivery chain after review

The review on #883 identified that its migration renumbering conflicts with the authoritative mainline layout introduced by #896. That prerequisite has been dropped. The assessment payload has been restacked onto main `9a7bae2d` (including #779, #855, #896 and the scanner/advisory updates through #924).

| Phase | PR | Capability | Base |
| --- | --- | --- | --- |
| 1 | #884 | Cycle persistence and resumable backfill | main |
| 2 | #885 | Lifecycle contracts and additive schema | #884 branch |
| 3 | #886 | Immutable snapshots and history | #885 branch |
| 4 | #887 | Finding lineage and native evidence | #886 branch |
| 5 | #888 | Comparison and governed review state | #887 branch |
| 6 | #889 | Immutable uploaded source and retest reuse | #888 branch |
| 7 | #890 | Closure, reopen and relationships | #889 branch |
| 8 | #891 | HTTP/OpenAPI, worker and rollout integration | #890 branch |
| 9 | #892 | Lifecycle and retest UI | #891 branch |
| 10 | #893 | Operational commands, deployment and documentation | #892 branch |

Merge #884 first, then proceed in order. Prefer merge commits to retain stack ancestry; after merging a predecessor, retarget the next PR to main and review its remaining diff. #868 is a draft tracking/reference PR and must not be merged. #883 is superseded by mainline #896 and is no longer a prerequisite. Existing branch names remain stable even though their numeric suffixes describe the original 11-phase decomposition.

## Follow-up: advisory migration collision

Main subsequently added `0145_advisory_alias_index.sql` in #921. The reviewer identified the resulting duplicate version at the assessment stack base. The entire unmerged assessment block is shifted from 0145–0159 to 0146–0160. SQL bodies are unchanged; migration test filenames, embedded-file references, Goose upgrade/rollback targets and operator documentation follow the new numbers. Upgrade-path fixtures also cover main version 0145. Published main migrations are never renumbered.

## Mainline ownership and migration order

All migration files already on main are retained byte-for-byte. No released migration is renamed or rewritten by this stack:

| Version | Authoritative mainline migration |
| --- | --- |
| 0138 | response_attempt_invariants |
| 0139 | response_execution_runtime |
| 0140 | correlation_event_time_state |
| 0141 | incident_response_provenance |
| 0142 | response_target_evidence_receipts |
| 0143 | response_halt_writer |
| 0144 | scan_run_provenance |
| 0145 | advisory_alias_index |

The only new SQL files are 0146–0160. Their SQL bodies and relative ordering are unchanged from the audited assessment payload: Cycle backfill; snapshots; cycle API; integrity; snapshot backfill; lineage; lineage backfill; comparison; closure; relationships; reports; visible projects; comparison evidence; source packages; source bindings.

Core `internal/domain/scanrun`, `internal/usecase/scanrun`, response, response-saga, correlation and incident code has no diff against current main. Assessment-specific extensions to ScanRun adapters add immutable evidence and source metadata; they do not recreate the provenance aggregate, service or migration.

The original base `34ed7b2b` already included #779 and #855. The review exposed the later migration-layout change from #896, rather than a need to replace the core implementation. Dropping the obsolete migration prerequisite and restacking removes that conflict while retaining main as authoritative.

## Preservation

- Original local commit: `cd5094b8fc719be4afbc5789cbb3bf3781540080`.
- The original uncommitted Docker Go 1.27.0 builder update remains preserved in `codex/868-local-source-snapshot` (`eb137084`) and delivered by #893.
- The original checkout and uncommitted patch remain unchanged.
- The original 344-path source audit accounted for every meaningful local change: 310 exact local blobs, 31 adaptations for main, #880 validation, migration references or formatting, and three inherited ScanRun tests with stronger main-side database isolation/boundaries. Its source bundle and pre-review stack bundle remain available; no original source branch was deleted.
- The first review restack compared the assessment delta using the old #883 head as its lower boundary. That audit retained all 333 paths: 321 exact pre-review blobs and 12 main/configuration/documentation adaptations. This remains the historical preservation checkpoint before the second review renumber.
- The second review renumber changes only assessment migration filenames, version references/tests and this delivery documentation after applying newer main commits. The pre-renumber and final trees are compared through that explicit filename mapping.
- The 15 assessment SQL blobs are unchanged. All existing main SQL blobs are unchanged. Every PR parent and incremental diff is checked.
- #880's actor/timestamp validation, bounded backfill inputs, actor fallback, fenced tenant transactions and regression assertions remain in the assessment phases.
- #879 remains a historical reference for the initial fix; its migration numbering is superseded by #896 and is not reapplied.

## Validation

The restack receives a repository-wide Go build at every phase and package tests for the capability introduced by each phase. Validation includes the existing `TestMigrationInventoryNoDuplicateGooseVersions`, PostgreSQL owner-role migration/rollback tests against a disposable PostgreSQL 17 database, and final assessment/lineage/closure/source integration coverage.

Final validation also covers repository-wide Go tests and vet, frontend typecheck/tests/build/lint, and Helm strict lint/render assertions. Results are recorded in the updated PR descriptions. CI is disabled for this repository, so local verification is explicitly reported rather than inferred from GitHub mergeability.
