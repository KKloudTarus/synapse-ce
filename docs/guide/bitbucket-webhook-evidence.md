# Bitbucket Cloud inbound webhook review evidence (#1453)

Implementation scope: signed Bitbucket Cloud push and open PR creation/update deliveries scan one bound existing Git Project. Real provider verification below was collected on 2026-10-04. Earlier validation sections are historical records.

## Real provider verification (2026-10-04)

The public [test repository](https://bitbucket.org/synapse-ce-webhooks-vku/webhook-validation/src/main/) belongs to the VKU account's `synapse-ce-webhooks-vku` workspace. [PR 1](https://bitbucket.org/synapse-ce-webhooks-vku/webhook-validation/pull-requests/1) and [PR 2](https://bitbucket.org/synapse-ce-webhooks-vku/webhook-validation/pull-requests/2) generated real signed deliveries to a local Synapse API backed by PostgreSQL 17. A temporary HTTPS tunnel exposed only the inbound POST hook route; management routes returned 404 and unsigned delivery returned 401. These Bitbucket PRs are provider test fixtures; the implementation contribution remains GitHub PR #1544.

| Event | Request UUID | HTTP status | Completed analysis |
| --- | --- | --- | --- |
| `repo:push`, greeting | `7082c875-51ab-49e3-9a8f-fd535a825173` | 202 | `d84ed9f66716208330697473e2443228` |
| `pullrequest:updated`, greeting | `6c337d4d-901f-4b72-969d-9421c9f8dac6` | 202 | `7f1a0dda52b3bea207fb33bacf0bd7d6` |
| `repo:push`, message | `2e0cae03-5f04-49bb-bdbf-25c53b42a477` | 202 | `95cff09680edbc88f839e2330dfec0a2` |
| `pullrequest:created`, message | `241cddd0-d389-4dc7-a121-04a6e013d81b` | 202 | `130e4cc4ea5841788f7e964f1413d2db` |
| `pullrequest:updated`, automatic retry | `7034dd71-73e8-457c-8f8d-82b962a179dd` | 503, then 202 at provider; 202 at Synapse twice | `3d823122cdc7d3bb319a834fa707be8d`, exactly once |
| `pullrequest:created`, fork | `38a1eea3-2248-4a82-a7db-1935627877ab` | 202 | `561f2837386b63c894e9568f23e57980` |

Greeting analyses pin `8db8a7f191595e577998f9c970ddd6f74a8733e3`; message analyses pin `0ae05ec04b4263b665140145b5c77361dc111e16`. PR analyses retain destination `main`, with base and merge base `15778e2daa3c46a0d60961f9866c46b1ca4d3646`. The [selected analysis records and retry facts](assets/ui/bitbucket-webhooks/live/manifest.json) contain no webhook secret, signature headers or raw delivery body.

The first real PR-created delivery returned 400: Bitbucket supplies a 12-character source commit hash. Its [documented event payload](https://support.atlassian.com/bitbucket-cloud/docs/event-payloads/) uses this abbreviated form. The receiver now resolves that prefix through the [Bitbucket commit API](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-commits/#api-repositories-workspace-repo-slug-commit-commit-get), using only the persisted Project repository. Resolution occurs before receipt/enqueue locks, requires a matching 40-character hash, and rechecks the binding and stored source before enqueue. Queue and acquisition still require the full immutable SHA. Subsequent real PR-created and PR-updated deliveries completed successfully.

For the retry proof, a temporary local proxy forwarded Bitbucket's original signed request to Synapse, then returned 503 after the first upstream 202. Bitbucket automatically retried the same UUID; the second attempt received 202. Analysis count increased from four to five, not six. The fault proxy was stopped and normal routing restored after capture.

[Fork PR 3](https://bitbucket.org/synapse-ce-webhooks-vku/webhook-validation/pull-requests/3) uses a commit unique to the public fork, `66229771a7d4d20a4492555a0fb1ab1146e760ba`. The scan succeeded. Its completed PostgreSQL queue record pins that full SHA against the persisted destination repository, with `DisableGitCredentials=true` and `no_build_execution=true`. The fork page contains only its creation activity and zero builds; no forge decoration was produced. This verifies a public fork. Private repository and private fork delivery were not exercised.

| Actual browser evidence | Record |
| --- | --- |
| Signed delivery history | [Bitbucket history](assets/ui/bitbucket-webhooks/live/delivery-history.jpg) |
| Real PR with English and Vietnamese description | [Forge screenshot](assets/ui/bitbucket-webhooks/live/pull-request-bilingual.jpg) |
| Automatic retry attempts | [First attempt, 503](assets/ui/bitbucket-webhooks/live/retry-attempt-one.jpg), [second attempt, 202](assets/ui/bitbucket-webhooks/live/retry-attempt-two.jpg) |
| Completed analysis, light and dark | [Light](assets/ui/bitbucket-webhooks/live/console-light.jpg), [dark](assets/ui/bitbucket-webhooks/live/console-dark.jpg) |
| Live enabled integration | [Console configuration](assets/ui/bitbucket-webhooks/live/integration-light.jpg) |
| Public fork PR and completed scan | [Forge](assets/ui/bitbucket-webhooks/live/fork-pull-request.jpg), [console](assets/ui/bitbucket-webhooks/live/fork-console-dark.jpg) |

Light/dark captures use the console's Appearance setting and live API data. Bitbucket's surrounding UI renders in English; the forge screenshot proves bilingual user content, not a native Vietnamese Bitbucket locale. Outbound PR decoration is outside this inbound receiver's scope.

## Current verification (2026-10-04)

| Check | Result |
| --- | --- |
| Full Go build and vet, Go 1.27 on Linux; native Windows build/vet | Passed |
| Full Linux package run with isolated PostgreSQL, then environment repair reruns | 432 packages passed initially, 37 had no tests; all five initially failing packages passed on rerun (437 passing packages combined). The initial full command exited 1; this is not a claim that it exited 0. API/worker reruns supplied Git metadata, Helm rerun normalized the Windows copy to LF, and agent/eBPF reruns used an unprivileged user. Privileged kernel tests skipped; no privileged eBPF execution is claimed |
| Full fresh PostgreSQL package | Passed: 523 top-level tests, 4 opt-in skips, 1202.747s |
| Race tests: SCM webhook, Project, Bitbucket adapter, HTTP, API composition | Passed on Linux |
| Changed backend lint, golangci-lint 2.13.2 | Passed, 0 issues |
| Full frontend suite | Passed: 170 files, 1103 tests |
| Integrations UI, frontend typecheck and production build | Passed: 14 focused tests, typecheck and build |
| OpenAPI and documentation checks | Passed |
| Independent security review of abbreviated-commit resolution | Passed, no findings |
| Real signed push, PR-created/updated and automatic retry | Passed; full SHA and destination base retained, retry creates one analysis |

The frontend is unchanged by the commit-resolution fix. Native Windows cannot execute the Linux Unix-socket broker tests or Go race mode without CGO; relevant race and broader package evidence comes from Linux. The suite's privileged kernel and opt-in checks remain outside this webhook verification.

## Local console evidence

These screenshots were captured before the rebase and render the real console using Chromium against a local Vite server and mocked HTTP API responses. All fixture names, repository URLs and hook paths are synthetic. No real credentials are captured. The secret is cleared immediately on submit, including API failure; the screenshot runner verifies the input is empty. All screenshots are English because the changed console strings currently render in English. The real forge screenshots above contain English and Vietnamese user content; these fixtures cover console failure and loading states separately.

| State | Light | Dark |
| --- | --- | --- |
| ready | [Screenshot](assets/ui/bitbucket-webhooks/light-ready.png) | [Screenshot](assets/ui/bitbucket-webhooks/dark-ready.png) |
| loading | [Screenshot](assets/ui/bitbucket-webhooks/light-loading.png) | [Screenshot](assets/ui/bitbucket-webhooks/dark-loading.png) |
| empty | [Screenshot](assets/ui/bitbucket-webhooks/light-empty.png) | [Screenshot](assets/ui/bitbucket-webhooks/dark-empty.png) |
| unbound | [Screenshot](assets/ui/bitbucket-webhooks/light-unbound.png) | [Screenshot](assets/ui/bitbucket-webhooks/dark-unbound.png) |
| error | [Screenshot](assets/ui/bitbucket-webhooks/light-error.png) | [Screenshot](assets/ui/bitbucket-webhooks/dark-error.png) |
| permission-denied | [Screenshot](assets/ui/bitbucket-webhooks/light-permission-denied.png) | [Screenshot](assets/ui/bitbucket-webhooks/dark-permission-denied.png) |
| saved | [Screenshot](assets/ui/bitbucket-webhooks/light-saved.png) | [Screenshot](assets/ui/bitbucket-webhooks/dark-saved.png) |
| save-error | [Screenshot](assets/ui/bitbucket-webhooks/light-save-error.png) | [Screenshot](assets/ui/bitbucket-webhooks/dark-save-error.png) |
| save-loading | [Screenshot](assets/ui/bitbucket-webhooks/light-save-loading.png) | [Screenshot](assets/ui/bitbucket-webhooks/dark-save-loading.png) |
| editing | [Screenshot](assets/ui/bitbucket-webhooks/light-editing.png) | [Screenshot](assets/ui/bitbucket-webhooks/dark-editing.png) |

[Capture manifest](assets/ui/bitbucket-webhooks/manifest.json) records the fixture source and browser errors. No browser runtime errors were observed.

## Security and persistence checks

- HMAC-SHA256 over raw bytes uses `X-Hub-Signature`; generic/GitHub signature headers do not authenticate a Bitbucket endpoint. Missing/duplicate headers, invalid signatures and tenant/header overrides are tested. Previous-secret rotation is tested.
- Request UUID and authenticated-body digest receipts commit in the same PostgreSQL transaction as scan enqueue. Tests cover failure after enqueue, cancellation, terminated DB connection, retries and concurrent replay with changed request UUIDs.
- Real PostgreSQL tests use a `NOSUPERUSER NOBYPASSRLS` runtime role. Owner privileges are restricted to fixture setup/cleanup. Hostile tenant/owner identities cannot provision, rotate or accept another endpoint. PUBLIC cannot execute the new SECURITY DEFINER functions. Migration 0221 upgrades from shipped 0220 and rolls back to 0220 while preserving the identity schema, GitLab payload and notification indexes; runtime direct endpoint DML remains revoked.
- Bitbucket integrations bind one Git Project; concurrent second bindings are rejected. Payload clone URLs cannot override the stored Project repository. Multi-change pushes validate all targets before any enqueue.
- Supported PR deliveries reject comment, approval and change-request payloads, preventing an unsigned event header from reclassifying those signed bodies as PR creation/update events.
- Fork and missing repository identities restrict scans: credential-free acquisition, no build resolvers and no forge writes, including when Project decoration is opted in. An unrestricted control confirms resolver probes actually execute in the corresponding test.
- The queue-only SCA entry point refuses missing queues/tracking stores. Multi-ref pushes enqueue without reserving the single running-scan slot; workers retry slot contention without spending delivery attempts, recheck live scope before execution, skip terminal deliveries by job ID, and expose unstarted dead letters as failed scans. PR source SHA and destination base ref remain pinned in each queued request.

## Validation before rebase

Commands use Go 1.27.0, pnpm 9 and golangci-lint 2.13.2 (the CI version). PostgreSQL is version 17.11; tests set `SYNAPSE_TEST_DB_DSN` to an isolated local database. Helm 3.17.3 was built from official source; its compression dependency was reconstructed from the exact upstream tag and verified against the pinned module checksum before use.

| Check | Result |
| --- | --- |
| Changed backend packages and acquisition regressions, `go test -race` | Passed |
| Focused Bitbucket/migration/lifecycle/hostile tests and webhook/integration regressions, `go test -race` | Passed on real PostgreSQL (17.015s); additional multi-ref queue transaction and migration race tests passed (5.448s) |
| HTTP hostile harness and inbound/GitHub/Bitbucket regressions | Passed |
| OpenAPI and docs checks | Passed |
| `go vet` for changed packages, acquisition, API and docs | Passed |
| `go vet` and golangci-lint on all packages with available dependencies | Passed: 457 packages; lint reports 0 issues after fixing the Bitbucket replay error capitalization |
| Full frontend suite after maintainer audit fixes | Passed: 157 files, 984 tests (237.44s) |
| Final Integrations tests | Passed: 11 tests, including UTF-8 byte length and whitespace validation |
| `pnpm typecheck` and frontend build | Passed |
| `make build`, full `go vet`, `make typecheck`, full lint | Not green: module download for `modernc.org/libc@v1.75.7` returns Forbidden at storage.googleapis.com. Frontend typecheck passed separately |
| Full Go test command with real PostgreSQL | `go test -p 1 -count=1 -timeout=30m ./...` remains failed: 9 packages cannot load libc. Combining this run with successful chart and benchmark reruns yields 421 passing test packages and 36 packages with no test files; this does not claim a green full command |
| Helm chart security and data-governance tests | Passed with Helm 3.17.3 (1.240s), clearing the earlier missing-Helm failure |
| Capture and benchmark environment checks | Capture fixtures pass with test-only `GOFLAGS=-buildvcs=false`. The candidate builder intentionally clears Go overrides, so it needs the normal module cache and a writable default build cache; restoring those paths and setting `XDG_CACHE_HOME` clears the benchmark failure (full scabench package passed in 49.989s). No benchmark isolation or dependency declarations were changed |
| Full PostgreSQL package after queue transaction fix | Passed all tests against real PostgreSQL in the broader serialized Go run (398.193s), after an earlier full-package pass (376.337s). The earlier full `-race` attempt timed out; focused Bitbucket/migration race tests passed again after the lint fix (6.251s) |
| Additional backend CI checks | Passed: 73 Python tests and AWS staging static security/data-governance checks |

## Current merge allocation

The branch contains upstream main `b1bc5adda23d545f0e821b3e480da5dc7ad3cd1b`. The unshipped Bitbucket lifecycle migration is **0221**, following shipped **0220** and the [maintainer allocation](https://github.com/KKloudTarus/synapse-ce/pull/1544#issuecomment-5981019374). The lifecycle fixture upgrades from 0220 and rolls back to 0220; both security-function inventories retain the Bitbucket entries. Recheck the merged maximum immediately before merge. Earlier allocation numbers below are historical.

## Validation before the 0207 allocation (2026-10-02)

The API wires GitHub, GitLab and Bitbucket directly into `ProviderReceiver`. The combined receiver test covers GitHub fork restrictions, GitLab replay, Bitbucket enqueue failure/retry, UUID and body replay, fork PR routing, bound tenant/project identity, and refusal of unknown providers. GitLab retains transactional payload dedupe; Bitbucket retains its separate transactional UUID/body receipts. The HTTP delivery claim remains GitHub-specific because the other receivers commit their receipts atomically with enqueue.

The Project webhook tests share one queue capture helper. The console retains provider capability checks and allows only Git Projects for GitLab/Bitbucket direct binding; its regression test submits the binding for both providers.

This run uses Go 1.27.1, pnpm 11.19.0 and a local PostgreSQL 17.11 database. Go dependencies were downloaded from the configured public module proxy or their upstream source without changing go.mod/go.sum.

| Check | Result |
| --- | --- |
| Scoped backend race tests: SCM webhook, Project, integrations, SCA, HTTP, Bitbucket provider, memory and Postgres | Passed |
| PostgreSQL race tests: migrations 0203/0206, Bitbucket lifecycle/replay/atomic enqueue/tenant checks, GitLab atomic replay and concurrent bindings | Passed against real PostgreSQL (14.189s) |
| OpenAPI and documentation race tests | Passed |
| `go build ./...` | Passed |
| Scoped `go vet`, including API/worker composition roots | Passed |
| Integrations UI tests, including GitLab/Bitbucket Git-only binding | Passed: 14 tests |
| Frontend typecheck and production build | Passed |

These local checks do not supply actual Bitbucket delivery evidence or English/Vietnamese forge screenshots. Those acceptance items still require a real test repository and reachable deployment.

## Validation after the 0207 allocation (2026-10-02)

The migration SQL is unchanged; only its unshipped version and lifecycle test name/fixture number moved from 0206 to 0207. On the branch rebased onto `696bd990`, the full Go build and scoped SCM webhook, Project, integrations, HTTP, OpenAPI and docs race tests passed. The PostgreSQL migration 0203/0207, Bitbucket lifecycle/replay/atomic enqueue/tenant isolation and GitLab atomic replay/concurrent binding race tests passed against a fresh PostgreSQL 17.11 database (23.937s), including upgrade from 0205 and rollback to 0205.

## Validation after the 0219 allocation (2026-10-03)

Upstream main at `61fefd13` is merged. The Bitbucket migration is 0219 and its lifecycle test starts at 0218, asserts version 0219 after upgrade, and rolls back to 0218 while checking that the existing identity schema remains ready. Both inventory fixtures retain the three Bitbucket functions alongside all identity entries from main.

This run uses Go 1.27.1, PostgreSQL 17.11, pnpm 11.19.0 and golangci-lint 2.13.2. Dependencies unavailable from the configured module proxy were obtained from their pinned upstream Git tags and verified against the existing module checksums; `go.mod` and `go.sum` are unchanged.

The first full PostgreSQL run (520.147s) exposed an existing assessment relationship concurrency bug: another commit could change the selected head between the stale-token check and rebuilding the preview, producing a validation error instead of a stale-preview conflict. Relationship commits now take the existing cycle row lock before both reads. The existing PostgreSQL concurrency/RLS/rollback regression passed 20 consecutive race-enabled runs (82.550s); the assessment cycle/comparison race suites, lint and full build also passed after this fix.

| Check | Result |
| --- | --- |
| `go build ./...` | Passed |
| Scoped `go vet` and golangci-lint on the seven affected backend packages and assessment cycle package; API/worker root vet | Passed; lint reports 0 issues |
| Scoped backend, memory, docs, OpenAPI and platform race tests | Passed |
| Real PostgreSQL migration 0219, inventory, Bitbucket atomic enqueue/retry/replay/tenant isolation and GitLab replay/binding race tests | Passed (9.094s) |
| Full PostgreSQL package on a fresh database after the assessment concurrency fix | Passed (437.005s): 517 top-level tests passed, 0 failed, 4 opt-in tests skipped |
| Integrations UI tests | Passed: 14 tests |
| Frontend typecheck and production build | Passed |

At the time of this historical run, real provider delivery and forge screenshots were unavailable. They were collected on 2026-10-04 as recorded above.

## Review disposition

Published review summaries and maintainer comments on PR #1544 were checked through the 2026-10-04 migration allocation.

| Review/comment | Disposition |
| --- | --- |
| [Initial migration allocation](https://github.com/KKloudTarus/synapse-ce/pull/1544#issuecomment-5944232391) | Superseded by the allocation update below; the already shipped 0203/0205 are unchanged. |
| [First review](https://github.com/KKloudTarus/synapse-ce/pull/1544#pullrequestreview-5387730777) | Rebase conflicts are resolved. Bitbucket UUID/body dedupe is transactional with enqueue, as confirmed by the later review and real PostgreSQL retry/concurrency tests. |
| [Integration review](https://github.com/KKloudTarus/synapse-ce/pull/1544#pullrequestreview-5388456991) | Three-provider dispatcher/composition test and shared queue test helper are fixed. Real signed delivery and bilingual forge evidence are recorded in the 2026-10-04 section. |
| [Updated migration allocation](https://github.com/KKloudTarus/synapse-ce/pull/1544#issuecomment-5948201783) | The initial move to 0206 was tested from a database at 0205; the later 0207 allocation supersedes it. |
| [Approval](https://github.com/KKloudTarus/synapse-ce/pull/1544#pullrequestreview-5390679561) | Reviewer confirmed transactional dedupe, dispatcher composition and helper consolidation; implementation findings are closed. |
| [Outstanding evidence](https://github.com/KKloudTarus/synapse-ce/pull/1544#issuecomment-5950150855) | Completed by the real signed deliveries, bilingual forge screenshot, light/dark console scans and automatic retry recorded above. |
| [Earlier migration allocation](https://github.com/KKloudTarus/synapse-ce/pull/1544#issuecomment-5950579065) | The move to 0207 is superseded by the 2026-10-03 allocation below. |
| [Inventory guards](https://github.com/KKloudTarus/synapse-ce/pull/1544#issuecomment-5951246204) | All three Bitbucket functions remain in both `securityDefinerExceptions` and `runtimeExecuteGrants`, together with the identity additions from main. |
| [Maintainer integration fixes](https://github.com/KKloudTarus/synapse-ce/pull/1544#issuecomment-5953230428) | The maintainer's merge and reviewed inventory entries are preserved. The current lifecycle fixture uses shipped ceiling 0220. |
| [Previous migration allocation](https://github.com/KKloudTarus/synapse-ce/pull/1544#issuecomment-5967845893) | Migration and lifecycle test move to 0219; setup and rollback use 0218. Main is merged again and both inventories preserve all three Bitbucket entries. Superseded by migration 0221; current real provider evidence is recorded above. |

## Reproducing provider verification

A real Bitbucket Cloud test repository and a reachable Synapse deployment are required for these steps:

1. Create an inbound Bitbucket integration, bind one existing Git Project whose persisted source is the test repository, provision its webhook secret, and enable the integration. Configure the returned HTTPS hook URL and the same secret in Bitbucket. Select repository push and pull-request created/updated events.
2. Push a commit on a branch and capture Bitbucket's successful delivery history together with the corresponding queued/completed Synapse analysis and immutable commit SHA. Retry that delivery and verify it does not create a second scan.
3. Open a pull request and push an update. Capture the created/updated deliveries, analysis source SHA and destination base branch. Exercise a fork PR and record credential-free acquisition, disabled build execution, and absence of forge writes.
4. Record the required real forge screenshots and the English/Vietnamese acceptance evidence, with links to the delivery and analysis records. The existing synthetic console images do not satisfy this step.

These steps were completed for the public test repository on 2026-10-04, as recorded above. Retest with a private repository before claiming private connector/fork compatibility. The commit lookup preserves the fail-closed credential boundary when a fork commit is unavailable anonymously from the persisted repository.
