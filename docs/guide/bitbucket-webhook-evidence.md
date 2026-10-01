# Bitbucket Cloud inbound webhook review evidence (#1453)

Implementation scope: signed Bitbucket Cloud push and open PR creation/update deliveries scan one bound existing Git Project. This document records the validation that was actually run; it is not evidence of a real Bitbucket repository delivery.

## Local console evidence

These screenshots render the real console using Chromium against a local Vite server and mocked HTTP API responses. All fixture names, repository URLs and hook paths are synthetic. No real credentials are captured. The secret is cleared immediately on submit, including API failure; the screenshot runner verifies the input is empty. All screenshots are English because the changed console strings currently render in English. Real forge screenshots in English/Vietnamese remain outstanding.

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
- Real PostgreSQL tests use a `NOSUPERUSER NOBYPASSRLS` runtime role. Owner privileges are restricted to fixture setup/cleanup. Hostile tenant/owner identities cannot provision, rotate or accept another endpoint. PUBLIC cannot execute the new SECURITY DEFINER functions. Migration 0204 is tested up and down; runtime direct endpoint DML remains revoked.
- Bitbucket integrations bind one Git Project; concurrent second bindings are rejected. Payload clone URLs cannot override the stored Project repository. Multi-change pushes validate all targets before any enqueue.
- Supported PR deliveries reject comment, approval and change-request payloads, preventing an unsigned event header from reclassifying those signed bodies as PR creation/update events.
- Fork and missing repository identities restrict scans: credential-free acquisition, no build resolvers and no forge writes, including when Project decoration is opted in. An unrestricted control confirms resolver probes actually execute in the corresponding test.
- The queue-only SCA entry point refuses missing queues/tracking stores. Multi-ref pushes enqueue without reserving the single running-scan slot; workers retry slot contention without spending delivery attempts, recheck live scope before execution, skip terminal deliveries by job ID, and expose unstarted dead letters as failed scans. PR source SHA and destination base ref remain pinned in each queued request.

## Validation run

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

## Remaining acceptance evidence

A real Bitbucket Cloud repository/connection has not been supplied, so no actual delivery history, forge status/comment or Vietnamese forge screenshot is claimed. Outbound PR decoration is outside this receiver's scope. The change should stay draft until required full build/CI checks and actual-forge evidence are completed.

The branch starts from `e73a899a0de8bc891f0acb341730bc0c8bed2274` (main after #1539). Migration 0204 avoids the 0203 file reserved by concurrent GitLab PR #1540. Whichever PR merges second must refresh its base, resolve shared webhook administration/HTTP/provider changes, and recheck migration ordering; avoiding a filename collision does not establish compatibility between the two independent PRs.
