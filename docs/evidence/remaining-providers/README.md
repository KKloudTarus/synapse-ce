# Remaining ticket and document providers

## Acceptance ledger

Preflight: 20 October 2026, `origin/main` at `545bb50e`. B04 (#1582), document
foundation (#1577), and B07 (#1586, merge `17d2e496`) are merged. Existing
intents, links, reconciliation, release controls, and retained evidence are reused.
The implementation order is #1437 → #1438 → #1439 → #1440 → #1441 → #1447 →
#1448. The maintainer authorized the recorded #1437 takeover.


Current draft scope, agreed with the maintainer on 20 October 2026: the working
ticket and Microsoft/Drive document profiles below are implementation-ready.
Notion (#1446) is excluded entirely, including connection-only registration and
configuration; its claim and assignment are released on the issue. Live E2E and
destination screenshots remain deferred. This is not acceptance or closure of the
full B08 batch.

| Issue | Existing main | Candidate implementation / provider limit | Required current checks / remaining acceptance |
| --- | --- | --- | --- |
| #1437 GitHub Issues | Credentialless inbound adapter; tenant/host SCM credential store; durable ticket workflow | Private-only issue provider, SCM resolver injection, metadata, exact preview/marker recovery, registry/API/UI | Contract/privacy recheck, host/tenant/credential/redaction, failure/recovery and workflow tests; private EN/VI issues and console states remain live acceptance |
| #1438 GitLab Issues | Inbound adapter and SCM connector | Confidential issue provider using same ticket path, SaaS/self-managed policy | Confidentiality, credential/egress/rate/error/uncertainty tests; native confidential EN/VI issues and console states remain live acceptance |
| #1439 Azure Boards | Shared registry and ticket reconciliation | Native work-item provider and polling | Contract, exact-marker recovery, permissions/tenant/sealed secret, polling proposal tests; native work items remain live acceptance |
| #1440 ServiceNow | Shared registry and ticket reconciliation | Incident/vulnerability record provider and polling | Contract, exact correlation recovery, permissions/tenant/sealed secret, polling proposal tests; native records remain live acceptance |
| #1441 Linear | Shared registry and ticket reconciliation | Native GraphQL issue provider | GraphQL errors, metadata, exact-marker recovery, credential/egress/polling tests; native issues remain live acceptance |
| #1447 SharePoint / OneDrive | Shared document intent/restriction/release controls | Graph provider, opaque revision fencing, restricted-sharing proof, purge | Contract/ACL/pagination/inheritance/CAS/recovery/legal-hold/purge tests; native document and sharing views remain live acceptance |
| #1448 Google Drive | Shared document intent/restriction/release controls | Drive provider, opaque revision fencing, restricted-sharing proof, purge | Contract/ACL/pagination/inheritance/CAS/recovery/legal-hold/purge tests; native document and sharing views remain live acceptance |

No new #1449 implementation: its conditional claim remains with nghiadaulau.
No duplicate #1457 implementation or PR: #1587 merged on 19 October 2026.
The candidate was fast-forwarded to `origin/main` at `a55a314a`, reusing its SIEM
hostile-harness coverage and the subsequent canonical-assignee visual evidence.
#1458–#1460 are closed; their merged transports are reused without rebuilding.
Teams/PagerDuty acceptance remains deferred under #1576 and is outside this change.

## Design and invariants

Reuse the shared durable executors. Build the provider payload during preview, persist
approved content, and add only the correlation marker at submit. Preserve legacy Jira
snapshots. A provider's native privacy policy must be explicit; absence of Jira security
levels is not a waiver. Resolve forge credentials from the current tenant/host SCM
connector immediately before requests, including the final private/confidential preflight.
Do not copy them into integration credentials. Provider responses and URLs are untrusted;
requests remain bounded and origin-pinned through safehttp/operator self-hosted policy.

Partial attachment and purge outcomes remain quarantined until completion can be
proved. They are not automatically retried or adopted, and a missing object does
not prove permanent erasure. Neutral-shell recovery can converge automatically
only after exact identity, marker, authority and restriction proof.

Document publication retains reviewer permission, detail class, source state/legal hold,
verified restriction before each content upload, authority and lease/revision fences,
uncertain-result recovery, append-only audits, and governed unpublish. Opaque remote
revisions must round-trip durably; an ETag must not be hashed or truncated into an integer.
If an API cannot prove the required sharing or permanent purge, refuse release and keep
that capability unavailable. An operator assertion is not provider permission evidence.

## Execution and evidence limits

The maintainer directed implementation first and deferred E2E on 20 October 2026.
No B08 live acceptance or Docker full-stack E2E is claimed by this preflight.
Future GitHub acceptance must include a fresh unique correlation label with the
configured PAT and recovery after a lost create response. A disposable local PostgreSQL container is used for persistence checks; no B08
provider sandbox credentials were established. Missing live
resources: dedicated private GitHub repository; GitLab project; Azure DevOps organization
and project; ServiceNow instance; Linear workspace;
Microsoft Graph test tenant, drive and restricted reader group;
Google Drive test account/container and restricted reader identity. Live permissions,
retention and sharing settings must be checked before future acceptance operations.

B04/B07 screenshots and provider receipts retain their original source/environment/time
provenance. They are historical foundation evidence, not current B08 execution. Revoked
B06/B07 OAuth must not be reused. No billing or school resources may be changed.
Contract doubles prove local behavior only. Current commands, review findings, UI previews
and the final gate will be recorded here as they are produced; missing checks are not pass.

## Review corrections

The first combined implementation review and security/performance passes requested
changes. Their findings are not approvals of the current candidate:

| Finding | Correction / verification status |
| --- | --- |
| Native browser URLs rejected after successful ticket creation | GitLab uses its `/-/issues/` path; Linear uses its explicit browser origin; ServiceNow uses the documented Next Experience path with an encoded target and no outer query. Adapter and shared workflow acknowledgment/reconciliation regressions pass. The stored URL constraints remain unchanged. |
| Unsupported Linear `Issue.updatedBy` query field | Removed; schema-shaped request tests assert that polling uses supported fields. |
| Linear recovery accepted marker substrings | Require the exact terminal delimited marker exactly once; prefix, embedded, duplicate and foreign-team candidates are refused. |
| Graph republish rejected newly staged attachments | A canonical, conditional-write ownership manifest binds staged filenames to exact Graph item IDs across adapter reconstruction. Manual files remain refused. Republish and purge regressions pass; reconstructed-adapter recovery tests cover interrupted neutral-shell initialization. |
| Graph purge required the narrow ACL it was meant to remediate | Separate identity/ownership reads from restriction proof; guarded purge can remove the publication after sharing drift. |
| Encoded document credentials were accepted | Reuse the shared scrubber for raw, base64 and hex credentials, including both Microsoft audience tokens. |
| Self-hosted forge calls created unowned HTTP pools | Reuse the adapter-owned policy client while validating the current connector endpoint before each request. |
| Native hex-encoded credentials passed validation | Shared redaction now validates every decoded JSON literal with the bound credential; lowercase/uppercase hex regressions cover ordinary and SCM tokens. |
| GitLab group membership was ignored | Effective access uses the maximum of direct project and inherited group access, with missing/null/low and mixed permission regressions. |
| SCM credential rotation bypassed literal payload scanning | Immediately before the outward write, scan against the exact copied credential selected after the privacy/access preflight. The rotation regression proves no POST occurs; the bounded security recheck and Docker race test pass. |
| Partial purge/upload was classified as a clean refusal after remote effects | Both purgers validate all children before deleting; any error after delete dispatch remains ambiguous. Graph post-create ACL/manifest/readback failures retain the fence. Executor post-restriction verification/readback failures also remain uncertain. Actual adapter regressions and the core quarantine/readback recovery regressions pass in Docker. |
| Repeated document proofs consumed the worker budget | Reuse actor/metadata within one fresh Drive proof, fetch each ACL once, and avoid a duplicate monitor read. Maximum attachment proof regression passes. A document-local clean-checkpoint yield resumes acknowledged work without waiting for lease expiry. Graph snapshot reuse and four concurrent read-only child checks remove redundant proof work without caching across writes. At eleven attachments, the previously failing 300ms/request attachment completes in 18.972s under 45s; the 210ms/request monitor completes in 4.219s under 10s. These are synthetic measurements, not live guarantees. The full persistence gate is recorded separately. |

Notion is excluded from this PR at the maintainer's direction. The separate
[#1446 issue](https://github.com/KKloudTarus/synapse-ce/issues/1446) retains its
original product goal and acceptance, the released ownership, and feasibility
notes for a future manual snapshot publication profile. No Notion provider,
configuration form or connection-only capability ships in this change.

## Local verification

Final checks run in Docker at the maintainer's request. The runtime is built from
[docker-runtime.Dockerfile](docker-runtime.Dockerfile): Go 1.27.0, Node 22.23.3 and
pnpm 9.15.9. Its verified image ID is
`sha256:a43aacdbc518ab3918c7f21563ce77ea85e927348b488b1f5d36f985709a3fde`.
The backend runner mounts golangci-lint 2.13.2 and Helm 3.19.0 read-only, uses
`GOCACHE=/cache/go` and `XDG_CACHE_HOME=/cache`, and shares the local Go module
cache. The XDG cache setting also gives the SCA candidate's intentionally isolated
build environment a writable default cache without changing its source or policy.
The database gate uses disposable PostgreSQL 17 and streams Go test JSON.

Current results:

| Check | Result |
| --- | --- |
| Full PostgreSQL persistence/RLS suite, `go test -json -timeout 90m -count=1 ./internal/infrastructure/persistence/postgres` | Docker exit 0; 1,149 test cases passed, four skipped, no failures, 1,712.893s. Persistence source inputs remained unchanged throughout. |
| Full web suite, typecheck, production build and lint | Docker exit 0; 212 files and 1,438 tests passed. Lint: zero errors, twenty warnings. |
| Document provider and shared executor recovery race regressions | Docker passed: documentproviders 5.680s and docpublish 14.651s. Includes permanent first/second DELETE 404 and post-create corrupt neutral-body readback regressions. |
| Exact outbound SCM credential rotation and ticket workflow race regressions | Docker passed: ticketproviders 1.130s and ticketing 4.736s. Independent security focus passed in 1.041s. |
| SCA candidate package after fixing the Docker cache | Docker passed, 103.800s. |
| Final backend lint, build, vet, full tests, typecheck, hostile harness and focused race gate | Docker exit 0 on the final Notion-exclusion candidate. Lint: zero issues; no test failures. Current race: document adapters 4.955s, shared document executor 12.520s and integration service 1.038s. Prior domain/store/ticket race evidence applies to unchanged production code. |

After removing Notion, the full Docker web suite again passed all 212 files and
1,438 tests, followed by typecheck, production build and lint (zero errors, twenty
warnings). The final docs/API drift recheck passed in 2.087s and 0.859s. The opt-in
rendering test regenerated the three authoritative provider descriptors; six
retained configuration captures are unchanged. Independent QA, security and
frontend reviews passed the removal delta. PostgreSQL/migration inputs are
unchanged, so the completed full database run remains applicable.

Earlier native PostgreSQL runs terminated with `signal: killed`; an initial cold
Docker lint run exceeded its default timeout. The first broad Docker runner then
failed because Helm was absent and the SCA isolated build cache was not writable.
Those runs are not pass evidence. The final backend runner mounts Helm, sets the
XDG cache, and allows fifteen minutes for the same linter checks.

Final recovery QA, security, shared-core reliability, frontend and architecture
reviews passed for their inspected working profiles after corrections. The bounded
SCM rotation security recheck also passed. The real schedule/Service/Executor
regression verifies one frozen artifact, yielded intent progress and the same
occurrence converging after lease expiry without duplicate remote effects.

The final performance review ran Docker contract measurements in 27.259s: Graph
attachment eleven made 108 requests in 18.972s at synthetic 300ms latency, within
the 45s worker-pass budget; monitoring made 38 requests in 4.219s at 210ms latency,
within its 10s budget. Eleven attachment slices made 913 Graph requests and 286
Drive requests. Concurrent read proofs peaked at four, with none active after
return; failed proof caused zero writes. These measurements do not establish live
latency or throughput.

Partial attachment/purge quarantine preserves safety and durable fences; it does
not claim automatic convergence. Live E2E and destination screenshots remain deferred.
The worktree-bound Taurus report covers the supported profiles in this PR. Notion
is outside its scope. Technical checks pass for the implementation delivered here. The Draft PR remains unmerged and
must not be read as full B08 or native live acceptance.
[Verification summary](verification-summary.json) records the Docker commands,
exit codes and log digests. Full raw logs remain local outside source control.

## Local visual previews

All captures below use synthetic fixtures. They show production components or the
actual HTML bytes produced by the document adapters; they are not screenshots from
live provider sandboxes and do not satisfy native live acceptance.

- [Ticket settings, light](console/github-issues-light.png),
  [dark](console/github-issues-dark.png),
  [mobile](console/github-issues-light-mobile.png).
- [Loading](console/loading-light.png), [empty](console/empty-light.png),
  [provider error](console/error-light.png),
  [permission denied](console/permission-light.png).
- [SharePoint configuration, light](configuration/sharepoint-light.png),
  [dark](configuration/sharepoint-dark.png),
  [Drive configuration](configuration/google-drive-light.png).
- [Finding ticket preview](ticket-entry/ticket-preview-light.png),
  [bulk preview](ticket-entry/bulk-preview-dark.png),
  [finding selection](ticket-entry/findings-bulk-selection-light.png).
- [Publication and schedules](publication-console/document-light.png),
  [sharing drift](publication-console/restriction-lost-dark.png),
  [native request preview](publication-console/azure-preview-dark.png).
- [SharePoint HTML, Vietnamese](documents/sharepoint-vi.png),
  [Drive HTML, English](documents/drive-en.png).

The console manifests record capture hashes and browser errors. Generate the HTML
fixtures with `SYNAPSE_DOCUMENT_PREVIEW_DIR` set to this directory's `documents/`
path and `go test ./internal/infrastructure/integration/documentproviders -run
'^TestDocumentRenderingEvidence$' -count=1`. Run a local Vite server with
`VITE_API_PROXY_TARGET` set so development MSW does not intercept the fixtures, then
run `web/scripts/remaining-providers-evidence.mjs` and
`web/scripts/document-provider-previews.mjs` and
`web/scripts/document-configuration-previews.mjs` and
`web/scripts/ticket-entry-previews.mjs` from `web/`. These scripts intercept
API calls locally and do not contact provider services.
