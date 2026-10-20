# Remaining ticket and document providers

## Acceptance ledger

Preflight: 20 October 2026, `origin/main` at `545bb50e`. B04 (#1582), document
foundation (#1577), and B07 (#1586, merge `17d2e496`) are merged. Existing
intents, links, reconciliation, release controls, and retained evidence are reused.
The implementation order is #1437 → #1438 → #1439 → #1440 → #1441 → #1447 →
#1448. The maintainer authorized the recorded #1437 takeover.


Current approved scope, agreed with the maintainer on 20 October 2026: the working
ticket and Microsoft/Drive document profiles below are implementation-ready.
Notion (#1446) is excluded entirely, including connection-only registration and
configuration; its claim and assignment are released on the issue. Live E2E has since started on authorized personal sandboxes; see the
[current live ledger](live/README.md) for actual outcomes and remaining gaps.
This is not acceptance or closure of the full B08 batch. The
[leaf closure audit](closure-audit.md) separates explicit issue requirements from
additional native fault scenarios and records the unresolved landing/evidence gates.

| Issue | Existing main | Candidate implementation / provider limit | Required current checks / remaining acceptance |
| --- | --- | --- | --- |
| #1437 GitHub Issues | Credentialless inbound adapter; tenant/host SCM credential store; durable ticket workflow | Private-only issue provider, SCM resolver injection, metadata, exact preview/marker recovery, registry/API/UI | Contract/privacy/tenant/recovery tests pass; real private EN/VI issues, replay and acknowledgement-commit recovery recorded. Lost provider HTTP-response recovery remains open |
| #1438 GitLab Issues | Inbound adapter and SCM connector | Confidential issue provider using same ticket path, SaaS/self-managed policy | Contract/privacy/tenant/recovery tests pass; real confidential EN/VI issues and one-attempt adoption of an uncertain create recorded. Broader native failure coverage remains open |
| #1439 Azure Boards | Shared registry and ticket reconciliation | Native work-item provider and polling | Contract, exact-marker recovery, permissions/tenant/sealed secret, polling proposal tests; native work items remain live acceptance |
| #1440 ServiceNow | Shared registry and ticket reconciliation | Incident/vulnerability record provider and polling | Contract, correlation recovery, permissions/tenant/sealed secret, polling proposal tests; native incident EN/VI and restricted-token checks passed |
| #1441 Linear | Shared registry and ticket reconciliation | Native GraphQL issue provider | Contract and polling tests pass; real EN/VI issues, idempotent replay and observations recorded. Native terminal-author/proposal and failure acceptance remains open |
| #1447 SharePoint / OneDrive | Shared document intent/restriction/release controls | Graph provider, opaque revision fencing, restricted-sharing proof, purge | Contract/ACL/pagination/inheritance/CAS/recovery/legal-hold/purge tests; native document and sharing views remain live acceptance |
| #1448 Google Drive | Shared document intent/restriction/release controls | Drive provider, opaque revision fencing, restricted-sharing proof, purge | Contract/ACL/pagination/CAS/recovery/legal-hold/purge tests pass; real restricted publish, same-ID republish, Reader PDF access and governed purge recorded. Interrupted upload/purge and sharing-drift native acceptance remain open |

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

The initial implementation-only gate was followed by authorized personal-sandbox
E2E through the Docker API and integrations worker. The [live ledger](live/README.md)
records native English/Vietnamese GitHub, GitLab and Linear issues, idempotent replay,
GitHub acknowledgement-commit recovery, and restricted Drive publication, same-ID
republish, Reader PDF access and governed purge. Earlier captures retain their
candidate provenance; they are not represented as reruns on a later binary.

Outstanding native acceptance includes an actual lost provider HTTP response,
interrupted attachment upload/purge, live sharing drift/legal hold, and terminal
actor/proposal cases. ServiceNow native EN/VI incidents now pass exact full-content
readback and replay with one attempt each, using a role-free machine and explicit
endpoint denials. The first partial-content incident remains quarantined; the
vulnerability profile and terminal actor/proposal cases are not passed.
Microsoft Azure Boards and SharePoint/OneDrive acceptance remains
explicitly deferred on #1439/#1447. It needs an Azure DevOps organization/project
and a business test tenant, drive, reader group and scoped credentials.

B04/B07 evidence remains historical foundation evidence. Revoked B06/B07 OAuth was
not reused, and billing and school resources were not changed. Contract doubles
prove local behavior; they do not replace the remaining native acceptance.

## Review corrections

The first combined implementation review and security/performance passes requested
changes. Their findings are not approvals of the current candidate:

| Finding | Correction / verification status |
| --- | --- |
| Native browser URLs rejected after successful ticket creation | GitLab accepts its exact `/-/issues/` and `/-/work_items/` paths; Linear uses its explicit browser origin; ServiceNow uses the documented Next Experience path with an encoded target and no outer query. Adapter and shared workflow acknowledgment/reconciliation regressions pass. The stored URL constraints remain unchanged. |
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

Live testing exposed and corrected additional boundary defects:

- Omitted mapping collections are normalized to JSON arrays/objects before the
  PostgreSQL update; the real locale update now succeeds without weakening CAS/RLS.
- Drive omits `pageToken` on first-page permission/child requests. Non-empty
  continuation tokens, repeat detection and bounded pagination remain intact.
- Drive metadata and media ETags differ in real responses. Revision-pinned bytes,
  checksum verification and a final conditional metadata proof now protect reads
  and duplicate-attachment recovery; write CAS and purge identity remain separate.
- Mapping selectors disclose provider, connection and endpoint. Preview disclosure
  comes from the digest-bound snapshot. Known Jira mappings retain their own route;
  missing native connections lock saving while preserving orphan inspection/deletion.

Notion is excluded from this PR at the maintainer's direction. The separate
[#1446 issue](https://github.com/KKloudTarus/synapse-ce/issues/1446) retains its
original product goal and acceptance, the released ownership, and feasibility
notes for a future manual snapshot publication profile. No Notion provider,
configuration form or connection-only capability ships in this change.

## Local verification

Final checks ran in Docker using Go 1.27.0, Node 22.23.3, pnpm 9.15.9,
golangci-lint 2.13.2, Helm 3.19.0 and PostgreSQL 17. The runtime defined by
[docker-runtime.Dockerfile](docker-runtime.Dockerfile) is
`sha256:a43aacdbc518ab3918c7f21563ce77ea85e927348b488b1f5d36f985709a3fde`.
The runner uses `GOCACHE=/cache/go`, `XDG_CACHE_HOME=/cache` and a persistent cache
on the host filesystem. Live API, worker and web binaries were rebuilt after the
fixes; [candidate hashes](live/candidate-provenance.json) identify their inputs.

| Check | Current result |
| --- | --- |
| `golangci-lint run --timeout=15m && make build vet test typecheck && make harness` | Docker exit 0; lint zero issues; no failing checks |
| Focused race gate: ticket/document adapters, ticket/document use cases and integration service | Docker exit 0; independent QA also reran both adapter packages with `-race -count=1` |
| Full PostgreSQL persistence/RLS suite, `go test -json -timeout 90m -count=1 ./internal/infrastructure/persistence/postgres` | 1,149 passed, four skipped, no failures, 1,375.446s. Persistence inputs remained unchanged afterward |
| Full web Vitest suite, typecheck, production build and lint | 212 files / 1,450 tests passed; zero lint errors, twenty warnings. Final scope-fixture correction also passed all eleven Settings tests |
| `go test -count=1 ./docs ./api` | Docker exit 0; 1.456s and 0.439s |
| Independent implementation QA, QA/security/performance/reliability/frontend/architecture reviews | Passed after the Settings routing, permission and orphan-visibility corrections |
| Browser evidence | Production-component fixture captures include missing/failed destination discovery, snapshot disclosure and 390px reflow. Actual Edge keyboard selection/preview/request expansion reached Submit without submitting a duplicate |

The subsequent ServiceNow identity correction replaces a nonexistent endpoint with
a bounded authenticated-user Table API query. The full Docker backend gate and
focused adapter race/API/use-case checks passed; nine identity contract cases
cover successful and fail-closed responses. QA, security, performance and
architecture reviews found no blocking source issue. The [live ledger](live/README.md#servicenow-identity-correction)
records the native restricted-token matrix, successful incident runs, and the
preserved partial-content failure separately from source checks.

The first broad web run found a missing API test stub and two unrelated fifteen-second
Template test timeouts. The stub was corrected; the final run used two workers and
passed without increasing timeouts. Earlier Docker failures caused by a full `/tmp`
cache, missing tooling or native toolchain termination are not pass evidence.

The new Drive readback adds one conditional metadata GET per body or duplicate
attachment proof; it does not change the restriction monitor path. Independent
Docker checks passed bounded revision/cancellation/oversize cases and the existing
maximum-attachment proof. The Graph eleven-attachment check measured 59 requests /
3.213s at synthetic 100ms transport delay; Drive retained its eighteen-request proof
bound. These are contract measurements, not native SLO or throughput claims.

Partial attachment/purge ambiguity remains durably quarantined. The earlier failed
Drive update is retained behind its release fence; a separate synthetic source
verified the corrected lifecycle. No automatic recovery or erasure is inferred
from a missing remote object. Deploy the preview backend before the new frontend;
older preview APIs fail closed in the new UI. Roll back the UI before the backend.

The [verification summary](verification-summary.json) records commands, outcomes and
log hashes. The worktree-bound Taurus report is local under `.git/taurus/`. Raw logs,
credentials and private runtime configuration remain outside source control.

## Local visual previews

The 96 captures below use synthetic fixtures. They show production components or the
actual HTML bytes produced by the document adapters; they are not screenshots from
live provider sandboxes and do not satisfy native live acceptance.

- [Ticket settings, light](console/github-issues-light.png),
  [dark](console/github-issues-dark.png),
  [mobile](console/github-issues-light-mobile.png).
- [Loading](console/loading-light.png), [empty](console/empty-light.png),
  [provider error](console/error-light.png),
  [permission denied](console/permission-light.png),
  [orphan mapping recovery](console/orphan-light.png).
- [SharePoint configuration, light](configuration/sharepoint-light.png),
  [dark](configuration/sharepoint-dark.png),
  [Drive configuration](configuration/google-drive-light.png).
- [Finding ticket preview](ticket-entry/ticket-preview-light.png),
  [bulk preview](ticket-entry/bulk-preview-dark.png),
  [finding selection](ticket-entry/findings-bulk-selection-light.png),
  [unresolved destination](ticket-entry/ticket-unresolved-light.png),
  [missing preview destination](ticket-entry/ticket-preview-missing-destination-dark.png),
  [390px preview](ticket-entry/ticket-preview-light-mobile.png).
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
API calls locally and do not contact provider services. Run these capture scripts
sequentially against one Vite server; temporary-entry creation/removal triggers
reloads in other simultaneously running captures.

## Azure description correction

Azure Boards serializes canonical message Markdown into safe HTML at the native
payload builder. The formatter retains the source body and keeps typed links
separate. The builder escapes hostile text and defangs body URLs; only checked
HTTPS links create anchors. The shared renderer is extracted from the existing
email formatter without changing email output, layout or severity. This avoids
trusting arbitrary HTML passed to a direct payload-builder call.

Regression tests cover Vietnamese punctuation, lists, line breaks, emphasis/code,
HTML injection, body-originated URLs, unsafe typed links and exact anchor count.
A workflow test uses the real Azure formatter/builder and proves that dispatch
sends the frozen HTML without calling the builder again. Tests failed before the
fix and pass afterward in Docker.

[Serializer preview](ticket-rendering/azure-description.png) shows the actual
fixture bytes in [azure-description.html](ticket-rendering/azure-description.html).
Its [manifest](ticket-rendering/manifest.json) records local hashes. This capture is
additional to the 96 component/report previews; it is synthetic local evidence,
not Azure product acceptance. The Microsoft sandbox deferral remains unchanged.

Regenerate with `SYNAPSE_TICKET_PREVIEW_DIR` pointing at `ticket-rendering/` and
`go test ./internal/infrastructure/integration/ticketproviders -run
'^TestAzureDescriptionRendersSafeHTMLAtPayloadBoundary$' -count=1`, then run
`node scripts/ticket-description-previews.mjs` from `web/` with Chromium available
at `/usr/bin/chromium`. The browser aborts all network requests during capture.
