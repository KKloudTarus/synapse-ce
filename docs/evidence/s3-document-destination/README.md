# S3-compatible document destination (#1449)

Captured on 23 October 2026 against `feat/1449-s3-document-destination`, branched from
`139268f0`.

## Evidence status

This is historical evidence for the earlier implementation. It predates the reader
gateway requirement, ETag conditional-write fencing, bounded history admission, and
all-before-delete exact-version purge proof described in the current S3 guide. It
does not establish live acceptance of those corrected behaviors. The separate
25 October safety acceptance below covers the corrected implementation.

## What was running

| Component | Detail |
| --- | --- |
| API | `synapse-api` on PostgreSQL 17, notifications on, `SYNAPSE_INTEGRATION_HOST_ALLOWLIST=172.28.0.10`, `SYNAPSE_INTEGRATION_PRIVATE_CIDRS=172.28.0.0/16` |
| Worker | `synapse-worker` with `SYNAPSE_WORKER_PROFILE=integrations` |
| Console | Vite dev server with `VITE_API_PROXY_TARGET=http://127.0.0.1:8080`, so no mock handler served a request |
| Destination | MinIO `RELEASE.2025-09-07T16-13-09Z` over TLS at `https://172.28.0.10:9000`, versioning enabled, one reader statement in the bucket policy |

The endpoint is a private address on a dedicated Docker network with a certificate issued by a
local CA, which is what the self-hosted allowlist admits. Loopback is refused by the address
policy, so the destination cannot be `127.0.0.1`.

## What the release did

1. The connection test ran as a durable integration operation and succeeded (`console/integrations-s3-connection-*.png`).
2. A reviewer published the engagement report. The worker created the neutral shell, uploaded the
   PDF attachment, wrote `report.html`, and the link recorded `remote_revision_kind: opaque` with
   `restriction_status: verified`.
3. The destination holds exactly three objects under `engagement-reports/<marker>/`, each stamped
   with `x-amz-meta-synapse-marker` (`destination/destination-state.json`).

## Known limits of this evidence

- The console has no Vietnamese locale, and MinIO renders its own English UI, so every capture is
  in English.
- The loading and error captures are the real console against the real API with one request
  delayed or answered `500` in the browser. Everything else is unmodified traffic.
- MinIO Community Edition's console has no bucket-policy pane, so the policy and the versioning
  status are captured from the S3 API itself in `destination/destination-state.json` rather than
  from a screenshot. The object browser header shows `Access: CUSTOM` for the same bucket.
- Permission denied is shown as the readonly role sees the screen: the connection is readable and
  every management action is withheld. There is no separate error page for it.

## Before the inline-code fix

The first release attempt on this branch reached the body step and ended `uncertain` with no
`report.html` written. The canonical renderer refused the release document because it carries
`<p>Evidence chain head: <code>…</code></p>`, and `code` was admitted only at the root. That
refusal applied to Google Drive and SharePoint/OneDrive as well. `published-report.png` is the
same document rendering correctly after the fix.

## Safety acceptance, 25 October 2026

The corrections were exercised with the actual API and integration worker, durable
PostgreSQL 17, TLS MinIO, and a separate authenticated reader gateway.
[`safety-acceptance.json`](safety-acceptance.json) records publish, changed-report
republish, public-policy refusal, restored-policy recovery, and completed unpublish.
The adapter live tests additionally prove a real competing conditional write,
paginated history beyond 64 versions, and Object Lock legal-hold refusal/recovery.

Browser captures show [anonymous denial](browser-anonymous.png),
[wrong-reader denial](browser-wrong-reader.png), the
[authorized HTML report](browser-authorized-report.png), and
[404 after unpublish](browser-unpublished.png). The temporary local CA was imported
with authorization and removed immediately after the browser checks. No certificate
warning was bypassed. The relative PDF returned authenticated HTTPS 200 with
`application/pdf`, a PDF signature, and valid `pdfinfo` output; the browser automation
PDF plugin rendered blank, so these captures do not claim visual PDF verification.

All 456 Go test packages passed, all command packages built, lint reported zero
issues, vet passed, and race checks passed for the document adapter and publication
use case. The worktree-bound Taurus report retains the exact commands, reviewer
results, and shipping fingerprint; these captures contain no credentials or cookies.

The final history proof uses at most four concurrent read-only version checks and
waits for all of them before the first deletion. A latency regression with 192
locked, unheld versions, simulated 60 ms S3 requests and 5 ms authorization guards
completed all 192 deletes and empty-prefix confirmation in 21.8 seconds under a
35-second deadline, reserving 10 seconds of the worker pass for preliminary work.
After this change, rebuilt API/worker publish and unpublish and all three real
MinIO lifecycle tests passed again.
