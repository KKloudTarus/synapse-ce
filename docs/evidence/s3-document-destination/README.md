# S3-compatible document destination (#1449)

Captured on 23 October 2026 against `feat/1449-s3-document-destination`, branched from
`139268f0`.

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
