# Current Data Center Confluence REST acceptance proof

This redacted bundle covers an isolated local Confluence Data Center fixture and contains no credentials, bearer tokens, or private CA material.

- Normal governed create produced page `1409030` with exactly one configured read group and one configured update group; storage-body script tags were absent.
- A synthetic source revision ran through the normal weekly scheduler. The occurrence completed on that page at provider version `3`; the schedule was then disabled.
- The pre-schedule and scheduled-report PDFs were downloaded with authenticated TLS validation. Each report has one page, and every page is included as a rendered preview.
- A real legal-hold cycle used `PUT /api/v1/fleet/engagements/{id}/legal-hold`, listed the active hold, received HTTP 403 for governed publish and unpublish, then released it with HTTP 204.
- The governed purge completed after the hold release. Direct provider reads for the current page, trashed page, history, and both attachments each returned HTTP 404; the integration was disabled afterward.

Native browser screenshots are deliberately not represented by this REST bundle. API evidence does not substitute for required UI capture.
