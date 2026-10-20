# Leaf closure audit

This audit uses the current bodies and comments of the seven assigned issues,
EPIC decisions D1–D8, and the implementation plan, refreshed on 20 October 2026.
Dependencies #1429 and #1444 are closed. PR #1599 is ready for review and remains
unmerged. Ready-for-review status does not establish that the implementation has
landed; the EPIC requires the implementation, UI, documentation and tests to land
together. Issues must not be manually closed to skip that prerequisite.

| Leaf | Explicit acceptance evidence | Closing disposition |
| --- | --- | --- |
| #1437 GitHub Issues | SCM credentials, private-only preflight and outward recheck; eight refusal cases and private-to-public drift assert zero POSTs. Bypassing the guard via a Go overlay makes those regressions fail. Native private EN/VI issues and console states inspected by QA. | Eligible for a closing keyword with this reviewed delta; closes on merge. |
| #1438 GitLab Issues | Shared SCM credentials, confidential payload/preflight contracts and real confidential EN/VI issues. QA inspected the native badges, content, diacritics and console states. | Eligible for a closing keyword; closes on merge. |
| #1439 Azure Boards | Provider/polling contracts and console states exist. Canonical Markdown now renders as safe HTML in the Azure serializer, with hostile-content/typed-link regressions and frozen-wire workflow proof. Native work-item EN/VI screenshots are absent. | Eligible for a closing keyword after the maintainer explicitly transferred Microsoft native acceptance to #1576 on 20 October 2026. No native pass claimed; closes on merge. |
| #1440 ServiceNow | Incident profile satisfies the issue's “incidents or vulnerability records” outcome. Identity/polling contracts, restricted-token matrix and fresh readable EN/VI records pass. Plain-text formatter regression and independent visual recheck resolve the Markdown-escape defect. | Eligible for a closing keyword with the refreshed evidence; closes on merge. |
| #1441 Linear | Native GraphQL contracts, exact-marker recovery, real EN/VI issues and polling observations. QA inspected native content and console states. | Eligible for a closing keyword; closes on merge. |
| #1447 SharePoint/OneDrive | Restricted provider/release/recovery contracts exist. Native documents and sharing-settings evidence are absent. The available Microsoft account is rejected as a consumer account without business presence. | Eligible for a closing keyword after the same explicit transfer to #1576. The original native/safety acceptance is preserved there; closes on merge. |
| #1448 Google Drive | Contract/restriction/lifecycle tests, actual HTML/PDF, separate Reader access, same-ID republish and governed purge are recorded. Native sharing-settings screenshot is still missing: the owner and Reader sharing dialogs return “you cannot share at this time”; the owner details pane also fails to load. | Keep open until the required product sharing-settings evidence can be inspected. Existing API permission proof and Reader access do not replace that screenshot. |

## Shared definition of done

- The same PR contains implementation and regression tests, current documentation,
  OpenAPI/configuration updates where the public contract changed, and Unreleased
  changelog entries. The latest formatter change adds no API or configuration field.
- The final Docker backend gate, hostile harness and six focused race packages pass.
  The full web suite/build and PostgreSQL/RLS evidence apply to unchanged web/store
  inputs. Exact commands and log hashes are in [verification-summary.json](verification-summary.json).
- Existing permission, sealed-credential, redaction, tenant and revision fences are
  preserved. No new tenant table or route is introduced by the closure corrections.
- QA inspected native ticket EN/VI images and representative light/dark console
  loading, empty, error and permission-denied captures. The refreshed ServiceNow
  images are in the [live ledger](live/README.md#servicenow-identity-correction).

On 20 October 2026 the maintainer explicitly transferred the remaining Microsoft
native acceptance for #1439/#1447 into #1576 alongside Teams/PagerDuty. Those
implementation leaves may close with this PR; #1576 and parent acceptance stay
open. The source issue bodies and tracker contain the scoped transfer. This
supersedes the earlier deferral-only disposition without recording a native pass.

The plan's GitHub browser deep-link check now passes after the user handled the
certificate warning. A fresh click from the real native issue retained the exact
HTTPS engagement/finding URL through local authentication and opened the expected
finding expanded with Open status. [Receipt](live/github-finding-link-result.json)
and [arrival screenshot](live/github-finding-link-arrival.png) retain the running
Docker image provenance; this was navigation acceptance, not a provider-wide rerun.
No agent bypassed the security warning or changed triage.

The broader live fault matrix—actual lost HTTP responses, interrupted upload/purge,
sharing drift/legal hold, terminal actor/proposal and the optional ServiceNow
vulnerability profile—remains explicitly unexecuted. These do not replace the
contract/failure tests already shipped, and they are not silently added to the four
ticket leaves' specific native screenshot criteria or reported as passed.

Notion #1446 remains excluded and released. #1449 remains outside this assignment;
#1457/#1587 and closed #1458–#1460 are reused. Teams/PagerDuty acceptance stays under
#1576. This audit does not close the full B08 batch or authorize a merge.
