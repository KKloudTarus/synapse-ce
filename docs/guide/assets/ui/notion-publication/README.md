# Notion snapshot functional evidence

Verified on 26 October 2026 with a synthetic stored engagement report, the real
Synapse API and PostgreSQL command queue, an integrations worker, and an existing
Notion sandbox workspace. No subscription, card, trial, or paid resource was added.

The destination-managed snapshot profile is an explicit provider-specific contract:
the destination owner controls sharing. An absent public URL is not proof of privacy.
Unpublish is recoverable Trash; files and older snapshots can persist. Schedules are
unsupported. The default connection-only profile remains unavailable for publication.

- [Functional results](functional-evidence.json): native PDF and block readback,
  exact downloaded-PDF hashes, English and Vietnamese text, immutable republish,
  history, idempotency, restart after an upload checkpoint, Trash, republish after
  Trash, and schedule rejection.
- [Console history](console-history.png): three retained snapshots, current marker,
  destination-managed disclosure, and the selected Notion integration.
- [Trash confirmation](console-trash-confirmation.png): recoverable removal and
  retained-file disclosure.
- [Retrieved report](retrieved-report.png): rendered bytes downloaded from the real
  Notion page, checked against the frozen stored report PDF.

The console was exercised against the final running build through its existing
local development endpoint. A repeat publish through the UI created no duplicate.
Destination document/block/file evidence was retrieved through the real Notion API;
a screenshot of the cloud sharing panel is not included and no effective ACL proof
is claimed. The acceptance decision prioritizes functional proof and the adapted
contract; a theme and visual-state matrix was not required.

Local verification passed: Go build and vet, full Go tests with the two environment
failures resolved by rerunning their affected packages, full web suite (215 files,
1545 tests), final focused UI/API regressions, TypeScript, web build, and lint.
Real PostgreSQL tests include populated migration 265 -> 266 -> 265 -> 266. Upgrade
requires the maintenance window documented in the publishing guide. Final security,
QA, architecture, performance, reliability, and frontend reviews have no blockers.
