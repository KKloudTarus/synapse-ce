# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Workflow-oriented sidebar navigation.** Reorganizes shipped dashboard capabilities around security operations, exposure management, engineering, runtime, and governance; separates engagement creation from the active navigation state; and removes unavailable placeholder destinations.

- **Breaking Asset API consolidation.** Removed `POST|GET /api/v1/assets/services`, `asset.BusinessService`, and the unused `member_of` fleet edge. Business-level Asset reads and writes now use `/api/v1/appsec/assets`; technical/fleet `/api/v1/assets` remains unchanged. Existing business-service rows retain their IDs and owners and receive stable keys during migration.

- Release gates use the owned SBOM engine, provision their pinned Syft and Grype dependencies, and can
  be dispatched manually.

### Fixed

- Standalone CLI scans bind the default tenant before persisting results.
- Release-signing CI uses the corrected provenance action and uploads the checksum signature once.

## [0.1.8] - 2026-08-15

This release expanded Synapse from its SCA and code-quality foundation into a governed, multi-pillar
security control plane.

### Added

- Continuous vulnerability-intelligence synchronization, reconciliation, risk assessment, and review.
- Risk-based remediation SLA policy, deterministic deadlines, immutable assessment history, and governed
  `open` / `mitigating` / `remediated` / `accepted_risk` transitions.
- AI false-positive triage with evidence-bound proposals, an independent verifier, human review,
  evaluation datasets, drift detection, promotion/rollback ledgers, and adversarial-invariance gates.
- Asset-centric correlation, unified risk stories, and judgment-gated cross-pillar promotion.
- Read-only AWS, Azure, and Google Cloud posture collection through a sandboxed helper.
- VM and Kubernetes fleet agents, certificate identity, host/cluster inventory, health and coverage views,
  signed work orders, governed response actions, rollout control, and safe decommissioning.
- Runtime detection, retro-hunting telemetry, purple-team coverage, governed adversary emulation, and
  chained exploitation with a fleet-wide kill switch.
- Governed DAST sessions, imported SARIF findings, source-snapshot publishing, JavaScript reachability,
  and additional first-party code-quality language packs.

### Changed

- Engagement creation and scan queueing became separate operations.
- The landing page, primary guides, and release infrastructure were refreshed for the expanded platform.

### Fixed

- AI and triage paths fail closed on malformed, truncated, unverifiable, or self-confirmed model output.
- Fleet, Kubernetes, DAST, reachability, source-snapshot, and web-navigation review findings were closed.
- CI lint and dependency updates restored the complete release gate.

## [0.1.7] - 2026-07-23

### Added

- Standalone RPM/deb package scans extract package payloads before scanning bundled binaries.
- Automatic remote-vs-local acquisition selection for package inputs.

### Changed

- The CI Action and release workflow verify scanner archives and support package artifacts consistently.

## [0.1.6] - 2026-07-23

### Added

- Standalone Python wheel and egg scans catalog package metadata and bundled native binaries.

## [0.1.5] - 2026-07-23

### Added

- Standalone deb scans infer the target distribution so OS-package CVE matching uses the correct release.

## [0.1.4] - 2026-07-23

### Added

- Standalone RPM, deb, and MSI package-file scanning with package-specific metadata extraction.
- Windows amd64 release archives.

### Fixed

- Release artifacts exclude unsupported Windows arm64 builds and use valid workflow identifiers.

## [0.1.3] - 2026-07-23

### Added

- XML injection code-quality rules.

### Changed

- Findings with unknown component versions no longer gate CI unless an advisory explicitly covers an
  unknown version.

### Fixed

- Container-image and finding-handler regressions found during the release review.

## [0.1.2] - 2026-07-22

### Fixed

- Image scans read `.synapseignore` and accepted-risk policy from the CI repository rather than an
  extracted image filesystem.

## [0.1.1] - 2026-07-22

### Fixed

- OS-package advisory matching is scoped to the detected distribution release.
- Release publishing skips the currently disabled Docker-image build.
- GolangCI-Lint passes in the release pipeline.

## [0.1.0] - 2026-07-22

### Added

- Initial tagged release of the deterministic security and code-quality scanner.
- Source and container-image scanning through the reusable GitHub Action.
- SCA, first-party code-quality rules, secrets and IaC checks, SARIF output, and severity-based CI gates.
- Air-gapped scanning of local `docker save` archives and offline NVD CVSS enrichment.

[Unreleased]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.8...HEAD
[0.1.8]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/KKloudTarus/synapse-ce/releases/tag/v0.1.0
