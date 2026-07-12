# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Synapse is under active development and has not cut a tagged release yet. The
capabilities below are already shipped on `main`.

### Added

- **Runtime-confirmed DAST findings.** A gated SAST hypothesis confirmed by the safe runtime-probe verifier now projects into a `Kind=dast` finding (previously an inert taxonomy value with no producer). The analysis layer routes by proof method: a runtime probe (`VerifyRuntime`) emits `Kind=dast` (records `reachability = reachable`, since the probe demonstrated exploitability), while a static or LLM verdict (`Verify`) emits `Kind=sast` — exactly one per confirmation, no duplicate. The finding is a deterministic, templated projection of the typed claim (no LLM). The probe still runs only under scope + window + kernel-enforced sandbox egress + HITL approval.
- **Automated LLM judgment-verifier.** `SYNAPSE_VERIFIER_MODEL`, when set to a model different from `SYNAPSE_LLM_MODEL`, now powers a server-side verifier: `POST /engagements/{id}/judgments/auto-verify` (PermReview) has that distinct model independently score each proposed gated judgment (reachability, SAST, critique, threat, VEX) and seals a verdict through the same gate a human uses — verifier identity `llm:<model>`, never the proposer, so it can never confirm its own claim. Best-effort; a model/verify failure leaves the judgment proposed.
- **AI false-positive gate — API scan path.** The false-positive triage now runs in the scan pipeline for both `synapse-cli` and the durable API scan job (populates `ScanResult.AITriage`).
- **AI false-positive gate — distinct-verifier consensus.** When `SYNAPSE_VERIFIER_MODEL` names a model different from the triage model, a `refuted` verdict must be independently confirmed by that verifier before it exempts the `--fail-on` gate (two-model consensus; a single model can no longer flip the gate on its own). Confirmed entries carry `"verified": true` in `ai_triage`. Falls back to single-model when no distinct verifier is set.
- **False-positive gate.** Findings in test/fixture/example paths (including the `*_test.go`, `test_*.py`, `*.test.ts`, `*_spec.rb` file conventions) are now classified as background scope and held back from the `--fail-on` gate by default (`--include-test` re-includes them). An opt-in AI critique (`SYNAPSE_FP_TRIAGE_ENABLED`) then has the configured LLM adjudicate the remaining production-scope first-party source findings, marking high-confidence refutations as suspected false positives — retain-and-mark (still reported and sealed, exempt from the gate), never deleted.
- **Release engineering.** goreleaser config and a tag-triggered release workflow that publish prebuilt binaries for all five commands (linux, macOS, Windows; amd64 and arm64) with a checksums file, a multi-arch `synapse-cli` container image on GHCR, and a reusable GitHub Action (`uses: KKloudTarus/synapse-ce@v1`) for the CI scan gate.
- **IaC misconfiguration scanning.** Added a Terraform rule for Amazon RDS DB instances without deletion protection.
- **SCA.** Added Conan 2.x `config_requires` packages to OwnSBOM component output.
- **SCA.** Added first-party OwnSBOM support for exact registry packages in Python `uv.lock` files.
- **SCA.** Added Conan 1.x node-level `python_requires` components to OwnSBOM output.
- **SCA.** Added deterministic dependency graph relationships for Conan 1.x `graph_lock` files.
- **SCA.** Added OwnSBOM support for exact Conan dependencies declared in `conanfile.txt`.
- **SCA (software composition analysis).** First-party SBOM generation across many
  lockfile ecosystems, advisory matching against OSV/GHSA/CSAF, and severity/risk
  prioritisation (CISA KEV, EPSS, CVSS). Vulnerabilities at or above a threshold become
  findings.
- **SAST (static analysis).** First-party source-code pattern rules across common
  languages, covering weaknesses such as weak crypto, hardcoded credentials, injection,
  insecure TLS, XPath injection, ReDoS, and insecure temporary files.
- **Secret scanning.** Detection of hardcoded credentials and key material (AWS keys,
  private keys, generic credential assignments) with placeholder/env-reference filtering.
- **IaC misconfiguration scanning.** Owned checks for Dockerfile, Kubernetes, Helm,
  Terraform, and CloudFormation.
- **SARIF output.** `synapse-cli scan --sarif` emits a SARIF 2.1.0 report for GitHub code
  scanning and other SARIF consumers, with a file and line for SAST, secret, and misconfig
  findings.
- **CLI merge gate.** `synapse-cli scan . --fail-on <severity>` exits non-zero when a
  finding at or above the threshold is present, for use in CI pipelines.

### Fixed

- **Config docs.** `docs/guide/configuration.md` listed the analysis-brain flags (judgments, SAST,
  reachability, secret and misconfig scanning, cross-check, compliance, scan cache, image rootfs, owned
  advisory, gomodgraph) as default `false`; they ship `true`. Corrected the defaults to match the code.

[Unreleased]: https://github.com/KKloudTarus/synapse-ce/commits/main
