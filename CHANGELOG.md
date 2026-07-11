# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Synapse is under active development and has not cut a tagged release yet. The
capabilities below are already shipped on `main`.

### Added

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

[Unreleased]: https://github.com/KKloudTarus/synapse-ce/commits/main
