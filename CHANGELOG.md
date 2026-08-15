# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Synapse is under active development and has not cut a tagged release yet. The
capabilities below are already shipped on `main`.

### Added

- **Risk-based remediation SLA governance.** Adds opt-in, tenant/RLS-safe and versioned SLA policy,
  immutable deterministic assessment history, mitigate/remediate deadlines in scan/API/UI output,
  human-only open/mitigating/remediated/accepted-risk transitions with hard acceptance expiry, and
  continuous vulnerability-intelligence reassessment that preserves human state. Replays cannot move
  an original deadline, machine principals cannot accept risk, and remediated findings cannot be
  silently reopened; re-exposure remains explicit review work.

- **Adversarial invariance gate for AI-triage promotion.** Golden datasets can bind a clean control to
  semantically equivalent prompt-injection challenges. Evaluation reports emit source-free pair evidence,
  and the comparison/release boundary requires complete coverage plus zero proposer, verifier, consensus,
  or deterministic-policy flips before a model or prompt can reach human promotion review.

- **Versioned AI-triage release governance.** Recomputes passing candidate comparisons at the approval boundary and records promotions or rollbacks in a create-only, hash-chained ledger. Every decision requires distinct PM and Security approvals bound to the current ledger head; no release artifact mutates runtime model, prompt, threshold, or gate configuration automatically.

- **AI-triage candidate promotion gate.** Strictly revalidates deterministic shadow reports, compares a candidate model/prompt with a baseline on the exact same reviewed dataset and policy, blocks new true-positive escapes plus overall or segment regressions, and emits stable CI evidence that still requires explicit human promotion approval.

- **Judgment-gated cross-pillar promotion.** Correlates deterministic reachability, confident internet-facing attack paths, and active same-path runtime detections into tenant-scoped priority proposals. Distinct sealed verification applies one-level changes, uncertain inputs remain review-only, and signal loss restores the exact prior priority through an append-only, auditable lifecycle.

- **AI-triage input drift evidence.** The tenant observability API and UI now expose deterministic,
  source-free language/CWE/project distributions. A new offline CLI compares them with a versioned,
  human-approved baseline using total-variation distance, writes stable CI evidence, and alerts on
  excessive drift or insufficient samples without gaining model-promotion or quality-gate authority.

- **Continuous vulnerability intelligence and risk management.** Adds operator-managed provider
  sources, durable synchronization and recovery, deterministic canonical advisory revisions,
  tenant-safe inventory correlation, append-only risk assessments, finding/action projections,
  guarded reconciliation and rollout controls, authenticated read/write APIs, OpenAPI coverage,
  and a responsive investigation UI with source, run, occurrence, assessment, and revision
  provenance. Provider input remains bounded and untrusted, raw payloads stay out of ordinary
  responses, and tenant-scoped writes fail closed behind PostgreSQL RLS.

- **Evidence-cited AI false-positive triage.** Supplies bounded deterministic source/sink, data-flow, sanitizer, call-path, route/framework, and reachability metadata to the AI triage proposer/verifier before model calls. Model claims must cite current server-generated evidence-token IDs; unknown, missing, driver-incompatible, or finding-mismatched receipts fail closed. Gate authorization now uses `fp-gate-v5` and requires that closed receipt in addition to the existing severity/CWE/evidence safety floors.

- **Safe AI-triage caching.** Tenant-bound API scans reuse typed proposer/verifier claims only when
  tenant, project/engagement scope, finding fingerprint, complete-source hash, prompt context, models,
  prompt version, and policy version all match. Cache hits are rebound to the current finding,
  re-authorized by deterministic server policy, and sealed into fresh scan evidence; provider failures
  and incomplete verifier claims are never cached.

- **Bounded AI false-positive triage.** Enforces a finite per-scan finding budget and configurable
  concurrency for LLM critique, prioritizes capped work deterministically, stops scheduling queued calls
  on cancellation, and seals/exposes eligible, attempted, and skipped counts while every untriaged
  finding remains reported and gating.

- **Visible AI gate exemptions in SARIF.** Retained findings exempted by the verified AI false-positive policy now carry a standards-based external suppression plus deterministic policy version/reason metadata in both CLI and stored engagement SARIF exports; advisory, review-required, stale, and high-risk decisions remain unmarked.

- **Provider-independent blind AI-triage verifier.** The false-positive verifier can use a separate endpoint and credential, records explicit provider plus canonical model-family metadata, and supports fail-closed `model_family` or stronger `provider` separation-of-duties policy. Missing or mismatched identity metadata keeps findings gating.
- **Asset-centric security management.** Promotes the shipped `fleet_business_services` rows in place to stable-keyed Business Assets above Engagements, with tenant/RLS-safe Project and technical-asset memberships, Engagement assignment, Findings/Coverage/Posture/History roll-ups, and UI built from the existing application components. Third-party findings retain provenance and no-promotion authority, while reachability retains proof tier and first-class `unknown`.

- **Immutable Project Code workspace.** Capture bounded analysis-time source and Git comparison artifacts so historical source, unified/split diffs, and finding locations remain inspectable without reconstructing mutable workspaces; large source and diff views use bounded windows or virtualization.
- **Deterministic reachability for Python (Tier-1 import-reachability).** Extends deterministic call-graph reachability beyond Go/JVM. A source-only scanner (`SYNAPSE_PYREACH_ENABLED`, opt-in) determines which declared PyPI packages first-party code actually imports; a declared-but-never-imported package (a dead dependency) mints a deterministic **Tier-1 `not_reachable`** judgment that the OpenVEX export consumes as a `vulnerable_code_not_in_execute_path` justification. It is source-only (no compile/execute, so in-process like the lockfile parsers), and conservative by design: a non-Python target, a target using dynamic imports (`importlib`/`__import__`), or an unresolvable import name yields *no* verdict rather than a false "not reachable". Honestly tiered — import-level, weaker than the Go call-graph Tier-2 proof.
- **Taint findings cite `file:line` (def-use precision).** The SSA call-graph builder now records first-party symbols' definition positions as a `relpath:line` side table (never an absolute host path, never file contents), carried across the sandboxed `synapse-callgraph` exec boundary. A confirmed taint `CapSAST` finding's location is now a `file:line` — like the pattern engine — instead of only a symbol, and the sealed witness records source→sink positions. It is a coarse, function-granular over-approximation (the function's definition line) and falls back to the symbol when a position is unavailable.
- **Runtime-confirmed DAST findings.** A gated SAST hypothesis confirmed by the safe runtime-probe verifier now projects into a `Kind=dast` finding (previously an inert taxonomy value with no producer). The analysis layer routes by proof method: a runtime probe (`VerifyRuntime`) emits `Kind=dast` (records `reachability = reachable`, since the probe demonstrated exploitability), while a static or LLM verdict (`Verify`) emits `Kind=sast` — exactly one per confirmation, no duplicate. The finding is a deterministic, templated projection of the typed claim (no LLM). The probe still runs only under scope + window + kernel-enforced sandbox egress + HITL approval.
- **Automated LLM judgment-verifier.** `SYNAPSE_VERIFIER_MODEL`, when set to a model different from `SYNAPSE_LLM_MODEL`, now powers a server-side verifier: `POST /engagements/{id}/judgments/auto-verify` (PermReview) has that distinct model independently score each proposed gated judgment (reachability, SAST, critique, threat, VEX) and seals a verdict through the same gate a human uses — verifier identity `llm:<model>`, never the proposer, so it can never confirm its own claim. Best-effort; a model/verify failure leaves the judgment proposed.
- **AI false-positive gate — API scan path.** The false-positive triage now runs in the scan pipeline for both `synapse-cli` and the durable API scan job (populates `ScanResult.AITriage`).
- **AI false-positive gate — distinct-verifier consensus.** When `SYNAPSE_VERIFIER_MODEL` names a model different from the triage model, a `refuted` verdict must be independently confirmed by that verifier before it exempts the `--fail-on` gate (two-model consensus; a single model can no longer flip the gate on its own). Confirmed entries carry `"verified": true` in `ai_triage`. Falls back to single-model when no distinct verifier is set.
- **False-positive gate.** Findings in test/fixture/example paths (including the `*_test.go`, `test_*.py`, `*.test.ts`, `*_spec.rb` file conventions) are now classified as background scope and held back from the `--fail-on` gate by default (`--include-test` re-includes them). An opt-in AI critique (`SYNAPSE_FP_TRIAGE_ENABLED`) then has the configured LLM adjudicate the remaining production-scope first-party source findings, marking high-confidence refutations as suspected false positives — retain-and-mark (still reported and sealed, exempt from the gate), never deleted.
- **Release engineering.** goreleaser config and a tag-triggered release workflow that publish prebuilt binaries for all five commands (linux, macOS, Windows; amd64 and arm64) with a checksums file, a multi-arch `synapse-cli` container image on GHCR, and a reusable GitHub Action (`uses: KKloudTarus/synapse-ce@v1`) for the CI scan gate.
- **CLI preflight.** Added `synapse-cli doctor [path]` for offline pre-scan readiness checks across toolchains, dependency markers, and scan dimensions.
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

### Changed

- **Workflow-oriented sidebar navigation.** Reorganizes shipped dashboard capabilities around security operations, exposure management, engineering, runtime, and governance; separates engagement creation from the active navigation state; and removes unavailable placeholder destinations.

- **Breaking Asset API consolidation.** Removed `POST|GET /api/v1/assets/services`, `asset.BusinessService`, and the unused `member_of` fleet edge. Business-level Asset reads and writes now use `/api/v1/appsec/assets`; technical/fleet `/api/v1/assets` remains unchanged. Existing business-service rows retain their IDs and owners and receive stable keys during migration.

### Fixed

- **Blind AI verifier independence.** False-positive verification now runs on every candidate before the
  proposer result is available and receives only the finding plus source context, preventing proposer
  verdict anchoring. Provider/date aliases and Amazon Bedrock geographic/global inference-profile IDs
  fail closed as the same model family, and operators are warned when aliasing disables verification.
- **Fail-closed AI validation.** Reject missing or out-of-range false-positive confidence and verifier
  scores instead of coercing malformed model output into a valid judgment; canonicalize model aliases
  before enforcing proposer/verifier separation; account conservatively for missing, negative, or
  under-reported token usage before any tool call; prefer validated structured source locations; and
  bound/token-check model-proposed SAST claims and risk-narrative driver lists before persistence.
- **Bounded LLM output.** `ChatRequest.MaxTokens` was set by the agent, false-positive triage, and
  judgment-verifier call sites but never reached the OpenAI-compatible wire request, so provider defaults
  could exceed the intended output budget. The adapter now sends the current `max_completion_tokens`
  field, negotiates and caches the deprecated `max_tokens` spelling only when a legacy gateway explicitly
  rejects the current field, and fails closed on `finish_reason=length` rather than parsing a potentially
  truncated structured verdict.
- **Deterministic AI adjudication.** An explicit `temperature: 0` never reached the provider: the
  OpenAI-compatible adapter only sent the field when it was greater than zero, so the value a
  deterministic caller asks for was indistinguishable from "unset" and was dropped from the request. The
  AI false-positive proposer, its distinct verifier, and the automated judgment verifier all request 0 and
  were therefore adjudicating at the provider's default sampling — the same finding could land on either
  side of the evidence threshold across two runs, so a gate exemption and a sealed verdict were not
  reproducible. `ChatRequest.Temperature` is now a `*float64` (nil leaves the provider default; a non-nil
  value, including 0, is sent verbatim), so those three call sites decode greedily as intended. The agent
  orchestrator is unchanged: it still leaves sampling to the provider unless a run configures one.
- **Config docs.** `docs/guide/configuration.md` listed the analysis-brain flags (judgments, SAST,
  reachability, secret and misconfig scanning, cross-check, compliance, scan cache, image rootfs, owned
  advisory, gomodgraph) as default `false`; they ship `true`. Corrected the defaults to match the code.

[Unreleased]: https://github.com/KKloudTarus/synapse-ce/commits/main
