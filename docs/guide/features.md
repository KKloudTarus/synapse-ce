# Features

[Documentation home](README.md) · Previous: [Quickstart](quickstart.md) · Next: [Configuration](configuration.md)

## Software composition analysis

**SBOM generation.** Synapse produces a software bill of materials with owned per-ecosystem lockfile
parsers and a pluggable producer, so detection is not tied to a single vendor. Current coverage: Go,
npm, Yarn, pnpm, PyPI, Poetry, Pipfile, uv, Cargo, Maven, Gradle, RubyGems, Composer, NuGet, Swift,
Dart, Hex/Elixir, Conda, R (renv), Julia, and Conan. It can also ingest a client-supplied CycloneDX
SBOM as the scan inventory.

**Multi-source detection.** Components are matched against a live advisory API and an offline
database. Results are cross-correlated and de-duplicated, and each finding records the scanner
and database version as evidence. An owned advisory store can ingest OSV, GHSA, CSAF, and
Ubuntu OVAL feeds so that detection does not depend on one provider. A freshness check warns
when a dated database is stale, and a `precise` detection mode routes single-source,
uncorroborated findings into a needs-verify queue instead of failing the build on them.

**Risk-based prioritization.** Findings are ordered by exploitability: the known-exploited
catalog first, then the exploit-prediction score, then CVSS. Ordering never uses raw CVSS
alone, so what is actually being exploited rises to the top.

**Reachability.** A deterministic call-graph engine decides whether a vulnerable symbol is
reachable from application code. A finding on code that is never called can be de-prioritized,
and a deterministic proof supersedes any model opinion.

**SBOM quality scoring.** Beyond coverage, Synapse scores the SBOM document itself against the
NTIA minimum elements and a set of semantic checks, then projects that onto named compliance
profiles: NTIA 2021 and 2025, BSI TR-03183-2, and OWASP SCVS levels 1 and 2. The score is
advisory and never gates a build, but it tells you whether the bill of materials is fit for
downstream vulnerability lookup and sharing.

**Scan cache.** An optional cache, addressed by source content plus the producer version, skips
re-cataloging an unchanged tree. A producer upgrade invalidates it automatically, so a stale
catalog is never served. The cache directory must be operator-owned.

## Secret and configuration scanning

**Secret scanning.** A read-only scan of the workspace flags hardcoded credentials using
keyword prefilters, per-rule regular expressions, and a Shannon-entropy gate for generic
secrets. Every match is redacted before it is stored, so the raw secret never reaches a log,
the evidence ledger, or a report.

**Misconfiguration and IaC scanning.** Owned checks over parsed Dockerfiles and Kubernetes
manifests flag issues such as running as root, unpinned base images, pipe-to-shell installs,
privileged or host-namespace pods, host-path mounts, and dangerous capabilities. The rules are
precision-biased: an unset default is not flagged, only an explicit unsafe setting.

## Container image and OS-package analysis

When container image scanning is enabled, Synapse materializes the image root filesystem and
runs owned catalogers over it, so a shipped artifact is inventoried even without a lockfile:

- **OS packages.** dpkg (`/var/lib/dpkg/status`) and apk (`/lib/apk/db/installed`) for Debian,
  Ubuntu, and Alpine, plus rpm from the sqlite `rpmdb.sqlite` used by modern RHEL, Fedora,
  AlmaLinux, Rocky, and Oracle Linux. Packages are emitted with a distro qualifier so the
  advisory matcher keys them to the right OS ecosystem.
- **Installed binaries.** Go build information embedded in ELF, PE, and Mach-O binaries, and
  Python dist-info and egg-info metadata, become `pkg:golang` and `pkg:pypi` components.

Every parser treats the image as untrusted input: reads are bounded, cancellable, and hardened
against a hostile filesystem or a crafted package database.

## First-party SAST and code quality

Synapse ships its own source-code analysis, not just dependency scanning. First-party SAST rules
run across many languages and feed a taint engine over the sandboxed `go/ssa` and tree-sitter call
graphs; confirmed results emit `Kind=sast` findings. A SonarQube-style code-quality surface adds
quality rules, quality gates and quality profiles, and hotspots. Third-party results enter the same
governance path through **SARIF ingest**, so findings from other scanners are de-duplicated,
prioritized, and reported alongside first-party ones.

## Offensive testing (red team)

Offensive capabilities are governed by a written offensive policy and a kill switch, and run only
inside the hardened sandbox with server-side scope and authorization:

- **Recon** enumerates a target's surface within the authorized scope.
- An **attack-path graph** correlates the asset inventory into reachable exposure chains.
- **Chained exploitation** advances step by step, each step producing its own proof; nothing
  promotes without a distinct verifier's sealed verdict.
- **Adversary emulation** runs benign technique variants that declare the detection each technique
  should produce — the offensive half of the purple-team ledger.

## Runtime defense (blue team)

A distributed **agent fleet** extends Synapse from point-in-time analysis to runtime, over both host
and Kubernetes estates:

- **Agents** collect host inventory and Kubernetes workload/exposure/identity inventory, with
  certificate enrolment, signed packaging and updates, per-asset coverage and freshness, and fenced
  leadership so scheduled work runs once.
- An **eBPF detection engine** observes process, file, network, and privilege events and evaluates a
  first-party detection catalog. A detection is **evidence, not an alert**: it is attributable,
  sealed into the same hash-chained evidence chain, and joined to the same asset and finding the
  static pillars reason about.
- A **columnar telemetry tier** retains raw events with a retention/cost model for retro-hunting.
- **Governed response actions** (isolate host, quarantine file, stop process) run under the *same*
  admission model as exploitation: server-side authorization, a human-approved sealed evidence
  record, argv-only execution, a mandatory reversal, and a declared blast radius.
- **Purple-team coverage** measures which techniques would actually be detected by joining
  emulation-expected detections with what actually fired, and reports the gap as a first-class number.

## Cloud posture (CSPM)

Read-only posture connectors for **AWS, Azure, and GCP** run behind a sandboxed helper. Credentials
are resolved by vault reference and passed to the helper out-of-band over an inherited file
descriptor (never in argv, env, or logs), every cloud operation is authorized server-side against
the engagement scope before it runs, and the connectors issue describe/list/get calls only. Findings
include IaC-declared-vs-live-state drift.

## Governance: suppression, VEX, and compliance

These share one rule that fits a chain-of-custody tool: acceptance is retain-and-mark, never
delete. An accepted finding is still reported, persisted, and evidence-sealed. Only the
`--fail-on` gate is exempted, and the exemption itself is recorded.

- **`.synapseignore` suppression.** Accept a finding by id, with an optional expiry and reason.
  An expired rule re-surfaces the finding and trips the gate again.
- **In-scan VEX.** An in-repo OpenVEX document (`.synapse.vex.json`) marks a finding
  `not_affected` or `fixed` at scan time, on the same retain-and-mark surface.
- **Compliance benchmark.** Re-projects findings onto a control specification and reports
  per-control PASS or FAIL. It reads every finding, including accepted ones, so acceptance can
  never flip a control to PASS.

## License compliance

Declared licenses are resolved to SPDX ids, including full SPDX expressions with AND, OR, and
WITH. A curated category and risk model classifies each license. Coordinate recovery
identifies shaded or metadata-less JARs by their hash, so their licenses and vulnerabilities
are attributed correctly rather than lost.

## Findings and evidence

One finding per issue, de-duplicated and updated in place across re-scans. Every artifact is
hash-chained into a tamper-evident custody record. A broken chain blocks the report. The audit
log and evidence ledger are append-only and can be anchored with an RFC-3161 timestamp for
external, tamper-proof proof.

## Hardened execution

Heavy or capability-sensitive tools are shelled out to pinned binaries via argv arrays, never
a shell string, so no target or agent input is ever concatenated into a command. On a Linux
host they run inside a bubblewrap sandbox with seccomp, cgroup limits, and egress scoping.
Scope and the authorization window are enforced server-side before any tool runs. If the
sandbox is requested but unavailable, startup fails closed rather than running unsandboxed.

## Access control

Per-action role-based access control and tenant isolation flow through a single authorization
chokepoint. Roles cover admin, consultant, reviewer, and read-only, with separation of duties
so a machine identity can never confirm its own claim. Secrets stay server-side in a
credential vault with placeholder substitution.

## Reporting and standards

Reports are templated from stored data and are deterministic. Compliance mapping from CWE to
OWASP, PCI, and ISO controls comes from a curated, source-cited table, with no model in the
path. Synapse exports CycloneDX and SPDX with PURL, SARIF, and OpenVEX, ingests CSAF and OVAL advisory
feeds, and uses KEV plus EPSS for prioritization. CSAF is an ingest format only; there is no CSAF export.
The SBOM both imports and exports: CycloneDX 1.6 and SPDX 2.3 and 3.0 are available from the
engagement, from the API export routes, and from the export button in the dashboard.

## Bounded AI analysis (optional)

An optional analysis layer turns raw scanner and agent output into confirmed findings. It is
deterministic-first and gated. The model only ever proposes. Every claim is a typed judgment
with a lifecycle of propose, verify, confirm. Gated capabilities promote only on a distinct
verifier's sealed verdict above the evidence threshold. Ungated ones need a human accept. The
agent can never confirm its own claim, and no model ever sits in the report path.

False-positive triage keeps the opinion/authorization boundary explicit: a single model can mark a
finding `suspected_fp` but cannot affect a gate. A distinct verifier must agree, then a deterministic
policy keeps high/critical, secret, and dangerous-CWE findings in human review. The full typed decision
and model/prompt/policy metadata are sealed into the scan evidence chain before an exemption can take
effect. Without an evidence ledger the decision remains advisory-only. Secret findings are never sent to
the LLM because even a redacted finding description cannot make its raw source context safe to transmit.

Capabilities include reachability proposals, pattern SAST, a taint engine over the call graph,
threat modeling over an architecture seam, AI critique and risk narrative, and human-gated
write-up drafts.

### Deterministic reachability

Reachability is the strongest anti-hallucination signal: a deterministic proof supersedes any LLM
opinion. The Go path builds a real call graph (Tier-2) and proves whether a vulnerable symbol is
actually called. For **Python** (`SYNAPSE_PYREACH_ENABLED`), a source-only scanner proves whether a
declared PyPI package is imported by first-party code at all — a declared-but-never-imported package
(a dead dependency) becomes a deterministic **Tier-1 `not_reachable`** judgment that the OpenVEX
export turns into a `vulnerable_code_not_in_execute_path` justification. It is honestly tiered
(import-level, weaker than a call path) and conservative: a target that uses dynamic imports
(`importlib`/`__import__`), a non-Python target, or an unresolvable import name yields no verdict
rather than a false "not reachable" that could suppress a real vulnerability.

When `SYNAPSE_PYREACH_TIER2_ENABLED=true`, a CGO-enabled `synapse-ast` sidecar parses Python without
importing or executing it, resolves imports, lexical call targets, constructors, receiver methods and
conservative inheritance, then queries advisory-provided affected symbols. A reached symbol produces a
bounded Tier-2 call path even when unrelated coverage is incomplete. A Tier-2 negative is emitted only
when extraction, resolution and symbol placement are complete; otherwise the Tier-1 judgment remains.
The Tier-2 flag is ignored unless `SYNAPSE_PYREACH_ENABLED=true`.

### Python semantic taint

`SYNAPSE_PYTAINT_ENABLED=true` enables a separate source-only Python value-flow pass. The `synapse-ast`
sidecar emits bounded value slots and expression/assignment/return flows; the analyzer then binds
positional and keyword arguments, method receivers, parameters, and return values across the resolved
call graph. It supports Flask, Django, and FastAPI request entrypoints and initial SQL, command, path,
SSRF, XSS, deserialization, and redirect sink models. Sanitizers are class-specific: HTML escaping stops
an XSS path but cannot hide the same value reaching `os.system`, and `yaml.safe_load` only neutralizes
unsafe-deserialization semantics.

Every hit is a gated `CapSAST` proposal at score zero under `system:python-taint-scan`; this pass has no
verification or self-confirmation path. The audit witness contains only bounded relative positions and
closed catalog metadata—never source contents or literal values. Parser/resolution gaps are recorded as
incomplete coverage: a real positive path may still be proposed, but absence of a path is never published
as a clean judgment. Scan JSON exposes this distinction in `analysis_coverage` as `complete`, `partial`,
`unavailable`, or `not_applicable`, with closed failure reasons, bounded counters, and an aggregated gap
histogram. Partial/unavailable analysis also produces an operator-facing `source_warnings` entry; tool
stderr, target paths, and source text are never copied into either surface.

After a distinct verifier confirms the proposal, its bounded source-to-sink position trace is retained on
the finding. The sink becomes the finding's primary source location, and SARIF 2.1.0 exports the ordered
trace as `codeFlows`/`threadFlows`, together with coverage-complete and graph-truncated properties. A trace
contains at most 64 canonical repository-relative positions and never contains expressions, source lines,
literal values, or internal value identifiers. The feature needs judgments plus a CGO-enabled
`synapse-ast`; it does not import, execute, or compile target Python and therefore does not require the
target-compilation sandbox.

### Runtime confirmation (DAST)

A gated SAST hypothesis can be confirmed at runtime by a **safe HTTP probe**. When a distinct
verifier's runtime probe confirms the hypothesis, the confirmed judgment is projected into a
`Kind=dast` finding — the dynamically-proven twin of the `Kind=sast` projection (a statically or
LLM-confirmed hypothesis stays `Kind=sast`). A DAST finding records `reachability = reachable`,
because the probe demonstrated the sink is actually reachable and exploitable.

The runtime probe never runs unguarded. It executes only through the governed workflow, which
requires, server-side: the target inside the engagement's authorization scope and window; the
sandbox with **kernel-enforced egress confinement** (the probe is refused when the host cannot
enforce the egress allowlist); and explicit HITL approval before any packet is sent. The verifier
records only a structured, closed-token result (a proof class plus a rationale) — raw probe output
lives in sealed, hash-chained evidence, never in the model transcript. The agent can only *propose*
the hypothesis; a **distinct** verifier confirms it, so a claim can never confirm itself.

Next: [Configuration](configuration.md)
