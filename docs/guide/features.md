# Features

[Documentation home](README.md) · Previous: [Quickstart](quickstart.md) · Next: [Configuration](configuration.md)

## Software composition analysis

**SBOM generation.** Synapse produces a software bill of materials across many ecosystems:
npm, PyPI, Maven, Gradle, Go, Cargo, RubyGems, Composer, NuGet, Hex, Dart and more. It has
owned per-ecosystem lockfile parsers and a pluggable producer, so detection is not tied to a
single vendor. It can also ingest a client-supplied CycloneDX SBOM as the scan inventory.

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
path. Synapse speaks CycloneDX and SPDX with PURL, SARIF, OpenVEX and CSAF, and KEV plus EPSS.
The SBOM both imports and exports: CycloneDX 1.6 and SPDX 2.3 and 3.0 are available from the
engagement, from the API export routes, and from the export button in the dashboard.

## Bounded AI analysis (optional)

An optional analysis layer turns raw scanner and agent output into confirmed findings. It is
deterministic-first and gated. The model only ever proposes. Every claim is a typed judgment
with a lifecycle of propose, verify, confirm. Gated capabilities promote only on a distinct
verifier's sealed verdict above the evidence threshold. Ungated ones need a human accept. The
agent can never confirm its own claim, and no model ever sits in the report path.

Capabilities include reachability proposals, pattern SAST, a taint engine over the call graph,
threat modeling over an architecture seam, AI critique and risk narrative, and human-gated
write-up drafts.

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
