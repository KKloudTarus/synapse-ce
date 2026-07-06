# Features

[Documentation home](README.md) · Previous: [Quickstart](quickstart.md) · Next: [Configuration](configuration.md)

## Software composition analysis

**SBOM generation.** Synapse produces a software bill of materials across many ecosystems:
npm, PyPI, Maven, Gradle, Go, Cargo, RubyGems, Composer, NuGet, Hex, Dart and more. It has
owned per-ecosystem lockfile parsers and a pluggable producer, so detection is not tied to a
single vendor. It can also ingest a client-supplied CycloneDX SBOM as the scan inventory.

**Multi-source detection.** Components are matched against a live advisory API and an offline
database. Results are cross-correlated and de-duplicated, and each finding records the scanner
and database version as evidence. An owned advisory store can ingest OSV, GHSA, and CSAF feeds
so that detection does not depend on one provider.

**Risk-based prioritization.** Findings are ordered by exploitability: the known-exploited
catalog first, then the exploit-prediction score, then CVSS. Ordering never uses raw CVSS
alone, so what is actually being exploited rises to the top.

**Reachability.** A deterministic call-graph engine decides whether a vulnerable symbol is
reachable from application code. A finding on code that is never called can be de-prioritized,
and a deterministic proof supersedes any model opinion.

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

## Bounded AI analysis (optional)

An optional analysis layer turns raw scanner and agent output into confirmed findings. It is
deterministic-first and gated. The model only ever proposes. Every claim is a typed judgment
with a lifecycle of propose, verify, confirm. Gated capabilities promote only on a distinct
verifier's sealed verdict above the evidence threshold. Ungated ones need a human accept. The
agent can never confirm its own claim, and no model ever sits in the report path.

Capabilities include reachability proposals, pattern SAST, a taint engine over the call graph,
threat modeling over an architecture seam, AI critique and risk narrative, and human-gated
write-up drafts.

Next: [Configuration](configuration.md)
