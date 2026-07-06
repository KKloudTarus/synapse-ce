# Introduction

[Documentation home](README.md) · Next: [Installation](installation.md)

## What is Synapse

Synapse runs the security-assessment lifecycle behind one governed control plane: software
composition analysis, recon, evidence capture, findings, and reporting. It is built for
consultancies and security teams that need results they can put in front of a client, with a
clear chain of custody.

The design goal is simple to state. Be fast, but be provable.

## Core ideas

**Deterministic-first.** Scanning, matching, license classification, and reporting are pure,
reproducible Go. The same inputs give the same outputs. There is no model in the report path.

**Bounded automation.** Where automated analysis helps, it is strictly bounded. A proposal is
only ever proposed. A typed Go state machine validates and executes it. Any capability that
could change a claim is gated: it needs a distinct verifier or a human sign-off before it is
confirmed.

**Scope-gated execution.** Every engagement carries an explicit scope and an authorization
window. Both are checked in the execution layer, server-side, before any tool runs. This is
not a prompt and not a single skippable hook.

**Tamper-evident by construction.** Every artifact is hash-chained. Audit and evidence logs
are append-only. A broken chain blocks the report, so a report always rests on evidence that
verifies.

**Secrets stay server-side.** A credential vault with server-side placeholder substitution
keeps tokens out of logs, transcripts, and source.

## How a scan flows

1. **Engagement.** You define a scope (in and out) and an authorization window. Nothing runs
   outside it.
2. **Acquire.** The target (a path, a git ref, or a container image) is pulled into an
   isolated workspace, size-bounded.
3. **SBOM.** Synapse generates a software bill of materials across many ecosystems, or ingests
   a client-supplied CycloneDX SBOM as the inventory.
4. **Detect.** Components are matched against a live advisory source, an offline database, and
   an optional owned advisory store. Results are cross-correlated and de-duplicated.
5. **Prioritize.** Findings are ordered by real risk: known-exploited catalog first, then
   exploit-prediction score, then CVSS. Reachability can de-prioritize a finding on code that
   is never called.
6. **License.** Declared licenses are resolved to SPDX ids and expressions, classified into
   categories, and scored for risk.
7. **Evidence and report.** Results are sealed into the hash-chained evidence ledger and can be
   exported as a templated report or in a standard format.

## Finding vs vulnerability

A vulnerability is a raw match against an advisory. A finding is the tracked, de-duplicated
unit of work that a vulnerability at or above a threshold promotes to. Re-scans update findings
in place rather than creating duplicates.

## Severity vs risk priority

Severity is the label derived from the CVSS base score. Risk priority is the ordering Synapse
actually uses for triage, and it is not raw CVSS. It starts from the known-exploited catalog,
then the exploit-prediction score, then CVSS. A widely exploited medium can outrank a
theoretical critical.

## Standards

Synapse speaks the formats a client expects: CycloneDX and SPDX with PURL, SARIF for findings,
OpenVEX and CSAF for exploitability statements, and KEV plus EPSS for prioritization.

Next: [Installation](installation.md)
