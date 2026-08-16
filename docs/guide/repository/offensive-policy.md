> Canonical source: [`docs/redteam/offensive-policy.md`](https://github.com/KKloudTarus/synapse-ce/blob/main/docs/redteam/offensive-policy.md). Do not edit this published mirror directly.

# Offensive governance policy

This document is the authority for what Synapse is permitted to execute against a customer estate. It exists before any exploitation engine (issue #418, epic #405, Phase 4) because the question an engineer faces on the first day of implementation is not *can we build this technique* but **is this technique allowed to run here, and who decided**.

The differentiator this platform claims is not proof of exploitation — Horizon3 and Pentera already ship that. It is **proof under a defensible chain of custody**. A chain of custody that exists only as convention is not one, so this policy is an artifact that code enforces and CI verifies.

## Status

| Field | Value |
|---|---|
| Policy adoption (governance) | **Reviewed and adopted 2026-08-10** by `nghiadaulau` (repository maintainer, accountable owner) |
| External legal counsel review | **Pending** — no counsel assigned; production clearance is gated on this |
| Review owner | `nghiadaulau` |
| Enforcement | `internal/domain/offensivepolicy` (register) + `internal/usecase/offensivepolicy` (enforcement, kill switch) |

**These are two levels of authority and they are not interchangeable.** Adoption means the accountable owner has reviewed this policy and put it in force — a real, dated review event, recorded rather than asserted. It is *not* an external legal opinion.

**Production clearance is gated on counsel review, not on adoption.** No technique in this register is marked production-safe while the external legal counsel review is *Pending*; `ProductionSafe` is refused for every entry until counsel records a date, and a maintainer adopting the policy cannot lift that gate. The refusal is enforced by test, not by convention — see `TestRegisterRefusesProductionSafeBeforeCounselReview`. This is deliberate: the owner can put the governance rules in force, but only counsel can clear a technique to run against a customer's production estate.

## 1. Scope and authority

This policy governs every action the platform executes **against a target**, whether issued by an agent, a work order, the orchestrator, or an operator. It does not govern read-only analysis of artifacts the customer supplied (SBOMs, source snapshots, images), which is covered by the ordinary engagement scope.

Three controls already exist and are **not replaced** by this policy: engagement scope, the authorization window, and human approval. This policy answers the question those three do not: *of the actions inside scope and inside the window, which are permitted at all, and under whose signature.*

## 2. Prohibited categories

These are refused by the enforcement path regardless of scope, window, approval, or operator seniority. A technique in a prohibited category cannot be made executable by configuration.

1. **Denial of service.** Any action whose expected effect is degraded availability, including resource exhaustion, connection flooding, and lock or queue saturation. Load generation for capacity assessment is not covered by this platform.
2. **Destructive actions.** Deletion, truncation, encryption, or corruption of customer data or configuration; disabling security controls; modifying audit or logging pipelines.
3. **Exfiltration beyond a bounded proof sample.** Retrieving customer data at volume. A proof sample is bounded and redacted — see §6.
4. **Unauthorised persistence.** Anything that survives on a customer host beyond the action, without a declared and tested cleanup path: implants, scheduled tasks, service installation, credential material left on disk, modified startup paths.
5. **Lateral movement into out-of-scope estate.** Using in-scope access to reach an asset outside the engagement's declared scope, including pivoting through trusted network paths.
6. **Third-party impact.** Actions against shared infrastructure the customer does not own, including SaaS tenants, upstream providers, and CDN or DNS infrastructure not named in scope.

## 3. Risk classification

Risk is classified on two independent axes, then reduced to a class. Both axes are stated per technique in the register.

**Probability of service disruption**

| Level | Meaning |
|---|---|
| none | The technique cannot affect availability of the target service |
| low | Disruption requires an unusual target defect or configuration |
| high | Disruption is a plausible outcome of normal execution |

**Reversibility**

| Level | Meaning |
|---|---|
| reversible | No target state changes, or changes are undone by a declared cleanup path that is tested |
| irreversible | Target state changes that cannot be reliably undone by the platform |

**Resulting class**

| Class | Definition |
|---|---|
| `low` | Disruption `none` **and** `reversible` |
| `medium` | Disruption `low` **and** `reversible` |
| `high` | Disruption `high`, **or** `irreversible` |
| `prohibited` | Falls into any §2 category |

The reduction is deliberately pessimistic: a single high axis produces a high class. A technique that cannot state both axes is not classifiable and is therefore refused, which is the same outcome as having no register entry.

## 4. Approval matrix

| Risk class | Approval mode | Meaning |
|---|---|---|
| `low` | `automatic` | Executes inside scope and window with no per-action human decision. Still audited and still sealed as evidence. |
| `medium` | `single` | One human with `PermOperate` records an approval for this technique, target, and window. |
| `high` | `dual` | Two distinct humans record approvals. The second may not be the same identity as the first, and neither may be a machine principal. |
| `prohibited` | — | No approval mode exists. Refused. |

**Approval is recorded as evidence, not as configuration.** The approving human, the technique, the target, the authorization window and the timestamp are sealed into the hash-chained evidence for the action before it executes. A stored configuration flag that says "approved" is not an approval; if the seal fails, the action is not permitted.

Machine principals (`agent:`, `llm:`, `mcp:`, `system:`, `machine:`, `bot:`, `service:`) can never satisfy an approval requirement. AI may propose an offensive plan; it may not approve one.

## 5. Rules of engagement fields

An engagement must carry all of the following before any offensive action is permitted. **A missing field is a refusal, not a default.**

| Field | Why |
|---|---|
| Authorized scope | The targets in scope, already enforced by the execution guard |
| Authorization window | Start and end; an action outside it is refused |
| Named authorizing customer contact | The human on the customer side who authorized the assessment |
| Emergency contact | Reachable during the window, for the case where the platform must be halted |
| Permitted risk ceiling | The highest risk class this engagement permits, which may be lower than the register allows |
| Excluded assets | Assets explicitly out of bounds even though they fall inside the scope expression |

The risk ceiling is a **narrowing** control: it can only reduce what the register permits, never widen it. An engagement cannot authorize a prohibited technique.

## 6. Data handling

- A **proof sample** is the minimum evidence that demonstrates impact. It is bounded to **4 KiB per finding** and redacted before it is stored: credential material, personal data, and authentication tokens are removed at capture, not at report time.
- Proof samples inherit the engagement's evidence retention. They are hash-chained like all other evidence and are never mutable.
- Retrieved data that is not a proof sample is not retained. There is no debug path that stores more.
- Secrets obtained during exploitation are recorded as **existence and location**, never as value.

## 7. Blast radius and cleanup

Every technique declares a blast radius:

| Radius | Meaning | Cleanup |
|---|---|---|
| `read_only` | Observes; no target state changes | Not applicable |
| `state_changing` | Changes target state | **Required**: a declared, ordered cleanup path with a verification step |

**A `state_changing` technique with no cleanup path fails CI, not runtime.** `TestRegisterRejectsStateChangingWithoutCleanup` walks the whole register and fails the build if any entry declares `state_changing` without a cleanup specification containing at least one step and a verification. This is deliberately a build-time gate: discovering an unreversible action at runtime means it has already run.

## 8. Kill switch contract

A single operator action halts all in-flight offensive work across the fleet.

- **Interface**: `POST /api/v1/redteam/halt` with `PermAdminister`, carrying a reason.
- **Effect**: every offensive work order for the tenant in `issued`, `claimed`, or `running` is transitioned to `cancelled`.
- **Audit**: the halt is audited with the operator identity and the reason before it is reported as complete. A halt that cannot be audited is still executed — stopping work matters more than recording it — but the response reports the audit failure rather than claiming a clean halt.
- **Bound**: **the control plane stops issuing and cancels every in-flight order within 5 seconds** of the request, measured under concurrent load by `TestHaltCancelsInFlightWithinBound`.

**What the bound does and does not cover, stated precisely because the difference matters during an incident.** The 5-second bound is the *control plane's* halt: after it, no further offensive work order can be claimed and every in-flight order is marked cancelled. An agent already executing a technique on a host learns of the cancellation on its next poll, so the estate-wide stop is bounded by the control-plane halt **plus one agent poll interval** (`SYNAPSE_FLEET_POLL`, default 60s). Any statement that the estate stops within 5 seconds would be false. The documented state after a halt is therefore: *no new offensive work is issued or claimable; in-flight orders are cancelled at the control plane; techniques already running on a host complete or abort within one poll interval, and their cleanup paths still run.*

## 9. Dry run

Dry run is part of this policy, not a debug flag. For any offensive plan the platform enumerates exactly what it would execute against what — technique, target, risk class, approval requirement, blast radius, cleanup path — and executes nothing.

`TestPlanExecutesNothing` asserts zero executions by injecting an executor that fails the test if it is called at all. Dry run is the default for a plan that has not yet been approved.

## 10. Technique register

This table is the **source of truth**. `internal/domain/offensivepolicy/policy.yaml` mirrors it, and `TestRegisterMatchesPolicyDocument` fails the build if the two diverge in either direction — an entry in one and not the other, or any field differing. Neither file may be edited alone.

A technique absent from this table is **refused**. That is the fail-closed default and the reason the table is deliberately short: entries are added when a technique is implemented and classified, not in advance.

| Technique | Taxonomy | Disruption | Reversibility | Risk | Approval | Radius | Cleanup | Production safe |
|---|---|---|---|---|---|---|---|---|
| `recon.service_banner` | T1595.002 | none | reversible | low | automatic | read_only | — | no |
| `recon.tls_inspect` | T1596 | none | reversible | low | automatic | read_only | — | no |
| `exploit.default_credentials` | T1078.001 | low | reversible | medium | single | read_only | — | no |
| `exploit.known_cve_readonly` | T1190 | low | reversible | medium | single | read_only | — | no |
| `exploit.web_shell_upload` | T1505.003 | low | irreversible | high | dual | state_changing | delete uploaded artifact; verify absence | no |
| `persist.scheduled_task` | T1053 | low | irreversible | prohibited | — | state_changing | — | no |
| `impact.service_stop` | T1489 | high | irreversible | prohibited | — | state_changing | — | no |
| `exfil.bulk_data` | T1041 | none | reversible | prohibited | — | read_only | — | no |
| `emu.process_discovery` | T1057 | none | reversible | low | automatic | read_only | — | no |
| `emu.system_network_config_discovery` | T1016 | none | reversible | low | automatic | read_only | — | no |
| `emu.dns_beacon_benign` | T1071.004 | none | reversible | low | automatic | read_only | — | no |
| `emu.credential_file_read` | T1552.001 | none | reversible | low | automatic | read_only | — | no |
| `emu.service_restart_probe` | T1569.002 | high | reversible | high | dual | state_changing | restart the service to its prior running state; confirm the service is running and healthy | no |

The `emu.*` entries are the governance facet of the adversary-emulation techniques (#421); each also appears in the emulation catalogue with its taxonomy and the detection it should produce. Emulation runs through this same allowlist, so an emulation technique absent here is refused like any other. The four benign discovery techniques are read-only and automatic; `emu.service_restart_probe` is lab-only — disruptive and therefore high-risk with dual approval, reversible via its cleanup, and never production-safe.

The three prohibited entries are listed **on purpose**. Omitting them would make them merely unknown, and the enforcement path would refuse them with "no register entry" — indistinguishable from a technique nobody has classified yet. Naming them records that they were considered and excluded, which is what a governance artifact is for.

## 11. Change control

- The register and this document change together in one commit. CI enforces it.
- Adding a technique requires its two risk axes, its blast radius, and a cleanup path when state-changing.
- Raising a technique's risk class needs no review. Lowering one requires the legal review owner named in §Status.
- Marking any technique `ProductionSafe` requires a recorded legal review date.
