# Playground demos

This playground exercise uses the existing console forms and components. The entry screen arranges seven foundation and setup chapters into a recommended learning journey: Platform Overview → Code Quality → Code Security → Repository & CI/CD Setup → AI Setup & Readiness → AI Review → Runtime Security. A numbered node-based journey groups the chapters into Explore, Assess, Connect and Operate, with distinct difficulty colors and three optional specialist branches. It shows completed chapters and the recommended next chapter. Each chapter retains independent progress, and users may open any chapter directly. Platform Overview retains the original populated fixtures and the original 20-step tour content. Finish marks the chapter complete and returns to the journey; ending the tour early does not mark completion. Code Security Walkthrough starts with an empty assessment workspace and walks through 26 workflow stages, split into individual fields and actions using a compact spotlight prompt. Each example value is filled automatically and highlighted when its explanation appears. Select Next to open forms, save data and start simulated jobs; no typing or manual selection is required.

## Run locally

From `web/`, with dependencies installed:

```sh
VITE_PLAYGROUND=1 pnpm dev --host 127.0.0.1 --port 5173
```

Open `http://127.0.0.1:5173/demo` and choose one of the ten chapters. Remove `VITE_API_PROXY_TARGET` before starting; the playground refuses to run with a real API proxy.

## Exercise

1. Create Checkout API as an Asset and link an Initial assessment.
2. Activate it, save a current authorization window, and allow SCA.
3. Scan the reserved demo repository on `main` with Git + Full.
4. Follow ten core phases in the existing Pipeline Journey Track. Review twelve packages across npm, PyPI and Go; eight advisories, four SAST issues, two secret findings, two IaC findings and two license reviews. Review permissive and copyleft licenses plus missing metadata and downloadable evidence. Confirm, assign and comment on a Finding.
5. Finalize the Initial Snapshot and complete the assessment.
6. Create a Re-test with copied scope and authorize it separately. Four scan actions open settings, review the prefilled Git + Full configuration on `remediated`, start the scan and verify completed coverage. The same core pipeline runs without repeating the Initial scan's ten explanations.
7. Finalize its Snapshot and compare: eighteen Fixed; zero New, Still detected or Not evaluated. The guide waits for both the summary and finding results to load. Reopening comparison restores its saved ID, Snapshot pair and All findings scope. Complete the Re-test, close the Cycle and download the JSON report.
8. Configure the demo OSV source, test it, save it and synchronize. The first run imports no new advisory.
9. Continue with Next to enable in-app delivery, publish the demo advisory, then synchronize again. One advisory matches retained `checkout-token@2.0.0` inventory and delivers one Inbox message. Open it and select the affected component to inspect the fix in `2.0.1`.

Code Security keeps its existing browser-local document. The three additional walkthroughs retain separate datasets and checkpoints in a second document. Pause preserves saved data. Reload reconstructs the current form and its previously filled values; completed API checkpoints recover directly to their result review. There is no Skip control. Each stage must be completed before Finish is available.

Progress and completion are stored in localStorage and shared across tabs on the same browser profile and origin. The selected chapter is stored in sessionStorage for each tab. Stores re-read the saved dataset before each update and observe storage events, so a stale tab does not overwrite another chapter's progress. Different browsers, profiles, origins and machines have independent progress; there is no account synchronization.

**Learning journey** returns to the entry screen. Switching modes reloads the app to isolate query data. Walkthrough Reset clears only the selected exercise; Platform Overview Reset clears only the original tour progress. Theme preferences are preserved. The original tour content and step definitions are retained.

## Focused walkthroughs

| Demo | Guided outcome |
| --- | --- |
| Runtime Security Walkthrough | 27 steps: enrolment token → simulated check-in → host/workload inventory → sensor coverage → five synthetic detections → five correlated incidents → investigate the High file-access case → analyst ownership and disposition → dry-run response → simulated apply and verification → audited reversal → resolution. |
| AI Review Walkthrough | 19 steps: five synthetic proposals across five languages and severity levels → human claim and mandatory rationale → accept a test fixture exemption → reject a production exemption → confirm and assign the retained finding → remediation note → derived outcome metrics. |
| Code Quality Walkthrough | 24 steps: create a Git Project with Synapse Way → baseline with ten issues and three hotspots → failed gate evidence → acknowledge maintainability debt → review a checksum hotspot as Safe → load an improved revision → second analysis → compare Failed/Passed gates, coverage 64%/86% and duplication 5%/1%. |

Completed walkthroughs offer Next chapter in journey order and Explore results. Runtime returns to the journey after the final chapter. Continue journey resumes the first incomplete chapter; completed chapters remain available for review.

Code Quality Explore results includes a source viewer with 28 retained training excerpts, findings anchored to the selected analysis, a dependency explorer with 12 packages and CycloneDX full/subtree downloads, and directory/file measures. Project navigation preserves the selected branch in the playground. Baseline issues and hotspot review coverage remain visible after the improved analysis completes. Improved quality does not upgrade dependencies: that operation belongs to Code Security. Source excerpts are synthetic and redact recorded unsafe expressions. Unified diff compares the retained excerpts; split diff, complexity, coupling and Git-history measures are not retained. Coverage, duplication, issue facets and measures totals agree with the selected analysis.

Every walkthrough uses the existing console screens, forms and API adapters. Next performs the highlighted action. Filled values receive a spotlight and a separate explanation of their purpose. The guide waits for loaded outcomes, including both comparison sides. It reconstructs unsaved modal fields, review expansion, finding details and transient dry-run plans after reload. Back revisits completed steps without repeating saved mutations. Start over clears only the selected walkthrough.

Code Security and Code Quality record TypeScript, Go, Python, Java and JavaScript. Their issue severity spans Critical, High, Medium, Low and Info. AI Review covers the same five languages and levels, with two guided decisions and three pending cases. Runtime records four telemetry classes, 96 samples, six packages, three workloads and five severity levels. List counts, facets, outcome metrics and comparison evidence derive from these records.

Runtime response and AI provider activity remain simulated; enrolment tokens cannot register a real agent. Intelligence cadence is explained in Code Security, while monitoring is advanced with manual synchronization. Additional console areas retain overview fixtures and are outside these focused scenarios.

## Boundaries and validation

The repository, packages, advisory feed, jobs, hashes and policy checks are simulated. No repository is cloned, no scanner executes, and no provider is contacted. Source cadence is explained but is not scheduled in this browser exercise; manual sync advances the monitor example. The closure download is JSON, not a generated PDF. New Intelligence exposure does not rewrite finalized Snapshots or the historical report.

The exercise handlers load only in a `VITE_PLAYGROUND=1` build. A normal production build excludes the walkthrough, scenario data and service worker.

```sh
pnpm typecheck
pnpm test src/playground/ScanWalkthrough.test.tsx src/playground/scenario/scenario.test.ts src/playground/workflows/workflows.test.ts
pnpm build
pnpm playground:build
```

The core simulation takes 18 seconds, with timestamped phase events and partial engine coverage until finalization. During the Initial scan, each phase has its own Next step and explanation. Package review automatically scrolls to the inventory, then focuses package identity, installed version, PURL and the retained monitoring package. Static code quality remains optional and outside this security assessment example.

## Advanced chapter plan

Status: the first delivery wave is implemented for local testing. The five foundation chapters remain intact. A separate Advanced chapters collection contains Remediation & Ownership (26 steps), Intelligence Operations (18 steps), and Quality Policies & CI (21 steps), with recommended preparation and direct access. Each chapter owns independent progress and synthetic data under `synapse.playground.advanced.v1`; its reset does not change the foundation datasets. The remaining waves below are planned and have no placeholder launch cards.

Remediation retains the 18-finding baseline, a mixed comparison (10 Fixed / 4 Still detected / 3 New / 4 Not evaluated), and a separate coverage-verification assessment (14 Fixed / 4 Still detected / 3 New / 0 Not evaluated). Missing configuration/license lanes block closure. A versioned server-policy preview then records an explicit seven-day exception for seven retained detections without relabeling them Fixed. Ownership assignment, transfer, eligible-user selection, due dates and audit history use the native screens.

Intelligence starts with two stale OSV-compatible synthetic feeds, retains a failed incremental run, recovers each feed independently, and performs full reconciliation of four advisories across npm, PyPI, Go and Maven. Exposure details, assessment history, in-app preference, delivery and acknowledgement remain separate checkpoints. Outbound notification-channel delivery attempts and redrive are reserved for Integrations & Delivery; this chapter demonstrates the in-app outcome only.

Quality copies and assigns a TypeScript profile, raises a reviewed rule to High, creates a release gate (zero new Critical issues / coverage ≥85% / duplication ≤3%), enables PR decoration and automatically supplies a synthetic LCOV artifact. A recorded PR #42 CI analysis changes coverage from 64% to 86%, duplication from 5% to 1% and new issues from 10 to zero. The original baseline retains Synapse Way; the revised result records Checkout Release and CI provenance. Issue/hotspot decision mechanics are taught in the prerequisite foundation chapter. Extended complexity/coupling and Git-history policy cases remain planned.

### Delivery sequence

| Wave | Chapter | Prerequisite | Guided case and acceptance outcome |
| --- | --- | --- | --- |
| 1 | Remediation & Ownership | Code Security | Route a finding through Ownership Inbox, assign a team, transfer ownership and inspect SLA/history. Compare a mixed Re-test with Fixed, New, Still detected and Not evaluated. Explain coverage before evaluating closure blockers and a recorded waiver. Finish with a traceable owner and evidence-backed closure decision. |
| 1 | Intelligence Operations | Code Security | Review two configured feeds, contrast incremental/full sync, inspect freshness and stale/failed runs, recover each feed, reconcile four advisories against retained inventory and track exposure history. Review in-app preferences, delivery and acknowledgement. Finish with an explained exposure and a verified monitor outcome. |
| 1 | Quality Policies & CI | Code Quality | Copy and assign a language profile, override severity, create and assign three release conditions, enable PR decoration and attach synthetic coverage automatically. Compare the baseline and PR analysis with retained policy and CI provenance. Finish by explaining why the revised build passes. |
| 2 | Asset & Dependency Intelligence | Code Security | Review asset lifecycle, memberships and history; contrast Git, local/archive, image and imported-SBOM inputs. Inspect dependency paths, direct/transitive relationships, reachability, KEV/EPSS context, license provenance and SBOM completeness. Finish with a justified remediation order and exported inventory. |
| 2 | AI Decision Operations | AI Review | Review agreement, disagreement and insufficient-evidence cases with claim/version checks and required rationale. Inspect Judgment review, agent proposals, threat-model/write-up drafts and verification where those surfaces are available. Assign a retained finding and inspect a recorded remediation outcome. Human review remains the decision boundary. |
| 2 | Fleet & Detection Operations | Runtime Security | Inspect rollout state and capability policy, token expiry/revocation, host package exposure and process/workload baselines. Diagnose a sensor gap, review detection provenance and asset relationships, then inspect recorded re-baseline/retrohunt results and a scoped response with reversal evidence. Finish with a coverage-aware incident decision. |
| 3 | Reporting & Evidence | Code Security or Runtime Security | Inspect finalized snapshots, report/compliance views and supported exports. Diagnose missing evidence, review audit history and retention/legal-hold rules, and inspect simulated export/erasure/privacy outcomes. Implement only formats and lifecycle actions supported by the product; do not present the current JSON closure download as PDF generation. |
| 3 | Integrations & Delivery | Intelligence Operations | Configure synthetic SCM/CI, webhook and SIEM connections; review subscriptions/templates, failed delivery, retry and redrive. Finish with matching event, attempt and receipt records. Keep unavailable Ticketing/Documentation integrations marked unavailable. |
| 3 | Administration & Governance | Remediation & Ownership | Review teams, roles and access decisions, tenant configuration, relationships, regional settings and feature availability. Demonstrate allowed/denied cases and their audit records with synthetic users. Finish with an explained least-privilege configuration. |
| Specialist | Cloud Posture | Asset & Dependency Intelligence | Review a recorded CSPM inventory, posture findings and remediation evidence for a synthetic account. No cloud credentials or live resource changes. Enable only after its feature flag and native surfaces are confirmed. |
| Specialist | Detection Validation Lab | Fleet & Detection Operations | Inspect recorded Recon/DAST, Purple Team and rehearsal results, their authorized scope and detection coverage. All activity is simulated, with no target scanning or offensive execution. Finish with an evidence-backed coverage comparison. |
| Specialist | Automation Interfaces | Integrations & Delivery | Walk through supported CLI/API/MCP request shapes and inspect canned responses, scope, permission failures, async status and audit evidence. Commands are examples against a local mock; do not execute against external systems. |

Wave 1 is ready for local acceptance. Continue with Wave 2 in the listed order after reviewing these outcomes. Future chapters should target one concrete case in roughly 12–18 guided steps; split a chapter when it introduces a second independent operational outcome. Chapter length is a planning target, not a reason to omit an important explanation.

### Implementation and verification contract

Before implementing a chapter, map its case to actual routes, controls, API contracts and feature flags. Distinguish existing product capabilities from overview-only fixtures and unavailable integrations. Prototype the full case with reviewable synthetic fixtures before adding its guide; do not expose empty chapter cards as completed functionality.

Every case should include representative positive, negative and incomplete-evidence states. Use TypeScript, Go, Python, Java and JavaScript wherever code context applies; use all severity levels where the underlying model supports them. Counts, lists, facets, trends and reports must derive from the same records. Runtime and cloud cases should vary telemetry/resource classes rather than attach artificial code-language fields. Informational observations must not be presented as exploitable vulnerabilities.

Acceptance requires: complete Next-only navigation; meaningful spotlight and scrolling; resume after pause/reload at every transient state; independent reset; cross-tab persistence checks; immutable baseline comparisons; successful Explore results links; honest unavailable states; simulated failures and recovery; and a final outcome that waits for loaded evidence. Verify both normal and playground builds to keep training handlers and data outside production. Save local browser proof for the chapter's decisive outcome.


## Setup chapters and demo contracts

- **AI Setup & Readiness (10 steps):** distinguish AI Agent, AI Triage and Fleet Agent; review deployment prerequisites; inspect blocked/ready states; save and inspect a synthetic retained-evidence review. The setup preview is explanatory, not a production settings form. The demo accepts only the supplied read-only review goal and calls no provider or external tool.
- **Repository & CI/CD Setup (34 steps):** source connector metadata → Jenkins connection and write-only demo credential → test → discover → bind → enable → poll → matched/missing/ambiguous cases → GitHub inbound binding → deployment handoff → synthetic PR delivery and gate outcome. Continue to Quality Policies & CI for policy customization. Polling reads existing builds; it does not trigger a pipeline.
- Setup state is browser-local under `synapse.playground.setup.v1`. Credentials are discarded; only configuration metadata is retained. Progress lives beside the other advanced chapter checkpoints. Restarting one setup chapter preserves the other chapter and the foundation datasets.
- The browser handler order is setup → advanced → workflow → scan scenario → overview. Tests exercise this complete order. Unknown mutations return an explicit unsupported response rather than a false success.
- Native PDF/HTML/DOCX downloads provide a labeled compact synthetic summary from the selected assessment findings. The playground report dialog explains that production sections, exhibits and sealing are not reproduced. Empty export responses raise an error instead of downloading an empty file. Assessment-cycle JSON exports retain their separate comparison and closure records.
- Guide placement prefers the centered Overview layout and moves aside when needed to avoid the current target. A shared purple spotlight respects nested scroll containers and modal boundaries. Entering a step scrolls to the beginning of its target; navigation anchors also reveal the page heading. Expanding a minimized guide returns to its current target without continuously overriding manual scrolling. The minimize control keeps navigation available on compact screens. AI review evidence is expanded before decisions.

### Local QA, October 9, 2026

Both setup chapters were completed through their visible Next/Finish controls. Repository setup was repeated from Start over after repairing form restoration following Bind. Reload during the Jenkins form recovered the supplied values. Mobile and desktop screenshots cover setup, guide placement, CI correlation and reporting; light and dark setup presentation were inspected. PDF bytes, cross-reference offsets, HTML escaping and DOCX package contents are tested, and a generated PDF was rendered for visual inspection. The in-app browser's download observer timed out, so its filesystem download handoff remains unverified; this is separate from the populated export payload tests.
