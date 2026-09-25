# Screen walkthrough

[Documentation home](README.md)

Every screen in the dashboard, as it renders, with what it is for and what to press.
Seventy-five screens including the detail pages and their sub-tabs, each captured at desktop
(1440px) and phone (390px) width.

## How these were captured

Against a real `synapse-api` on a real PostgreSQL, driven through a browser so every request
hit the live backend; the mock service worker was off. Every feature flag was on. The data is
real, produced by running the product rather than seeded into its tables:

- an engagement scanned against a clone of OWASP Juice Shop, 2,776 findings;
- a code-quality project with an analysis pushed by `synapse-cli`, 2,762 issues, managed gate
  failed, 154 findings at or above high;
- an AI agent session against OpenAI that spent 10,982 tokens and called the `list_findings`
  tool, with a distinct verifier model, because the Judgment primitive refuses to let a
  proposer verify its own claim;
- a `kind` Kubernetes cluster reporting through `synapse-cluster-agent`: 2 enrolled agents,
  5 namespaces, 64 assets, 6 workloads with their image digests, 66 coverage rows;
- a host reporting through `synapse-agent`, plus three EDR sensors whose sealed detections
  correlate into incidents;
- six business assets and eight users.

Two screens are empty for a reason worth stating rather than staging. Coverage Windows materialises
from sensor-state observations, and the eBPF sensors cannot load in this container, so the agent
reports "no runtime evidence collected" and there is nothing to window. The AI triage review queue
holds findings the proposer suspects are false positives; the triaged scan returned ten verdicts of
"sound" and none suspected, so there is nothing awaiting a human decision.

Every screen was captured again once all nineteen capabilities were switched on, because the first
pass documented a product with seven of them off. Three capture faults were fixed first, each of
which had put something untrue in this guide:

- The screenshots held one viewport, not the screen. The app scrolls inside a container rather than
  the document, so asking for a full-page capture changed nothing and every image stopped at the
  fold. The sweep now measures the page-level scroller and grows the viewport to it, which is why
  the longer screens here run to several thousand pixels.
- Risk Stories was published as a spinner. `networkidle` is not "the screen has rendered": a tab
  that starts its own fetch after hydration is still loading when the network goes quiet. The sweep
  waits for the main region to stop saying it is loading, and reports a screen that never stops
  rather than photographing it.
- Four screens were captured while the API was restarting and show the signed-out state. The
  heading check caught them and they were retaken.

The Code screen changed for a different reason: `synapse-cli publish-source` could not publish
anything until it was repaired, so it read "Source preview unavailable: Not retained" beside a
caption promising annotated source.

Regenerate them with the dev server running and a token the backend accepts:

```bash
cd web
VITE_API_PROXY_TARGET=http://localhost:8080 pnpm dev   # in one shell
UI_AUDIT_TOKEN=<api token> pnpm ui:audit               # in another
```

`pnpm ui:audit` also reports what a screenshot cannot show: a rendered error, horizontal
overflow at phone width, a missing page heading, a button with no accessible name, and any
failed API call. Pass `UI_ROUTES` to sweep detail screens and sub-tabs.

## What the sweep measured

`pnpm ui:audit` also records every `/api/v1` request the app makes while it drives the screens, so
API coverage can be read from what the product actually calls rather than from a static scan of the
client. Loading all 75 screens exercised **96 of the 371 registered routes**.

The other 275 are not unreachable; they need something a page load does not do:

- **176 are mutations** (`POST`, `PUT`, `PATCH`, `DELETE`). A read-only sweep never presses a button.
- **99 are GETs that open on a selection**: `/agent/sessions/{sid}`, `/recon/runs/{rid}`,
  `/evidence/{sha}`, `/findings/{fid}/comments`, the report and export downloads. You reach them by
  clicking a row, not by loading a screen.

So this number bounds coverage from below, and does not answer "is anything unreachable" on its own.
That question was answered separately by auditing every method in `web/src/lib/api` against its
consumers: 328 methods, of which 10 have no caller. None is an unmapped capability. Two are
superseded (`reopenAssessmentCycle` lost to the preview-and-commit flow, `listNotificationDeliveries`
to its paged replacement) and eight are single-record GETs whose list already carries the row.

Where that audit found a real gap, the gap was closed rather than recorded: user administration,
the assessment-cycle archive, snapshot finalize, issue review history, and the SLA decision record
all reached the API and no screen before this pass.

## Start

### Security Operations

`/dashboard`

The landing screen: what needs a person today, ranked, with the next action named.

1. Read the strip: **Critical open**, **High open**, **High-risk assets**, **Active engagements**, **Coverage gaps**, **Needs attention**.
2. Change the window with `7d` / `30d` / `90d`.
3. Filter the queue with `All`, `P1`, `Scan failed`, `Coverage gaps`, `Asset posture`, `Not scanned`.
4. Work the table: **Prio**, **Type**, **Asset / engagement**, **Issue**, **Owner**, **Age**, **Due**, **Next action** (the link you follow).
5. `Excluded findings` explains what the counts leave out, so a low number is not read as a clean result.

=== "Desktop"

    ![dashboard at desktop width](assets/ui/desktop_dashboard.webp)

=== "Phone"

    ![dashboard at phone width](assets/ui/phone_dashboard.webp)

## Security operations

### Engagements

`/engagements`

Every time-boxed assessment with its scope, status and finding counts.

1. Read **Total**, **Active**, **Completed**, **Unassigned**.
2. Narrow with the search box and the `All Status` / `All Scope` selects.
3. The **Findings** column breaks down by **crit**, **high**, **med**, **low**, and **unrated** when a finding carries no severity yet.
4. Click a name to open the engagement; the copy icon copies its id.
5. `Import bundle` takes a CI bundle; `New Engagement` starts one.

=== "Desktop"

    ![engagements at desktop width](assets/ui/desktop_engagements.webp)

=== "Phone"

    ![engagements at phone width](assets/ui/phone_engagements.webp)

### New Engagement

`/engagements/new`

Creates the scope and the authorization window. Both are enforced server-side before any tool runs.

1. Name the engagement.
2. Pick the owner or leave it `Unassigned`.
3. Choose the target kind and enter the target.
4. `Add target` for each further target in scope.
5. `Create Engagement`.

=== "Desktop"

    ![engagements_new at desktop width](assets/ui/desktop_engagements_new.webp)

=== "Phone"

    ![engagements_new at phone width](assets/ui/phone_engagements_new.webp)

### Assessment cycles

`/assessment-cycles`

The long-lived cycle grouping an initial assessment and its re-tests.

1. Open a cycle for its frozen root-to-final path and closure history.
2. `Review closure` fetches a server-signed preview; a commit without one is refused.
3. `Review reopen` reverses it and keeps the sealed manifest immutable.
4. `Archive Cycle` ends it permanently; the dialog says so, because the domain allows no transition out of archived.

=== "Desktop"

    ![assessment-cycles at desktop width](assets/ui/desktop_assessment-cycles.webp)

=== "Phone"

    ![assessment-cycles at phone width](assets/ui/phone_assessment-cycles.webp)

### AI Triage Reviews

`/ai-triage/reviews`

The human review queue for AI-proposed triage. A proposer never confirms its own claim.

1. Filter with `All severities`, `All projects`, `All states`.
2. Open a review to read the proposal and its evidence.
3. Claim it, then decide. The decision is recorded against your identity.

=== "Desktop"

    ![ai-triage_reviews at desktop width](assets/ui/desktop_ai-triage_reviews.webp)

=== "Phone"

    ![ai-triage_reviews at phone width](assets/ui/phone_ai-triage_reviews.webp)

### Automation Observability

`/ai-triage/observability`

What the automation did and how well it held up, so the triage pipeline can be audited.

1. Read the counters.
2. `Refresh` re-pulls them.

=== "Desktop"

    ![ai-triage_observability at desktop width](assets/ui/desktop_ai-triage_observability.webp)

=== "Phone"

    ![ai-triage_observability at phone width](assets/ui/phone_ai-triage_observability.webp)

### Ownership inbox

`/ownership`

Findings routed to your teams, so each has a named owner.

1. Filter to your teams or to a severity.
2. Select findings and reassign in bulk.
3. Open one for its ownership history and who changed it.

=== "Desktop"

    ![ownership at desktop width](assets/ui/desktop_ownership.webp)

=== "Phone"

    ![ownership at phone width](assets/ui/phone_ownership.webp)

## Exposure management

### Security Asset Inventory

`/assets`

The business-asset estate: what exists, how critical, who owns it, and whether its posture is known.

1. **Total assets** and **Critical** are estate-wide; **Active on this page** and **Needs attention on this page** say their scope in the label.
2. Narrow with the search box and the type / criticality / lifecycle selects.
3. A posture of **Unknown** means not assessed, never clean.
4. Page with `Previous` / `Next`; the filter and the page are applied in the database.
5. `New Asset` adds one; the open arrow on a row opens the asset.

=== "Desktop"

    ![assets at desktop width](assets/ui/desktop_assets.webp)

=== "Phone"

    ![assets at phone width](assets/ui/phone_assets.webp)

### Vulnerability Intelligence

`/vulnerability-intelligence`

Advisory ingest, the vulnerabilities it produced, and the machinery that keeps both current.

1. Move between `Overview`, `Vulnerabilities`, `Sources`, `Sync runs`, `Attack paths`, `Engine accuracy`.
2. `Sync all` pulls every enabled source; `Full sync all` re-pulls from the beginning.
3. `Full reconciliation` re-evaluates existing findings against the current advisory set.
4. **Engine accuracy** holds the owned engine's measured results, so a detection-quality claim can be checked.

=== "Desktop"

    ![vulnerability-intelligence at desktop width](assets/ui/desktop_vulnerability-intelligence.webp)

=== "Phone"

    ![vulnerability-intelligence at phone width](assets/ui/phone_vulnerability-intelligence.webp)

## Security engineering

### Code Quality

`/code-quality`

Long-lived project identities and their health, separate from time-boxed engagements.

1. Filter with `All health states`; order with `Recently analyzed`.
2. Open a project for its hotspots, issues, code, dependencies, measures, comparison, analysis and activity.
3. `New project` registers one.

=== "Desktop"

    ![code-quality at desktop width](assets/ui/desktop_code-quality.webp)

=== "Phone"

    ![code-quality at phone width](assets/ui/phone_code-quality.webp)

### Quality Gates

`/code-quality/gates`

The pass/fail conditions a project's analysis is judged against.

1. Filter by `All` / `Built-in` / `Custom`; order with `Name (A to Z)`.
2. Open a gate to read its conditions.
3. `New gate` creates a custom one; built-ins cannot be edited.

=== "Desktop"

    ![code-quality_gates at desktop width](assets/ui/desktop_code-quality_gates.webp)

=== "Phone"

    ![code-quality_gates at phone width](assets/ui/phone_code-quality_gates.webp)

### Quality Profiles

`/code-quality/profiles`

Which rules are active per language. Ninety built-in profiles ship, three per language.

1. Filter by `All` / `Built-in` / `Custom`.
2. Pick a language group, then a profile; each row shows its active rule count.
3. Copy a built-in to get a custom profile you can edit.

=== "Desktop"

    ![code-quality_profiles at desktop width](assets/ui/desktop_code-quality_profiles.webp)

=== "Phone"

    ![code-quality_profiles at phone width](assets/ui/phone_code-quality_profiles.webp)

### Rules

`/rules`

The detection catalogue: every rule the scanners can apply.

1. Read **Vulnerabilities**, **Security hotspots**, **Code smells & bugs**, **Supported stacks**.
2. Filter with `Language`, `Type`, `Severity`, `Tag`, `CWE`.
3. The copy action on a row copies the rule key for a profile or a suppression.

=== "Desktop"

    ![rules at desktop width](assets/ui/desktop_rules.webp)

=== "Phone"

    ![rules at phone width](assets/ui/phone_rules.webp)

## Runtime security

### Fleet coverage

`/fleet`

Which assets an agent covers, per capability, and how fresh that coverage is.

1. Filter agents by `All` / `Healthy` / `Stale` / `Revoked`.
2. A verdict of **unauthorized** is its own label and is never folded into covered.
3. The desired-capability gaps section lists capabilities an asset should have and does not; a failure there is shown, not rendered as no gaps.
4. `Export CSV` takes the current view out.

=== "Desktop"

    ![fleet at desktop width](assets/ui/desktop_fleet.webp)

=== "Phone"

    ![fleet at phone width](assets/ui/phone_fleet.webp)

### Agent administration

`/fleet/agents`

Enrolment, staged rollout of the agent binary, and the lifecycle of an agent and its keys.

1. Set **Lifetime (minutes)** and press `Mint token`. The token is shown once and is spent on first use.
2. Enter **Set target version** and **Canary groups**, then `Set target`.
3. Promote, pause or resume the rollout; a pause takes a reason.
4. List an agent's keys, revoke one key, or revoke the agent with a reason.

=== "Desktop"

    ![fleet_agents at desktop width](assets/ui/desktop_fleet_agents.webp)

=== "Phone"

    ![fleet_agents at phone width](assets/ui/phone_fleet_agents.webp)

### Hosts

`/fleet/hosts`

Host inventory from the agents, with per-host packages and CVEs.

1. Search and filter the host list.
2. Open a host for its packages and the CVEs matched against them.

=== "Desktop"

    ![fleet_hosts at desktop width](assets/ui/desktop_fleet_hosts.webp)

=== "Phone"

    ![fleet_hosts at phone width](assets/ui/phone_fleet_hosts.webp)

### Coverage windows

`/fleet/coverage-windows`

What an agent observed over a chosen span, used to retro-hunt collected telemetry.

1. Enter an **Asset id** and an **Agent id**.
2. Set the window.
3. `Apply` runs the hunt.

=== "Desktop"

    ![fleet_coverage-windows at desktop width](assets/ui/desktop_fleet_coverage-windows.webp)

=== "Phone"

    ![fleet_coverage-windows at phone width](assets/ui/phone_fleet_coverage-windows.webp)

### Kubernetes Workloads

`/fleet/workloads`

Cluster workloads the cluster agent reported, with their images and service accounts.

1. `About workloads` explains what the cluster agent collects and what it does not.
2. Read cluster, namespace, kind, name, service account and images.

=== "Desktop"

    ![fleet_workloads at desktop width](assets/ui/desktop_fleet_workloads.webp)

=== "Phone"

    ![fleet_workloads at phone width](assets/ui/phone_fleet_workloads.webp)

### Asset graph

`/fleet/asset-graph`

How technical assets relate. Every edge carries provenance, so inferred is never shown as observed.

1. `Observed vs inferred` explains the distinction the graph encodes.
2. Fill **From**, **Kind**, **To**, **Confidence**, **Provenance**.
3. `Add relationship` commits it; creation is idempotent on the natural key.

=== "Desktop"

    ![fleet_asset-graph at desktop width](assets/ui/desktop_fleet_asset-graph.webp)

=== "Phone"

    ![fleet_asset-graph at phone width](assets/ui/phone_fleet_asset-graph.webp)

### Incidents

`/fleet/incidents`

Runtime incidents raised from agent telemetry, tracked through their lifecycle.

1. Read **Open**, **Critical unresolved**, **In progress**, **Resolved**.
2. Filter by state: new, open, triaged, investigating, contained, remediated, resolved, closed, reopened.
3. Open an incident for its timeline and the response actions taken.

=== "Desktop"

    ![fleet_incidents at desktop width](assets/ui/desktop_fleet_incidents.webp)

=== "Phone"

    ![fleet_incidents at phone width](assets/ui/phone_fleet_incidents.webp)

### Response operations

`/blueteam/response`

Defensive actions against a live target. Every action is planned as a dry run first.

1. Pick the **Engagement**.
2. Pick the **Action** and name the **Target**.
3. `Plan (dry run)` first; the plan is what you review before anything executes.
4. Follow the record list with `all` / `pending` / `applied` / `reverted` / `failed`.
5. `Halt offensive work` stops the engagement's offensive activity.

=== "Desktop"

    ![blueteam_response at desktop width](assets/ui/desktop_blueteam_response.webp)

=== "Phone"

    ![blueteam_response at phone width](assets/ui/phone_blueteam_response.webp)

## Settings

### Audit trail

`/settings`

The audit log is hash-chained and append-only, and this screen can verify the chain.

1. Read **Time**, **Actor**, **Action**, **Target**, **Details**.
2. `Re-verify` re-walks the chain and reports whether it is intact, including unchained entries.

=== "Desktop"

    ![settings at desktop width](assets/ui/desktop_settings.webp)

=== "Phone"

    ![settings at phone width](assets/ui/phone_settings.webp)

### Team

`/settings/team`

Who can sign in, what they can do, and their API keys.

1. Type a name, pick a role, press `Add`. The API key appears once.
2. `Change role` opens a radio group on the row; pick a role, then `Save role`. Selecting alone does nothing, because a privilege change should not happen on a stray click.
3. `Disable` revokes access and keeps the account and its audit trail; it becomes `Enable`.
4. `Rotate key` issues a new key and stops the previous one immediately.
5. A failed action is written on the row, not only in the toast.

=== "Desktop"

    ![settings_team at desktop width](assets/ui/desktop_settings_team.webp)

=== "Phone"

    ![settings_team at phone width](assets/ui/phone_settings_team.webp)

### Finding ownership

`/settings/ownership`

Teams, members and the routing policy that decides which team owns a finding.

1. Define teams and members.
2. Map repositories and assets to teams.
3. Author a policy version, preview it against real findings, then activate the version you reviewed.

=== "Desktop"

    ![settings_ownership at desktop width](assets/ui/desktop_settings_ownership.webp)

=== "Phone"

    ![settings_ownership at phone width](assets/ui/phone_settings_ownership.webp)

### Integrations

`/settings/integrations`

Outbound systems Synapse talks to, and whether each is enabled.

1. Add an integration and supply its credential; secrets go to the vault.
2. Enable or disable one without deleting it.
3. Check its bindings to see what it is wired to.

=== "Desktop"

    ![settings_integrations at desktop width](assets/ui/desktop_settings_integrations.webp)

=== "Phone"

    ![settings_integrations at phone width](assets/ui/phone_settings_integrations.webp)

### Connectors

`/settings/connectors`

Source-control hosts a scan can clone a private repository from.

1. Pick the **Provider**, then fill **Name**, **Host**, **Username** and the **Personal access token**.
2. The token is encrypted at rest and supplied to git only at clone time.
3. `Add connector` saves it.

=== "Desktop"

    ![settings_connectors at desktop width](assets/ui/desktop_settings_connectors.webp)

=== "Phone"

    ![settings_connectors at phone width](assets/ui/phone_settings_connectors.webp)

### SLA policy

`/settings/sla`

How a finding's remediation deadline is computed. The policy is versioned.

1. Set the **Version label**.
2. Set **Factor weights**: severity, exploitability, threat intel, exposure and the rest.
3. Set **Tier thresholds & due windows**: **Tier**, **Score ≥**, **Mitigate**, **Remediate**.
4. `Activate` makes this version the one new assessments use; existing findings are unchanged until reassessed.

=== "Desktop"

    ![settings_sla at desktop width](assets/ui/desktop_settings_sla.webp)

=== "Phone"

    ![settings_sla at phone width](assets/ui/phone_settings_sla.webp)

### Offensive policy

`/settings/offensive-policy`

What offensive tooling is permitted and under what authorization.

1. Set the policy for the tenant.
2. Save it; the change lands in the audit trail.

=== "Desktop"

    ![settings_offensive-policy at desktop width](assets/ui/desktop_settings_offensive-policy.webp)

=== "Phone"

    ![settings_offensive-policy at phone width](assets/ui/phone_settings_offensive-policy.webp)

### Alerting

`/settings/alerting`

Where notifications go, which events trigger them, and what was delivered.

1. `Add channel`, then set **Type**, **Name**, **Webhook URL**, **HMAC secret**.
2. Add rules mapping events to channels.
3. `Send test alert` proves the path end to end before you rely on it.
4. Review deliveries with the channel / event / state filters; open one to see each attempt.

=== "Desktop"

    ![settings_alerting at desktop width](assets/ui/desktop_settings_alerting.webp)

=== "Phone"

    ![settings_alerting at phone width](assets/ui/phone_settings_alerting.webp)

### Telemetry privacy

`/settings/privacy`

What agent telemetry is retained and what is redacted before storage.

1. Read the active policy.
2. Change what is collected and redacted, then save a new version.

=== "Desktop"

    ![settings_privacy at desktop width](assets/ui/desktop_settings_privacy.webp)

=== "Phone"

    ![settings_privacy at phone width](assets/ui/phone_settings_privacy.webp)

### Relationships

`/settings/relationships`

Proposed links between assessments, reviewed before they are committed.

1. Read each candidate and its evidence.
2. Preview the change, then commit the preview you reviewed.

=== "Desktop"

    ![settings_relationships at desktop width](assets/ui/desktop_settings_relationships.webp)

=== "Phone"

    ![settings_relationships at phone width](assets/ui/phone_settings_relationships.webp)

### Config

`/settings/config`

Per-person preferences and the session.

1. Pick `Light`, `System` or `Dark`.
2. `Disconnect` ends the session.

=== "Desktop"

    ![settings_config at desktop width](assets/ui/desktop_settings_config.webp)

=== "Phone"

    ![settings_config at phone width](assets/ui/phone_settings_config.webp)

## Engagement detail

`/engagements/{id}/{tab}`: twenty-eight tabs in five groups. The header carries `Build report`,
`Export`, `Import`, `Scan settings` and `Run scan` on every tab, and the scan panel shows the
pipeline stages with their timings.

### Overview

`/engagements/{id}/overview`

Scan health, the pipeline journey with per-stage timings, risk analysis and inventory counts.

1. Read the header: status, the asset, how many targets are in scope, and the authorization window.
2. Press **Run scan** to start one, or **Scan settings** to choose the mode and which analyzers run.
3. Expand **Pipeline Journey Track** to see every step of the last scan with its counts and duration; a step that failed says why here.
4. A banner above the tabs reports an incomplete inventory, for example a manifest that could not be resolved. Treat it as an unresolved result, not a clean one.
5. **Build report** renders from stored data only; **Export** and **Import** move a CI bundle in and out.

=== "Desktop"

    ![engagements_engagement_overview at desktop width](assets/ui/desktop_engagements_engagement_overview.webp)

=== "Phone"

    ![engagements_engagement_overview at phone width](assets/ui/phone_engagements_engagement_overview.webp)

### Findings

`/engagements/{id}/findings`

Every finding, ranked. Columns: **Pri**, **Severity**, **Finding & Details**, **Scope**, **Status**.

1. Filter by severity, kind, status and producer; the search box matches title, rule and path.
2. Sort by pressing a column header. The page size control offers 25, 50 or 100.
3. Open a finding to read its evidence, its judgment history, and the retests recorded against it.
4. Change status or severity from the finding, and record the reason; the change is written to the append-only audit log.
5. The count beside the tab is the filtered total, so it moves as you narrow.

=== "Desktop"

    ![engagements_engagement_findings at desktop width](assets/ui/desktop_engagements_engagement_findings.webp)

=== "Phone"

    ![engagements_engagement_findings at phone width](assets/ui/phone_engagements_engagement_findings.webp)

### Imported

`/engagements/{id}/imported`

Findings ingested from another tool, kept distinct from what Synapse detected.

1. This tab holds third-party findings brought in as SARIF, kept apart from what Synapse produced so provenance stays clear.
2. Read the import summary for what was accepted and what was refused.
3. `synapse-cli validate-sarif` reports what the server would accept without writing anything; use it before importing.
4. Nothing here is merged into the native finding set; it is governed separately.

=== "Desktop"

    ![engagements_engagement_imported at desktop width](assets/ui/desktop_engagements_engagement_imported.webp)

=== "Phone"

    ![engagements_engagement_imported at phone width](assets/ui/phone_engagements_engagement_imported.webp)

### Comparison

`/engagements/{id}/comparison`

Two immutable snapshots compared. `Finalize snapshot` creates one from selected scan runs.

1. Press **Configure comparison** and choose two finalized snapshots: a baseline and a current.
2. Pick the scope, which decides whether the comparison covers all findings, security findings only, or vulnerabilities only.
3. Press **Run comparison**. The result is immutable and addressed by its own id, so the same link always shows the same answer.
4. Read the ratios first: new, fixed, unchanged, and the ones that could not be compared.
5. Filter the compared findings by presence, severity, change flag and review state, then open one to see both observations side by side.
6. An Assessment in no Cycle can still compare its own snapshots; the Cycle only adds sibling Assessments as baselines.

=== "Desktop"

    ![engagements_engagement_comparison at desktop width](assets/ui/desktop_engagements_engagement_comparison.webp)

=== "Phone"

    ![engagements_engagement_comparison at phone width](assets/ui/phone_engagements_engagement_comparison.webp)

### Remediation SLA

`/engagements/{id}/sla`

Deadlines per finding: **Tier / score**, **Mitigate by**, **Remediate by**, **Workflow**, **Policy**. `Transition` records a state change with its audit reason, and shows the prior transitions and deadline assessments.

1. The panel states the risk-based deadline for each finding and whether it is met, at risk, or breached.
2. Open **Transition history** on a finding to see who moved it, when, and the reason they recorded.
3. Open **Deadline assessments** to see how the deadline was derived, not just what it is.
4. Accepting a risk requires a reason and an expiry; both are audited and the acceptance lapses on its own.
5. The tab is empty and says so when `SYNAPSE_SLA_ENABLED` is off.

=== "Desktop"

    ![engagements_engagement_sla at desktop width](assets/ui/desktop_engagements_engagement_sla.webp)

=== "Phone"

    ![engagements_engagement_sla at phone width](assets/ui/phone_engagements_engagement_sla.webp)

### Risk Stories

`/engagements/{id}/risk-stories`

Per-asset risk narrative assembled from the findings.

1. A risk story groups findings, assets and detections that describe one attack narrative rather than one defect.
2. Each story names the asset it is about and the evidence that correlated it.
3. Stories are produced by correlation over the scan and fleet data, so an engagement with neither shows none.
4. Open a story to reach the findings underneath it.

=== "Desktop"

    ![engagements_engagement_risk-stories at desktop width](assets/ui/desktop_engagements_engagement_risk-stories.webp)

=== "Phone"

    ![engagements_engagement_risk-stories at phone width](assets/ui/phone_engagements_engagement_risk-stories.webp)

### Vuln Posture

`/engagements/{id}/vuln-posture`

Vulnerability posture for this engagement, with an acknowledge / resolve queue.

1. **Reconciled occurrences** lists every place a vulnerability was observed for this engagement, after reconciliation against the advisory store.
2. The **Action queue** holds the ones still awaiting a decision.
3. Press **Acknowledge** to record that the occurrence is known and accepted for now, or **Resolve** to close it.
4. Both write to the audit log with the actor; neither edits the finding's evidence.

=== "Desktop"

    ![engagements_engagement_vuln-posture at desktop width](assets/ui/desktop_engagements_engagement_vuln-posture.webp)

=== "Phone"

    ![engagements_engagement_vuln-posture at phone width](assets/ui/phone_engagements_engagement_vuln-posture.webp)

### Packages

`/engagements/{id}/components`

The software bill of materials: every package the scan cataloged.

1. Every component the scan resolved, with its version, PURL and licenses.
2. Search by name, version, PURL or license.
3. An empty list on an application that has dependencies is an unresolved result, not a clean one: a manifest without a lockfile cannot be pinned unless manifest resolution is enabled.
4. Components come from Synapse's own per-ecosystem parsers; no third-party scanner is involved by default.

=== "Desktop"

    ![engagements_engagement_components at desktop width](assets/ui/desktop_engagements_engagement_components.webp)

=== "Phone"

    ![engagements_engagement_components at phone width](assets/ui/phone_engagements_engagement_components.webp)

### Vulnerabilities

`/engagements/{id}/vulns`

Advisory matches against the cataloged packages.

1. Each row is a vulnerability matched against a resolved component, with severity, CVSS, EPSS and whether it is in CISA KEV.
2. **Direct** says whether the project depends on the affected package itself or reaches it through another one.
3. **Path** shows the route from a direct dependency to the vulnerable package, which is what makes a transitive finding actionable.
4. The fix column carries the fixed version and how confident the upgrade is.
5. Search matches the identifier, the component and the description.

=== "Desktop"

    ![engagements_engagement_vulns at desktop width](assets/ui/desktop_engagements_engagement_vulns.webp)

=== "Phone"

    ![engagements_engagement_vulns at phone width](assets/ui/phone_engagements_engagement_vulns.webp)

### Licenses

`/engagements/{id}/licenses`

License obligations per component, with the policy verdict.

1. Every distinct license found across the resolved components, classified against the policy.
2. Search by SPDX id or name.
3. A component whose license could not be determined is listed as unknown rather than assumed permissive.

=== "Desktop"

    ![engagements_engagement_licenses at desktop width](assets/ui/desktop_engagements_engagement_licenses.webp)

=== "Phone"

    ![engagements_engagement_licenses at phone width](assets/ui/phone_engagements_engagement_licenses.webp)

### Dependency graph

`/engagements/{id}/graph`

The dependency tree, loaded as its own chunk because only this tab needs it.

1. Choose a mode: **finding** traces the path to a vulnerable package, **explorer** walks out from one package, **license** shows what a license reaches, **blast** shows what depends on a package.
2. In finding mode, step through the vulnerabilities with the selector; the graph redraws for each.
3. In explorer mode, pick a focus package and a depth.
4. Solid edges were observed in the lockfile; the graph is empty when the scan resolved no dependency edges.
5. Pan and zoom with the controls; the minimap shows where you are in a large graph.

=== "Desktop"

    ![engagements_engagement_graph at desktop width](assets/ui/desktop_engagements_engagement_graph.webp)

=== "Phone"

    ![engagements_engagement_graph at phone width](assets/ui/phone_engagements_engagement_graph.webp)

### Scan runs

`/engagements/{id}/scanruns`

Every run with its provenance lanes, and the drift between runs.

1. Every scan this engagement has run, newest first, with its status, duration and the tool versions it pinned.
2. Select two runs and press **Compare A and B** to see what changed between them.
3. The diff separates findings that appeared, findings that went away, and changes caused by the advisory database moving rather than the code.
4. Each run links to the evidence it sealed.

=== "Desktop"

    ![engagements_engagement_scanruns at desktop width](assets/ui/desktop_engagements_engagement_scanruns.webp)

=== "Phone"

    ![engagements_engagement_scanruns at phone width](assets/ui/phone_engagements_engagement_scanruns.webp)

### Credentials

`/engagements/{id}/credentials`

Credentials in scope for this engagement, vault-backed.

1. Stores the credentials a scan or probe needs, by placeholder name, so no secret ever reaches argv or a log.
2. Press **Add a credential**, give it a placeholder name and the secret value, and save.
3. Reference it elsewhere as `{{secret:NAME}}`; the server substitutes it at execution time.
4. A stored value is never shown again, and **Delete** asks for confirmation.
5. Secrets are scrubbed from tool output, from sealed evidence, and from a tool's error before any of them is stored.

=== "Desktop"

    ![engagements_engagement_credentials at desktop width](assets/ui/desktop_engagements_engagement_credentials.webp)

=== "Phone"

    ![engagements_engagement_credentials at phone width](assets/ui/phone_engagements_engagement_credentials.webp)

### Code quality

`/engagements/{id}/quality`

The code-quality view scoped to this engagement.

1. The latest code-quality analysis for the project bound to this engagement: the quality gate verdict and the issue counts by kind and severity.
2. The gate says which condition failed, with the threshold and the actual value.
3. Follow through to the Code Quality project for the file-level detail.
4. The tab says the capability is unavailable rather than showing an empty result when code quality is not configured.

=== "Desktop"

    ![engagements_engagement_quality at desktop width](assets/ui/desktop_engagements_engagement_quality.webp)

=== "Phone"

    ![engagements_engagement_quality at phone width](assets/ui/phone_engagements_engagement_quality.webp)

### Threat model

`/engagements/{id}/threats`

The threat model for the target.

1. Holds an ingested threat model: trust boundaries, components, data flows and the assets they touch.
2. Read the counts first, then the boundary crossings, which are where a data flow leaves a trust boundary.
3. Nothing is inferred here; the model is what was ingested.

=== "Desktop"

    ![engagements_engagement_threats at desktop width](assets/ui/desktop_engagements_engagement_threats.webp)

=== "Phone"

    ![engagements_engagement_threats at phone width](assets/ui/phone_engagements_engagement_threats.webp)

### Recon

`/engagements/{id}/recon`

Recon runs. A run is proposed, gated on scope and authorization, then approved by a human.

1. Live recon is off until it is enabled in **Settings**, and the tab says so with a link there.
2. Choose a **Tool** and an **in-scope target**; only targets inside the engagement's scope are offered, and the server checks scope and the authorization window again before anything runs.
3. Press **Launch**. The run appears in **Runs** with its containment posture, which names the sandbox and how egress was restricted.
4. Open **Live log** to watch the tool's output as it arrives.
5. Every run seals its output into the evidence chain, including a failed one, and records the connect attempts the kernel observed.

=== "Desktop"

    ![engagements_engagement_recon at desktop width](assets/ui/desktop_engagements_engagement_recon.webp)

=== "Phone"

    ![engagements_engagement_recon at phone width](assets/ui/phone_engagements_engagement_recon.webp)

### Purple coverage

`/engagements/{id}/purple`

Which detections cover which attack techniques.

1. **Detection coverage** compares the techniques an emulation exercised against the detections that fired.
2. **Detection gaps to close** lists techniques that ran and were not detected, which is the list worth acting on.
3. Pick a **Target asset** and press **Run emulation** to run benign technique variants.
4. Each technique declares the detection it expects, so a gap is a statement about a control, not about the tool.
5. **Coverage by emulation run** keeps the history so improvement is visible.

=== "Desktop"

    ![engagements_engagement_purple at desktop width](assets/ui/desktop_engagements_engagement_purple.webp)

=== "Phone"

    ![engagements_engagement_purple at phone width](assets/ui/phone_engagements_engagement_purple.webp)

### Chain rehearsal

`/engagements/{id}/rehearsal`

Attack-chain rehearsal against the modelled path.

1. A rehearsal proves an exploitation chain is permitted and that its chain of custody is sound. It executes against a no-host simulation and never touches a host.
2. Add each step with its technique, target, blast radius (read-only or state-changing) and, for a state-changing step, its cleanup.
3. Press **Run no-host rehearsal**. Each step is admitted against the engagement's rules of engagement before it runs.
4. Every step seals its own evidence and is confirmed by a verifier distinct from the proposer.
5. The offensive kill switch halts a running rehearsal.

=== "Desktop"

    ![engagements_engagement_rehearsal at desktop width](assets/ui/desktop_engagements_engagement_rehearsal.webp)

=== "Phone"

    ![engagements_engagement_rehearsal at phone width](assets/ui/phone_engagements_engagement_rehearsal.webp)

### AI agent

`/engagements/{id}/agent`

The AI session transcript: the goal, each tool call, and the token cost.

1. Write the **Agent goal** and press **Start agent**.
2. The agent proposes; it never confirms its own claim, and no model sits in the report path.
3. Watch the **Transcript** for each tool call, its result, and the tokens spent.
4. With the approval mode set to manual, an action that needs approval waits for a decision rather than proceeding.
5. Past sessions stay in **Sessions** with their decisions and plans.

=== "Desktop"

    ![engagements_engagement_agent at desktop width](assets/ui/desktop_engagements_engagement_agent.webp)

=== "Phone"

    ![engagements_engagement_agent at phone width](assets/ui/phone_engagements_engagement_agent.webp)

### Cloud posture

`/engagements/{id}/cspm`

Cloud posture findings; an unknown-state resource stays NotAssessed.

1. Choose the provider (AWS, Azure or GCP) and press **Run posture scan**.
2. **Latest run** reports the assets read, the findings raised, and the coverage issues, which are the places the scan could not see.
3. Coverage issues matter as much as findings: an unreadable account is not a compliant one.
4. Each run links to the evidence it sealed.
5. The tab stays off until `SYNAPSE_CSPM_ENABLED` is set.

=== "Desktop"

    ![engagements_engagement_cspm at desktop width](assets/ui/desktop_engagements_engagement_cspm.webp)

=== "Phone"

    ![engagements_engagement_cspm at phone width](assets/ui/phone_engagements_engagement_cspm.webp)

### DAST

`/engagements/{id}/dast`

Dynamic testing. A scan or probe is proposed and a distinct reviewer approves it.

1. **Runtime verification** turns a finding into a probe: press **Propose probe**, fill in the URL, method, expected status and optional expected body.
2. A proposal is a claim, not an action. Press **Approve** or **Deny**, with a reason; only an approved probe can run.
3. Press **Run probe**. It executes under a kernel-enforced egress allowlist, so it can only reach what the scope permits.
4. **Authenticated DAST scan** follows the same propose, approve, run shape for a full scan.
5. The result records what was observed, which is what confirms or refutes the finding.

=== "Desktop"

    ![engagements_engagement_dast at desktop width](assets/ui/desktop_engagements_engagement_dast.webp)

=== "Phone"

    ![engagements_engagement_dast at phone width](assets/ui/phone_engagements_engagement_dast.webp)

### Detections

`/engagements/{id}/detections`

Runtime detections correlated to this engagement.

1. Detections shipped by the fleet agents for this engagement, sealed once into the evidence chain.
2. Press correlate to fold the newest detections into incidents.
3. A truncated evidence window says so rather than silently showing part of the picture.
4. Follow a detection to its provenance to see the chain behind it.

=== "Desktop"

    ![engagements_engagement_detections at desktop width](assets/ui/desktop_engagements_engagement_detections.webp)

=== "Phone"

    ![engagements_engagement_detections at phone width](assets/ui/phone_engagements_engagement_detections.webp)

### Detection provenance

`/engagements/{id}/detection-provenance`

Where each detection came from and what it was derived from.

1. The durable chain behind each detection: what produced it, which key signed it, and whether the chain still verifies.
2. A broken chain is stated plainly; it blocks the report rather than degrading it quietly.
3. An expired provenance record is distinguished from a broken one.
4. Use this tab when you need to defend a detection, not just read it.

=== "Desktop"

    ![engagements_engagement_detection-provenance at desktop width](assets/ui/desktop_engagements_engagement_detection-provenance.webp)

=== "Phone"

    ![engagements_engagement_detection-provenance at phone width](assets/ui/phone_engagements_engagement_detection-provenance.webp)

### Judgment review

`/engagements/{id}/reviews`

The propose / verify / confirm record, with the hash-chained evidence ledger.

1. Every analysis or AI claim arrives as a proposal that a distinct verifier must confirm.
2. Open a judgment to read the evidence score and the rationale recorded with it.
3. Confirm or refute it; a proposer can never confirm its own claim.
4. **Auto-verify all** runs the verifier over the queue where the policy allows it.
5. An empty queue means nothing is awaiting a human decision, not that nothing was proposed.

=== "Desktop"

    ![engagements_engagement_reviews at desktop width](assets/ui/desktop_engagements_engagement_reviews.webp)

=== "Phone"

    ![engagements_engagement_reviews at phone width](assets/ui/phone_engagements_engagement_reviews.webp)

### Evidence

`/engagements/{id}/evidence`

The evidence ledger itself. A broken chain blocks the report.

1. The hash-chained, append-only record for this engagement, newest first.
2. Press **Capture** to add a note or a file; both become part of the chain.
3. The chain is verified on read; a break is reported and blocks the report rather than being hidden.
4. Nothing here can be edited or deleted, which is the point.

=== "Desktop"

    ![engagements_engagement_evidence at desktop width](assets/ui/desktop_engagements_engagement_evidence.webp)

=== "Phone"

    ![engagements_engagement_evidence at phone width](assets/ui/phone_engagements_engagement_evidence.webp)

### Data governance

`/engagements/{id}/data-governance`

Retention and handling for the data this engagement holds.

1. **Legal hold** preserves this engagement's detection data against retention expiry and on-demand deletion. Press **Place a hold** with a reason; the reason is required and audited.
2. A held engagement refuses deletion, so place the hold before you need it.
3. **Release hold** lifts it, and is audited the same way.
4. **Data export** generates the governance bundle for a subject-access request: the detections held for this engagement plus any active holds. Press **Download JSON** to take it away.
5. **Danger zone** deletes the detection projection on demand. It requires a reason, asks for confirmation, refuses while a hold is in place, and never touches the evidence chain.
6. The tab needs `SYNAPSE_FLEET_ENABLED` and `SYNAPSE_FLEET_DETECTION_INGEST_ENABLED`, because the detection projection is the data it governs.

=== "Desktop"

    ![engagements_engagement_data-governance at desktop width](assets/ui/desktop_engagements_engagement_data-governance.webp)

=== "Phone"

    ![engagements_engagement_data-governance at phone width](assets/ui/phone_engagements_engagement_data-governance.webp)

### Write-up drafts

`/engagements/{id}/writeup-drafts`

AI-drafted write-ups, unconfirmed until a human accepts them.

1. Drafts a description and a remediation for a finding, as a proposal a human decides on.
2. Open the finding the draft is about to judge it in context.
3. Edit the draft, then **Save**, **Accept** or **Reject**.
4. Nothing reaches the report until it is accepted; no model writes into the report path.

=== "Desktop"

    ![engagements_engagement_writeup-drafts at desktop width](assets/ui/desktop_engagements_engagement_writeup-drafts.webp)

=== "Phone"

    ![engagements_engagement_writeup-drafts at phone width](assets/ui/phone_engagements_engagement_writeup-drafts.webp)

### Settings

`/engagements/{id}/settings`

Scope, authorization window, rules of engagement, and the engagement lifecycle.

1. **Scope** lists what is in and out of scope. The execution layer checks it server-side before any tool runs, so this is a control, not a label. Press **Save scope**.
2. **Authorization window** bounds when execution is permitted. Press **Save window**.
3. **Live reconnaissance** is the switch that makes execution against a real target possible. Enabling it re-confirms the acceptable-use policy version and records a lab-authorization attestation; both go to the append-only audit log. Disabling needs neither.
4. **Offensive rules of engagement** set the maximum blast radius, from prohibited through low, medium and high. Unset means offensive actions are refused. Press **Save RoE**.
5. **Asset assignment** binds the engagement to a business asset; **Lifecycle** activates, completes or archives it.

=== "Desktop"

    ![engagements_engagement_settings at desktop width](assets/ui/desktop_engagements_engagement_settings.webp)

=== "Phone"

    ![engagements_engagement_settings at phone width](assets/ui/phone_engagements_engagement_settings.webp)

## Asset detail

`/assets/{key}` and its tabs. The route accepts either the asset id or its tenant-scoped
business key.

### Overview

`/assets/{key}`

Criticality, owner, lifecycle and posture for one business asset.

1. **Asset profile** carries what the asset is: type, criticality, lifecycle and owner. Press the edit control to change them, then **Save**.
2. Criticality drives the remediation deadline an SLA policy derives, so it is a governance field rather than a label.
3. **Recent engagements** links to the assessments that covered this asset.
4. Lifecycle moves the asset through its stages; the control offers only the transitions the current state allows.

=== "Desktop"

    ![assets_payments-api at desktop width](assets/ui/desktop_assets_payments-api.webp)

=== "Phone"

    ![assets_payments-api at phone width](assets/ui/phone_assets_payments-api.webp)

### Components

`/assets/{key}/components`

The projects and technical assets that make up this business asset.

1. **Projects / repositories** lists the code identities bound to this asset.
2. **Technical / fleet assets** lists the hosts, workloads, images and exposures the fleet has attributed to it.
3. Together they are the denominator for coverage: what should be assessed, not what happens to have been.
4. Add a component with the selector and mark one **Primary** when the asset has an obvious main repository.

=== "Desktop"

    ![assets_payments-api_components at desktop width](assets/ui/desktop_assets_payments-api_components.webp)

=== "Phone"

    ![assets_payments-api_components at phone width](assets/ui/phone_assets_payments-api_components.webp)

### Engagements

`/assets/{key}/engagements`

Every assessment that covered this asset.

1. Every engagement assigned to this asset, with its status and dates.
2. An asset with no engagement says so plainly, which is the state worth noticing on a critical asset.
3. Follow one through to its findings.

=== "Desktop"

    ![assets_payments-api_engagements at desktop width](assets/ui/desktop_assets_payments-api_engagements.webp)

=== "Phone"

    ![assets_payments-api_engagements at phone width](assets/ui/phone_assets_payments-api_engagements.webp)

### Findings

`/assets/{key}/findings`

Findings aggregated across those assessments.

1. The current findings across every engagement that covered this asset, so one screen answers "what is open against this asset".
2. Filter and page through them; the list is server-paged, so a large estate stays fast.
3. Severity and status are the finding's own, not a copy, so acting here acts on the finding.

=== "Desktop"

    ![assets_payments-api_findings at desktop width](assets/ui/desktop_assets_payments-api_findings.webp)

=== "Phone"

    ![assets_payments-api_findings at phone width](assets/ui/phone_assets_payments-api_findings.webp)

### Coverage

`/assets/{key}/coverage`

Which components were assessed, by what, and how recently.

1. Each expected component with its coverage verdict against the freshness target named in the panel title.
2. A component never assessed and one assessed too long ago are different verdicts, and both differ from one that is current.
3. The counts beside the title break the estate down by verdict.
4. Coverage is computed against the components declared on the asset, so an incomplete component list produces a flattering number.

=== "Desktop"

    ![assets_payments-api_coverage at desktop width](assets/ui/desktop_assets_payments-api_coverage.webp)

=== "Phone"

    ![assets_payments-api_coverage at phone width](assets/ui/phone_assets_payments-api_coverage.webp)

### History

`/assets/{key}/history`

The assessment history for the asset.

1. The assessment history for this asset over time: which engagement, when, and what it found.
2. Use it to answer how long an asset has gone without assessment, which the coverage verdict summarises but does not date.

=== "Desktop"

    ![assets_payments-api_history at desktop width](assets/ui/desktop_assets_payments-api_history.webp)

=== "Phone"

    ![assets_payments-api_history at phone width](assets/ui/phone_assets_payments-api_history.webp)

## Code quality project

`/code-quality/projects/{key}` and its tabs.

### Overview

`/code-quality/projects/{key}`

Project health, the managed gate verdict, and the trend.

1. The quality gate verdict for the selected branch, with each condition, its threshold and the actual value.
2. The ratings are **Security**, **Reliability** and **Maintainability**, beside coverage and duplication.
3. Switch between **Overall Code** and **New Code**; a gate usually fails on new code, which is the code you can still change.
4. The branch selector offers the branches that have analyses. A project bound to a local path has no branch name and shows "no branch".
5. Press **Run analysis** to start one, or **Coverage** to upload a coverage report the analysis cannot produce itself.

=== "Desktop"

    ![code-quality_projects_juice-shop at desktop width](assets/ui/desktop_code-quality_projects_juice-shop.webp)

=== "Phone"

    ![code-quality_projects_juice-shop at phone width](assets/ui/phone_code-quality_projects_juice-shop.webp)

### Security hotspots

`/code-quality/projects/{key}/hotspots`

Code needing a security review decision.

1. A hotspot is code that needs a human to decide whether it is a vulnerability in this context, not a finding asserting that it is.
2. Select one to read the code around it with the rule that raised it.
3. Record the decision: it is safe here, or it is a real vulnerability. The decision and its rationale are kept.
4. The review percentage on the Overview counts these decisions, so an unreviewed project reads 0% however clean it is.

=== "Desktop"

    ![code-quality_projects_juice-shop_hotspots at desktop width](assets/ui/desktop_code-quality_projects_juice-shop_hotspots.webp)

=== "Phone"

    ![code-quality_projects_juice-shop_hotspots at phone width](assets/ui/phone_code-quality_projects_juice-shop_hotspots.webp)

### Issues

`/code-quality/projects/{key}/issues`

Every issue with its rule, severity and status. The inspector shows the review history behind the current status before you reclassify.

1. Filter by kind, severity, status, rule and path; the search box matches title, rule and path together.
2. Open an issue to read it against its source, with the rule's explanation beside it.
3. Change its status and record the rationale; the history is kept and shown in the inspector above the form.
4. The code lens shows the issue in place rather than as a line number you have to go and find.

=== "Desktop"

    ![code-quality_projects_juice-shop_issues at desktop width](assets/ui/desktop_code-quality_projects_juice-shop_issues.webp)

=== "Phone"

    ![code-quality_projects_juice-shop_issues at phone width](assets/ui/phone_code-quality_projects_juice-shop_issues.webp)

### Code

`/code-quality/projects/{key}/code`

The analysed source, annotated with its findings.

1. Browse the source the analysis captured, directory by directory.
2. Per-file measures sit beside the tree, so you can see which file carries the issues.
3. A file is present only when the analysis published its source; a project that has not published shows none.

=== "Desktop"

    ![code-quality_projects_juice-shop_code at desktop width](assets/ui/desktop_code-quality_projects_juice-shop_code.webp)

=== "Phone"

    ![code-quality_projects_juice-shop_code at phone width](assets/ui/phone_code-quality_projects_juice-shop_code.webp)

### Dependencies

`/code-quality/projects/{key}/dependencies`

The dependency tree with risky paths marked.

1. The project's dependency tree, resolved from its manifests and lockfiles.
2. Search by package, version or PURL.
3. Filter to what you are looking for, then expand a node to walk the tree.
4. Export the SBOM to take the inventory away in a standard format.

=== "Desktop"

    ![code-quality_projects_juice-shop_dependencies at desktop width](assets/ui/desktop_code-quality_projects_juice-shop_dependencies.webp)

=== "Phone"

    ![code-quality_projects_juice-shop_dependencies at phone width](assets/ui/phone_code-quality_projects_juice-shop_dependencies.webp)

### Measures

`/code-quality/projects/{key}/measures`

The measured metrics for the analysis.

1. Choose a **Measures domain** to switch between reliability, security, maintainability, coverage, duplication and size.
2. The list is a file tree: press a directory to descend, and the breadcrumb takes you back.
3. Filter files or directories by name.
4. Sort by a metric to find the worst files in that domain, which is usually the fastest route to the work worth doing.

=== "Desktop"

    ![code-quality_projects_juice-shop_measures at desktop width](assets/ui/desktop_code-quality_projects_juice-shop_measures.webp)

=== "Phone"

    ![code-quality_projects_juice-shop_measures at phone width](assets/ui/phone_code-quality_projects_juice-shop_measures.webp)

### Compare

`/code-quality/projects/{key}/compare`

Two analyses compared.

1. Pick two targets, a base and a compare; they must be different.
2. **Swap base and compare** reverses the direction without re-picking.
3. The result reports what moved between them, metric by metric, rather than two independent snapshots you have to diff by eye.

=== "Desktop"

    ![code-quality_projects_juice-shop_compare at desktop width](assets/ui/desktop_code-quality_projects_juice-shop_compare.webp)

=== "Phone"

    ![code-quality_projects_juice-shop_compare at phone width](assets/ui/phone_code-quality_projects_juice-shop_compare.webp)

### Analysis

`/code-quality/projects/{key}/analysis`

One analysis in detail.

1. The details of one analysis: when it ran, what produced it, and the gate it was evaluated against.
2. Use it to answer why a gate verdict came out as it did, including which conditions were evaluated.

=== "Desktop"

    ![code-quality_projects_juice-shop_analysis at desktop width](assets/ui/desktop_code-quality_projects_juice-shop_analysis.webp)

=== "Phone"

    ![code-quality_projects_juice-shop_analysis at phone width](assets/ui/phone_code-quality_projects_juice-shop_analysis.webp)

### Activity

`/code-quality/projects/{key}/activity`

The analysis history, which is where a CI push lands.

1. The analysis history for the project, newest first.
2. Each entry carries its gate verdict, so a regression is visible as a change rather than an isolated result.
3. Follow an entry to its analysis details.

=== "Desktop"

    ![code-quality_projects_juice-shop_activity at desktop width](assets/ui/desktop_code-quality_projects_juice-shop_activity.webp)

=== "Phone"

    ![code-quality_projects_juice-shop_activity at phone width](assets/ui/phone_code-quality_projects_juice-shop_activity.webp)

