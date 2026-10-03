// The guided trip. Each step names a control, says what pressing it does, and says why the product
// behaves that way, because a tour that only advances teaches nothing.
//
// `anchor` is a CSS selector or a text match resolved at run time. It is optional and best-effort:
// the navigation carries no stable test anchors, so a step whose anchor no longer resolves still
// shows its card rather than breaking the trip. Anchors are therefore written against text a reader
// can see, which survives restructuring better than a class name.
export type TourStep = {
  route: string
  title: string
  /** What the control is and what pressing it does. */
  body: string
  /** Optional: why the product works this way. Rendered as a second, quieter paragraph. */
  why?: string
  /** Optional anchor. `text:` matches visible text, anything else is a CSS selector. */
  anchor?: string
}

export const TOUR_STEPS: TourStep[] = [
  {
    route: '/dashboard',
    title: 'What you are looking at',
    body: 'This is the full console with seeded data. Every number, finding and host here is a fixture: no scan runs, no target is contacted, and nothing you click leaves your browser. Use the left sidebar to move between areas, and come back to this bar at any time to restart the trip or reset the data.',
    why: 'The playground has no backend at all. Synapse runs real tools against real targets, so a public instance with a live backend would be something people could point at third parties.',
    anchor: 'text:Dashboard',
  },
  {
    route: '/engagements',
    title: 'Engagements: the unit of authorized work',
    body: 'Each row is a time-bounded piece of assessment work. The status chip tells you whether it is Active, and the date range next to it is the authorization window. Click a row to open it; the "New Engagement" button in the sidebar is how a real one starts.',
    why: 'Scope and the authorization window are checked server-side in the execution layer, before any tool runs. A scan cannot outlive the permission that allowed it, which is what separates an assessment platform from a scanner.',
    anchor: 'text:New Engagement',
  },
  {
    route: '/engagements/eng-001',
    title: 'The engagement header controls',
    body: '"Run scan" starts the pipeline for this engagement, "Scan settings" picks which analyses run, "Build report" renders the report from stored evidence, and "Export" writes SARIF or OpenVEX for another tool to read. The "Evidence verified" badge means the hash chain for this engagement checks out.',
    why: 'Reports are templated from stored data only, and a broken evidence chain blocks the report rather than footnoting it. No model sits in that path.',
    anchor: 'text:Run scan',
  },
  {
    route: '/engagements/eng-001',
    title: 'Reading the overview',
    body: 'Raw findings is everything the engines produced. Actionable is what survived triage and reachability. Repro % is how much of this result a rerun would reproduce exactly. The "Remediation Priorities" list is ordered by what fixing one package buys you, so the top row is the best next action rather than the highest CVSS.',
    why: 'Ordering by impact-per-fix is why the list groups by package: upgrading express once clears three findings, and a severity-sorted list would have scattered them.',
    anchor: 'text:Remediation Priorities & Targets',
  },
  {
    route: '/engagements/eng-001/supply-chain',
    title: 'Supply chain',
    body: 'Components come from the SBOM this engagement recorded, and each advisory match links to the evidence it was confirmed from. "Composition & Provenance" at the bottom names the engine versions and the SBOM digest that produced this result.',
    why: 'The provenance block is what makes a result auditable months later: the same SBOM digest and the same advisory database revision reproduce the same answer.',
    anchor: 'text:Supply Chain',
  },
  {
    route: '/engagements/eng-001/findings',
    title: 'Findings and what you can do to one',
    body: 'Use the severity and kind filters to narrow the list, then open a finding to see its evidence, its location and its reachability verdict. From an open finding you can accept it, mark it a false positive, or assign an owner.',
    why: 'A disposition is recorded against the finding and kept in the audit log, so "we decided this was not exploitable" survives the person who decided it.',
    anchor: 'text:Findings',
  },
  {
    route: '/engagements/eng-001/reachability',
    title: 'Reachability: why most advisories do not matter',
    body: 'Each row says whether the vulnerable symbol is actually callable from this codebase, with the call path that proves it. Sort by state to put the reachable ones first.',
    why: 'Reachability here is build-aware rather than guessed from identifier names, so an advisory on a package nothing calls ranks below one on a path that executes. That ordering is the difference between 45 findings and the 28 worth anyone\'s afternoon.',
    anchor: 'text:Reachability',
  },
  {
    route: '/engagements/eng-001/evidence',
    title: 'Evidence is append-only',
    body: 'Every claim on the other tabs links back to a record here. Entries are hash-chained, so each one commits to the one before it, and nothing can be edited after the fact.',
    why: 'If the chain breaks, the report is blocked instead of published with a warning. That is the strict choice on purpose: a report nobody can verify is worse than no report.',
    anchor: 'text:Evidence',
  },
  {
    route: '/code-quality',
    title: 'Projects are the long-lived half',
    body: 'A Project is the durable identity of a codebase, separate from the Engagements that assess it. Open one to see its analyses over time, its quality gate, and the code viewer.',
    why: 'Splitting the two means a finding can move with the code across assessments, instead of being born and dying inside one report.',
    anchor: 'text:Code Quality',
  },
  {
    route: '/code-quality/projects/synapse-ce',
    title: 'The code viewer',
    body: 'Pick a file on the left to read it with the analysis overlaid: changed lines, duplicated blocks and coverage are marked in the gutter. Switch between the file and the diff to see what one analysis changed.',
    why: 'The source shown here is the snapshot the analysis actually read, pushed by the pipeline with --push-source. That is why the view is honest about files it does not have rather than fetching today\'s code and pretending it was the one analysed.',
    anchor: 'text:Code',
  },
  {
    route: '/code-quality/gates',
    title: 'Quality gates decide what fails a build',
    body: 'A gate is a set of conditions on new code. Edit one to change a threshold, and the pipeline that next evaluates this project uses the new revision.',
    why: 'Conditions apply to new code rather than the whole repository, so a team inherits a clean bar on what they write without first paying down everything written before them.',
    anchor: 'text:Quality Gates',
  },
  {
    route: '/fleet/agents',
    title: 'The agent fleet',
    body: 'Each row is an installed agent with its version, platform and last check-in. Use the rollout controls to move a channel to a new version, promote a canary, or pause a rollout that is going badly.',
    why: 'Agents are lease-based and leader-gated, so a fleet-wide action is applied by one coordinator rather than raced between replicas.',
    anchor: 'text:Agents',
  },
  {
    route: '/fleet/hosts',
    title: 'Hosts and their packages',
    body: 'Every host the fleet reports, with its installed package count and the vulnerability summary the control plane computed. Open a host to see the findings behind those counts, with fixable and KEV flagged separately.',
    why: 'Fixable and KEV are separated because they answer different questions: one is "can I act on this today", the other is "is this being exploited in the wild right now".',
    anchor: 'text:Hosts',
  },
  {
    route: '/fleet/asset-graph',
    title: 'The asset graph',
    body: 'Nodes are technical assets (hosts, workloads, images, exposures, repositories) and edges are the observed relationships between them. Follow an edge to see how an internet-facing exposure reaches a workload, and the image and repository behind it.',
    why: 'Each edge records its provenance and whether it was observed or inferred, so a path you act on can be traced back to the inventory that claimed it.',
    anchor: 'text:Asset Graph',
  },
  {
    route: '/fleet/incidents',
    title: 'Incidents are folded from events',
    body: 'Open an incident to see its timeline, the detections that raised it, and the response actions available. Assign an owner, change status, or apply a response from the detail view.',
    why: 'The incident is projected from an append-only event log rather than being a mutable row, so its history is reconstructable and the timeline is not a summary someone edited.',
    anchor: 'text:Incidents',
  },
  {
    route: '/ai-triage/reviews',
    title: 'A model proposes, a person confirms',
    body: 'Each row is a triage suggestion waiting on a human. Claim one to take it, then accept or reject the proposal. The observability tab next door shows how the model has been performing against those human decisions.',
    why: 'A proposer never confirms its own claim. A suggestion reaches this queue rather than closing a finding, which is why a wrong suggestion costs a reviewer a minute instead of costing you a vulnerability.',
    anchor: 'text:Review Queue',
  },
  {
    route: '/vulnerability-intelligence',
    title: 'Advisory intelligence',
    body: 'The advisory sources feeding the matcher, their freshness, and the aliases that tie one vulnerability together across naming schemes. Open a source to test or disable it.',
    why: 'Freshness is shown per source because a match is only as current as the feed behind it, and a stale feed is a silent false negative rather than a visible error.',
    anchor: 'text:Vulnerability Intelligence',
  },
  {
    route: '/ownership',
    title: 'Ownership routes work to people',
    body: 'Teams, mappings and policies decide who a finding belongs to. A mapping binds an asset pattern to a team; a policy decides what happens when nothing matches.',
    why: 'Routing is a product feature rather than a spreadsheet because an unrouted finding is the one nobody fixes.',
    anchor: 'text:Ownership',
  },
  {
    route: '/settings/integrations',
    title: 'Where a real install connects',
    body: 'In a deployment this is where SCM webhooks, CI tokens and notification channels are bound. Secrets entered here are sealed into the vault immediately and never read back.',
    why: 'The webhook plane authenticates with its own HMAC and never falls back to a human credential, so a compromised webhook cannot become a session.',
    anchor: 'text:Integrations',
  },
  {
    route: '/dashboard',
    title: 'That is the trip',
    body: 'Press Reset in the top bar to clear anything you changed and start over, or Hide to get the bar out of the way. Everything you saw runs from fixtures in your browser, so nothing here can be broken by clicking.',
    why: 'To run this against your own code, the repository README has the docker compose setup; the same dashboard then talks to a real control plane.',
  },
]
