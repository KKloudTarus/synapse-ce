// The guided trip through the playground. Steps are route-based rather than anchored to a CSS
// selector: the dashboard has no stable test anchors in its navigation, so a selector-anchored tour
// would break silently the first time a component is restructured. A step may name an optional
// `highlight` selector, and a step whose selector is absent still shows its card.
export type TourStep = {
  route: string
  title: string
  body: string
  highlight?: string
}

export const TOUR_STEPS: TourStep[] = [
  {
    route: '/dashboard',
    title: 'Start here',
    body: 'Every number on this site comes from seeded fixtures. Nothing is scanned, no target is reached, and there is no backend behind the page. Use it to see what the console looks like with data in it.',
  },
  {
    route: '/engagements',
    title: 'Engagements are time-bounded',
    body: 'An Engagement carries a scope and an authorization window. The window is enforced server-side, before any tool runs, which is why a scan cannot outlive the permission that allowed it.',
  },
  {
    route: '/engagements/eng-001/supply-chain',
    title: 'Supply chain, from the owned engine',
    body: 'Components and advisories are matched by the platform\'s own engine. Open a finding to see the evidence it was confirmed from rather than a tool name.',
  },
  {
    route: '/engagements/eng-001/sast',
    title: 'Code findings carry a path',
    body: 'A SAST finding names the file, the rule and the data flow. The reachability tab answers the separate question of whether the vulnerable code is actually callable.',
  },
  {
    route: '/engagements/eng-001/reachability',
    title: 'Reachability narrows the list',
    body: 'Reachability is build-aware rather than guessed from identifiers, so an advisory on a package nothing calls ranks below one on a path that executes.',
  },
  {
    route: '/engagements/eng-001/evidence',
    title: 'Evidence is hash-chained',
    body: 'Every claim links to an append-only, hash-chained record. A broken chain blocks the report, and reports are templated from stored data alone, so no model sits in the report path.',
  },
  {
    route: '/code-quality',
    title: 'Projects are long-lived',
    body: 'A Project is the durable identity for a codebase, separate from the Engagements that assess it. Gates and profiles decide what fails a build.',
  },
  {
    route: '/fleet/agents',
    title: 'The agent fleet',
    body: 'Agents report host telemetry and runtime detections. The control plane receives a detection plus a bounded window of surrounding events rather than the raw stream.',
  },
  {
    route: '/fleet/incidents',
    title: 'Incidents are folded from events',
    body: 'An incident is projected from an append-only event log, so its history is reconstructable and its timeline is not a summary someone wrote.',
  },
  {
    route: '/ai-triage/reviews',
    title: 'A model proposes, a human confirms',
    body: 'Triage suggestions arrive as proposals. A proposer never confirms its own claim, so a suggestion reaches a reviewer queue instead of closing a finding.',
  },
  {
    route: '/vulnerability-intelligence',
    title: 'Advisory intelligence',
    body: 'Advisories, aliases and feed freshness are kept as reference data the matcher reads, so a match can be explained by the revision it was made against.',
  },
  {
    route: '/settings/integrations',
    title: 'Where a real install connects',
    body: 'In a real deployment this is where SCM webhooks, CI tokens and notification channels are bound. In the playground every form answers from fixtures and nothing leaves your browser.',
  },
]
