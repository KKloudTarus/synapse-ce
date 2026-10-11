import { COMPARISON_ID, CYCLE_ID, DEMO_ADVISORY, INITIAL_ID, RETEST_ID, TARGET, initial, retest, type Scenario } from './scenario/store'

export interface ScanStep {
  id: string; chapter: string; title: string; action: string; why: string; expected: string
  route: (s: Scenario) => string; ready: (s: Scenario) => boolean
  read?: boolean; anchor?: string; focus?: string; details?: { label: string; meaning: string }[]
}
const route = (path: string) => () => path
const scanned = (s: Scenario) => Boolean(initial(s)?.scan?.finishedAt)
const rescanned = (s: Scenario) => Boolean(retest(s)?.scan?.finishedAt)
export const comparisonResultSelector = `[data-comparison-result="${COMPARISON_ID}"][data-comparison-scope="all"][data-comparison-ready="true"] [data-comparison-summary]`
export const comparisonRoute = (s: Scenario) => {
  const path = `/engagements/${RETEST_ID}/comparison`
  if (!s.comparisonAt) return path
  const params = new URLSearchParams({ comparison_mode: 'lifecycle', comparison_base_assessment: INITIAL_ID, comparison_baseline: `${INITIAL_ID}-snapshot-1`, comparison_current: `${RETEST_ID}-snapshot-1`, comparison_id: COMPARISON_ID, comparison_scope: 'all' })
  return `${path}?${params}`
}
const authorized = (a: ReturnType<typeof initial>) => Boolean(a?.status === 'active' && Date.parse(a.authorizedFrom) <= Date.now() && Date.parse(a.authorizedTo) > Date.now() && a.tools.includes('sca'))

export const SCAN_STEPS: ScanStep[] = [
  {
    id: 'asset', chapter: 'Asset & scope', title: 'Create your first Asset', route: route('/assets'), anchor: 'New Asset',
    action: 'Select New Asset. Enter Name: Checkout API, Key: checkout-api, Owner: Checkout Team, Type: Application and Criticality: High. Add a short business description, then select Create Asset.',
    why: 'An Asset represents the product you are protecting. It connects assessments and risks over time, and names the team responsible for them.',
    expected: 'The Asset inventory shows the new Asset with the name, owner and criticality you entered.', ready: s => Boolean(s.asset),
    details: [
      { label: 'Name / Key', meaning: 'Name is the display label. Key is the stable identifier used in URLs; use lowercase letters and hyphens.' },
      { label: 'Type', meaning: 'Type classifies the business object. Application fits the API in this exercise.' },
      { label: 'Owner', meaning: 'Owner names the team responsible for the Asset, separately from a Finding Assignee.' },
      { label: 'Criticality', meaning: 'Criticality reflects business importance. High fits a payment service whose outage affects revenue. Severity describes an individual vulnerability.' },
      { label: 'Description', meaning: 'Description gives the reviewer business context and impact. The scan target is configured separately.' },
    ],
  },
  {
    id: 'engagement', chapter: 'Asset & scope', title: 'Create the initial assessment', route: s => `/engagements/new?assetId=${s.asset?.id ?? ''}`, anchor: 'Name',
    action: `Create an engagement named “Checkout API · Initial” for Demo Company. Select your Asset and Linked target. Add ${TARGET} as an in-scope Repo target, then select Create Engagement.`,
    why: 'An engagement defines one assessment with its own scope and authorization window. In-scope targets may be assessed; exclusions take precedence. The .example repository is a local training fixture.',
    expected: 'An Initial assessment is linked to your Asset in a new Cycle, with no scan or findings yet.', ready: s => Boolean(initial(s)),
  },
  {
    id: 'authorization', chapter: 'Asset & scope', title: 'Authorize work within scope', route: route(`/engagements/${INITIAL_ID}/settings`), anchor: 'Authorization window',
    action: 'Open Settings and activate the assessment. Save an authorization window from yesterday to tomorrow, using your timezone. Allow SCA in Rules of engagement, then select Save RoE. Review the scope.',
    why: 'Scope, time and tool class are separate execution constraints. SCA inspects dependencies in source; allowing it does not authorize live testing.',
    expected: 'The assessment is Active, its authorization window is current, and SCA is allowed.', ready: s => authorized(initial(s)),
  },
  {
    id: 'scan', chapter: 'Scan & triage', title: 'Configure and run a scan', route: route(`/engagements/${INITIAL_ID}`), anchor: 'Scan Settings',
    action: 'Open Scan settings. Use the demo repository, Git, branch main and Full mode. Leave static code quality off for this exercise, then select Save & Run scan. Follow each core phase in the Pipeline Journey Track before reviewing the finalized results.',
    why: 'The branch identifies the source revision being assessed. Full retains dependency analysis, configured source security engines and licensing. This demo shows SCA, SAST, secrets and IaC; optional code quality remains separate. A successful job still needs complete engine coverage.',
    expected: 'The job succeeds with Complete coverage, twelve packages and eighteen findings across five categories. No real scanner executes.', ready: scanned,
    details: [{ label: 'Scan modes', meaning: 'Vulns evaluates vulnerabilities; Licenses evaluates licensing. Local refers to a directory on the backend host. This exercise uses Git + Full to retain comparable coverage.' }],
  },
  { id: 'packages', chapter: 'Scan & triage', title: 'Read the recorded inventory', focus: '[data-package-summary]', route: route(`/engagements/${INITIAL_ID}/components`), read: true,
    action: 'Open Supply Chain → Packages. Review each package name, version, PURL and manifest location across npm, PyPI, Go and Maven. Find checkout-token@2.0.0; it will be used later in the monitoring example.',
    why: 'The SBOM records dependencies for this source revision. PURL identifies the package and ecosystem; its version determines whether an advisory applies.',
    expected: 'Twelve packages have resolved versions across npm, PyPI and Go. checkout-token remains at 2.0.0 for the monitoring example.', ready: scanned },
  { id: 'vulnerabilities', chapter: 'Scan & triage', title: 'Understand a vulnerability', focus: '#engagement-tabpanel', route: route(`/engagements/${INITIAL_ID}/vulns`), read: true,
    action: 'Open Vulnerabilities and inspect DEMO-CHECKOUT-001. Review the affected package, installed version, severity, source and fixed version 1.1.0.',
    why: 'An advisory describes a vulnerability. A Finding records its relevance to an assessment. Unknown reachability requires investigation before deciding whether it is exploitable.',
    expected: 'Eight DEMO advisories match dependencies that need upgrading. These are training records, not real CVEs.', ready: scanned },
  { id: 'licenses', chapter: 'Scan & triage', title: 'Review license results', focus: '#engagement-tabpanel', route: route(`/engagements/${INITIAL_ID}/licenses`), read: true,
    action: 'Review MIT, Apache-2.0 and BSD-3-Clause approvals, the GPL-3.0-only policy review and one package with missing license metadata.',
    why: 'License results are separate from vulnerability results. A dependency without known vulnerabilities may still need a licensing review.',
    expected: 'Eleven of twelve packages have identified licenses. Two records require review: copyleft obligations and missing provenance.', ready: scanned },
  { id: 'evidence', chapter: 'Scan & triage', title: 'Check the supporting evidence', focus: '#engagement-tabpanel', route: route(`/engagements/${INITIAL_ID}/evidence`), read: true,
    action: 'Open Evidence and select the artifact to download the demo scan log. Compare its branch, inventory and finding count with the recorded scan.',
    why: 'Evidence explains how a Finding was produced and supports later review. Hashes and chain verification are simulated here; the backend performs verification in a real installation.',
    expected: 'One DEMO scan log belongs to this assessment and supports the inventory and results.', ready: scanned },
  { id: 'triage', chapter: 'Scan & triage', title: 'Triage and assign a Finding', route: route(`/engagements/${INITIAL_ID}/findings`), anchor: 'All Findings',
    action: 'Open the checkout-parser Finding. Set its status to Confirmed, assign Admin User, and add a comment: “Verified against inventory. Upgrade checkout-parser to 1.1.0 and re-test.”',
    why: 'Triage records the reviewer’s decision. The Assignee owns the Finding; the Asset Owner owns the product. A manual Remediated status does not verify a fix.',
    expected: 'The Finding is Confirmed, assigned, and has a saved investigation note.', ready: s => Boolean(initial(s)?.findings.some(f => f.status === 'confirmed' && f.assignee && f.comments.length)) },
  { id: 'baseline', chapter: 'Scan & triage', title: 'Finalize the baseline Snapshot', route: route(`/engagements/${INITIAL_ID}/comparison`), anchor: 'Finalize snapshot',
    action: 'Open Comparison. Close Configure comparison if it is open. Select Finalize snapshot, include the completed scan run with Complete coverage, and confirm.',
    why: 'A Snapshot freezes the assessment results and provenance. It provides the baseline for checking remediation, without changing when new advisories arrive.',
    expected: 'The Initial assessment has finalized Snapshot 1.', ready: s => Boolean(initial(s)?.snapshotAt) },
  { id: 'complete-initial', chapter: 'Scan & triage', title: 'Complete the initial assessment', route: route(`/engagements/${INITIAL_ID}/settings`), anchor: 'Complete',
    action: 'Open Settings → Lifecycle and select Complete after finalizing the Snapshot.',
    why: 'A Completed assessment retains its results. Create a separate Re-test to assess the next revision and preserve the comparison history.',
    expected: 'The assessment is Completed, and Create Re-test is available while the Cycle remains Open.', ready: s => initial(s)?.status === 'completed' },
  { id: 'retest', chapter: 'Re-test & reporting', title: 'Create a Re-test in the same Cycle', route: route(`/engagements/${INITIAL_ID}`), anchor: 'Create Re-test',
    action: 'Select Create Re-test in Assessment lifecycle. Use Initial as the predecessor and Copy previous scope. Create the draft, then select Open Re-test.',
    why: 'A re-scan repeats work within an assessment. A Re-test creates a linked assessment to verify remediation. Copying scope does not copy execution permission or the scanner profile.',
    expected: 'Re-test 1 is a Draft in the same Cycle and cannot run yet.', ready: s => Boolean(retest(s)) },
  { id: 'retest-authorization', chapter: 'Re-test & reporting', title: 'Authorize the Re-test separately', route: route(`/engagements/${RETEST_ID}/settings`), anchor: 'Authorization window',
    action: 'Activate the Re-test. Save a current authorization window, allow SCA, and select Save RoE. Keep the same target and scope.',
    why: 'Each assessment needs its own execution authorization. Scope inheritance carries the assessment boundary, not the customer’s permission to run tools.',
    expected: 'The Re-test is Active with a valid window and SCA permission.', ready: s => authorized(retest(s)) },
  { id: 'retest-scan', chapter: 'Re-test & reporting', title: 'Scan the remediated revision', route: route(`/engagements/${RETEST_ID}`), anchor: 'Scan Settings',
    action: 'Review the prefilled Git + Full profile and branch remediated, then select Next to run the Re-test. The same core pipeline runs without repeating the initial setup walkthrough. Check Complete coverage before finalizing its Snapshot.',
    why: 'The remediated branch represents the updated source. An empty finding list verifies a fix only when scope and coverage are comparable with the baseline.',
    expected: 'Coverage is Complete. Twelve packages remain. All eighteen baseline findings are absent under comparable coverage, including source and configuration checks.', ready: rescanned },
  { id: 'retest-snapshot', chapter: 'Re-test & reporting', title: 'Finalize the Re-test Snapshot', route: route(`/engagements/${RETEST_ID}/comparison`), anchor: 'Finalize snapshot',
    action: 'Open Comparison. Close Configure comparison if necessary. Select Finalize snapshot and include the completed Re-test scan run.',
    why: 'Comparing immutable Snapshots retains the revision, engines and coverage of each assessment. Missing coverage must be classified as Not evaluated, rather than Fixed.',
    expected: 'Re-test Snapshot 1 records branch remediated with Complete coverage.', ready: s => Boolean(retest(s)?.snapshotAt) },
  { id: 'comparison', chapter: 'Re-test & reporting', title: 'Verify the remediation outcome', route: comparisonRoute, anchor: 'Configure comparison', focus: comparisonResultSelector,
    action: 'Select Configure comparison. Use Scan → re-scan lifecycle, Initial Snapshot 1 as the baseline, and Re-test Snapshot 1 as current. Run comparison and review the summary and all eighteen rows.',
    why: 'Fixed means the issue was not detected under comparable coverage. Review New, Still detected and Not evaluated alongside the fixes.',
    expected: 'Eighteen of eighteen findings are Fixed; New, Still detected and Not evaluated are all zero.', ready: s => Boolean(s.comparisonAt) },
  { id: 'complete-retest', chapter: 'Re-test & reporting', title: 'Complete the Re-test', route: route(`/engagements/${RETEST_ID}/settings`), anchor: 'Complete',
    action: 'Open Settings → Lifecycle and select Complete after reviewing the Snapshot and comparison.',
    why: 'Completing the Re-test finishes the verification assessment. Closing the Cycle is a separate decision after reviewing the full Initial → Re-test path.',
    expected: 'Both assessments are Completed. The Cycle remains Open for closure review.', ready: s => retest(s)?.status === 'completed' },
  { id: 'closure', chapter: 'Re-test & reporting', title: 'Review and close the Cycle', route: route(`/assessment-cycles/${CYCLE_ID}`), anchor: 'Review closure',
    action: 'Select Review closure. Enter “Verified eighteen fixes under comparable coverage”. Select Preview server policy, review the final assessment, Snapshots and comparison, then select Close from authoritative preview.',
    why: 'Closure seals the baseline-to-final assessment path. Intelligence can continue monitoring retained inventory without rewriting that historical result.',
    expected: 'The Cycle is Completed and its closure manifest references the correct assessments and comparison.', ready: s => Boolean(s.closure) },
  { id: 'report', chapter: 'Re-test & reporting', title: 'Download the sealed report', route: route(`/assessment-cycles/${CYCLE_ID}`), anchor: 'Download report',
    action: 'Select Download report in the closure history. The demo JSON report contains the Snapshots, comparison summary and retained inventory.',
    why: 'The closure report preserves the result at the time the Cycle was closed. This exercise returns an inspectable JSON report.',
    expected: 'The DEMO report records eighteen Fixed findings and retains checkout-token@2.0.0 in the final inventory.', ready: s => s.reportDownloaded },
  { id: 'intelligence-source', chapter: 'Intelligence & monitoring', title: 'Configure an Intelligence source', route: route('/vulnerability-intelligence?tab=sources'), anchor: 'Add source',
    action: 'Open Sources → Add source. Use key checkout-demo, name Checkout demo feed, OSV and https://checkout.example/advisories.json. Set cadence to 24 hours, stale threshold to 48 hours, Incremental and Enabled. Keep adapter config {} and credentials empty. Test connection, then Save source.',
    why: 'The source supplies advisories. Cadence controls synchronization; the stale threshold identifies old data. Intelligence evaluates retained inventory without cloning or scanning source again.',
    expected: 'The Enabled demo source is saved after a successful connection test. Connections are simulated in this playground.', ready: s => Boolean(s.source && s.connectionTested) },
  { id: 'initial-sync', chapter: 'Intelligence & monitoring', title: 'Synchronize and check source health', route: route('/vulnerability-intelligence?tab=sources'), anchor: 'Sync now',
    action: 'Select Sync now for your source, then open Sync runs. Check that the run succeeds; use Refresh if needed. The demo feed has not published the new advisory yet, so inserted is zero.',
    why: 'Test connection validates configuration; synchronization imports data. Successful, fresh synchronization is required before monitoring can use new advisories.',
    expected: 'The first run succeeds with no new advisory and no Asset notification.', ready: s => s.syncs.some(r => r.finishedAt && !r.feedPublished) },
  { id: 'notification-preference', chapter: 'Intelligence & monitoring', title: 'Enable in-app delivery', route: route('/inbox'), anchor: 'Delivery preferences',
    action: 'Open Notifications → Delivery preferences. Set vulnerability_action.created · in_app to Enabled.',
    why: 'Importing an advisory and delivering a notification are separate stages. This preference controls new Inbox notifications; other channels require their own configuration.',
    expected: 'The Enabled preference is saved. The Inbox is empty before the new advisory is imported.', ready: s => s.notificationPreference === 'enabled' },
  { id: 'publish', chapter: 'Intelligence & monitoring', title: 'Publish a new demo advisory', route: route('/vulnerability-intelligence?tab=sources'),
    action: 'Select Next to publish the advisory to the simulated feed. Synchronization will import it and deliver the matching notification in the following steps.',
    why: 'checkout-token@2.0.0 remains in retained inventory after closure. DEMO-CHECKOUT-004 affects that version and identifies 2.0.1 as the fix.',
    expected: 'The feed contains a new advisory, while the Inbox and historical scan results are unchanged.', ready: s => s.feedPublished },
  { id: 'monitor-sync', chapter: 'Intelligence & monitoring', title: 'Import the advisory and match inventory', route: route('/vulnerability-intelligence?tab=sources'), anchor: 'Sync now',
    action: 'Select Sync now again. Open Sync runs and wait for Succeeded; use Refresh if needed. Check one inserted advisory and the notification badge.',
    why: 'The path is feed publication → source synchronization → package/version match → exposure/action → Inbox delivery. Manual synchronization lets you test it without waiting for the 24-hour cadence.',
    expected: 'One advisory matches checkout-token@2.0.0 and produces one notification. Historical Snapshots and the closure report stay unchanged.', ready: s => Boolean(s.correlatedAt) },
  { id: 'inbox', chapter: 'Intelligence & monitoring', title: 'Open the alert and investigate', route: route('/inbox'), anchor: 'Open',
    action: 'Open Notifications. Read the DEMO message and select Open. Select checkout-token in Affected inventory to review installed version 2.0.0, fixed version 2.0.1 and the source assessment.',
    why: 'An inventory match starts an investigation. The owner or assignee still needs to assess reachability, plan the upgrade, and verify it in a new assessment.',
    expected: 'The notification is read, and the advisory identifies the matching package/version from the Re-test inventory.', ready: s => Boolean(s.monitorInvestigated && s.notificationReadAt) },
  { id: 'finish', chapter: 'Intelligence & monitoring', title: 'One complete assessment loop', route: route(`/vulnerability-intelligence/advisories/${DEMO_ADVISORY}`), read: true,
    action: 'Review the result: an owned Asset, an authorized scan, a triaged Finding, a Re-test confirming eighteen fixes, a sealed report and a new Intelligence notification.',
    why: 'For a new alert, involve the Asset Owner, assign remediation, and start the next assessment under your process. A closed Cycle preserves history; it does not describe every current risk.',
    expected: 'You have completed the core workflow. Continue exploring the console or return to the overview tour.', ready: s => Boolean(s.asset && initial(s)?.status === 'completed' && retest(s)?.status === 'completed' && s.closure && s.reportDownloaded && s.correlatedAt && s.monitorInvestigated) },
]

export const scanStepRoute = (s: Scenario) => SCAN_STEPS[Math.min(s.step, SCAN_STEPS.length - 1)].route(s)
