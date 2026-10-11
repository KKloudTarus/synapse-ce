import { CORE_PHASES } from './scenario/catalog'
import { phaseCompleted } from './scenario/data'
import { comparisonResultSelector, SCAN_STEPS, type ScanStep } from './scan-steps'
import { DEMO_ADVISORY, INITIAL_ID, RETEST_ID, TARGET, initial, retest, type Scenario } from './scenario/store'

export type GuideTarget = { kind: 'field' | 'button' | 'text' | 'selector'; name: string }
export interface GuideAction<S = Scenario> {
  title: string; body: string; why: string; target?: GuideTarget
  done: (s: S, doc: Document) => boolean
  auto?: boolean
  pipeline?: string
  route?: string
  example?: { value?: string | ((s: S) => string); choice?: string; checked?: boolean; file?: { name: string; content: string; type: string } }
  prefill?: { target: GuideTarget; example: NonNullable<GuideAction<S>['example']> }[]
}
const normalize = (s: string) => s.replace(/\s+/g, ' ').trim().toLowerCase()
export function findGuideTarget(target: GuideTarget | undefined, doc = document): HTMLElement | null {
  if (!target) return null
  const selector = target.kind === 'selector' ? target.name : target.kind === 'field' ? 'input, textarea, select, [role="combobox"], [role="radiogroup"]' : target.kind === 'button' ? 'button, a, [role="button"]' : 'h1, h2, h3, h4, label, [role="region"]'
  const candidates = [...doc.querySelectorAll<HTMLElement>(selector)].filter(el => !el.closest('[data-guided-demo], [aria-hidden="true"], [inert], [hidden]') && el.getClientRects().length > 0)
  // The active dialog takes precedence over controls with the same name behind it.
  candidates.sort((a, b) => Number(Boolean(b.closest('[role="dialog"]'))) - Number(Boolean(a.closest('[role="dialog"]'))))
  if (target.kind === 'selector') return candidates[0] ?? null
  const wanted = normalize(target.name)
  const names = (el: HTMLElement) => {
    const labels = [...doc.querySelectorAll('label')].filter(l => l.contains(el) || Boolean(el.id) && l.htmlFor === el.id).map(l => l.textContent ?? '').join(' ')
    const labelledBy = (el.getAttribute('aria-labelledby') ?? '').split(' ').map(id => doc.getElementById(id)?.textContent ?? '').join(' ')
    return [el.getAttribute('aria-label') ?? '', labels, labelledBy, target.kind === 'field' ? '' : el.textContent ?? ''].map(normalize)
  }
  return candidates.find(el => names(el).includes(wanted)) ?? candidates.find(el => names(el).some(name => name.startsWith(`${wanted} `) || target.kind === 'button' && name.startsWith(wanted))) ?? null
}
const fieldValue = (target: GuideTarget, doc: Document) => {
  const el = findGuideTarget(target, doc)
  return el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement ? el.value.trim() : el?.textContent?.trim() ?? ''
}
const field = (name: string, body: string, why: string, valid: (v: string) => boolean = v => Boolean(v)): GuideAction => {
  const target: GuideTarget = { kind: 'field', name }
  return { title: name, body, why, target, done: (_, doc) => valid(fieldValue(target, doc)) }
}
const inspect = (name: string, body: string, why: string, kind: GuideTarget['kind'] = 'field'): GuideAction => ({ title: name, body, why, target: { kind, name }, done: (_, doc) => Boolean(findGuideTarget({ kind, name }, doc)) })
const inspectRegion = (title: string, selector: string, body: string, why: string): GuideAction => ({ title, body, why, target: { kind: 'selector', name: selector }, done: (_, doc) => Boolean(findGuideTarget({ kind: 'selector', name: selector }, doc)) })
const click = (name: string, body: string, why: string, done: GuideAction['done'], auto = true): GuideAction => ({ title: name, body, why, target: { kind: 'button', name }, done, auto })
const shown = (name: string, kind: GuideTarget['kind'] = 'field') => (_: Scenario, doc: Document) => Boolean(findGuideTarget({ kind, name }, doc))
const exact = (value: string) => (v: string) => normalize(v) === normalize(value)
const finding = (s: Scenario) => initial(s)?.findings[0]

function authorization(id: string): GuideAction[] {
  const assessment = (s: Scenario) => id === INITIAL_ID ? initial(s) : retest(s)
  return [
    click('Activate', 'Select Activate to begin this assessment.', 'Activation changes lifecycle status. Scope, time and tool permission still need to be configured.', s => assessment(s)?.status === 'active'),
    field('Authorization window start', 'Set the start to yesterday, using local time.', 'The start establishes when execution is permitted.', v => Boolean(v) && Date.parse(v) < Date.now()),
    field('Authorization window end', 'Set the end to tomorrow, using local time.', 'The end limits the authorization period. An expired assessment cannot run.', v => Boolean(v) && Date.parse(v) > Date.now()),
    field('Authorization window timezone', 'Use your IANA timezone, or UTC for this exercise.', 'The timezone makes the agreed execution window unambiguous.'),
    click('Save window', 'Select Save window to retain these dates.', 'Permission uses the saved window, rather than unsaved form values.', s => Boolean(assessment(s)?.authorizedFrom && Date.parse(assessment(s)!.authorizedFrom) < Date.now() && Date.parse(assessment(s)!.authorizedTo) > Date.now())),
    { ...inspect('Allow sca tools', 'Enable SCA in Rules of engagement.', 'SCA evaluates source dependencies. This permission does not authorize live testing.', 'button'), done: (_, doc) => findGuideTarget({ kind: 'button', name: 'Allow sca tools' }, doc)?.getAttribute('aria-pressed') === 'true' },
    click('Save RoE', 'Select Save RoE to save the allowed tool class.', 'Each assessment has its own execution permission.', s => Boolean(assessment(s)?.tools.includes('sca'))),
  ]
}
function scan(id: string): GuideAction[] {
  const assessment = (s: Scenario) => id === INITIAL_ID ? initial(s) : retest(s)
  const branch = id === INITIAL_ID ? 'main' : 'remediated'
  const verification: Record<string, string> = {
    'scanning vulnerabilities': 'The upgraded package versions are checked against the same advisory set. None of the eight baseline dependency advisories match this revision.',
    'analyzing source': 'The same source analysis evaluates the remediated revision. The four baseline source issues are no longer detected.',
    'scanning secrets': 'The redacted training placeholders have been removed. Secret scanning records no findings under comparable coverage.',
    'scanning configuration': 'Restricted storage access and a hardened container configuration address the two baseline IaC findings.',
    'scanning licenses': 'The two dependencies needing review now have approved MIT license metadata. All twelve packages have identified licenses.',
    'deriving findings': 'The Re-test retains twelve packages, zero findings and Complete engine coverage. The finalized Snapshot will supply evidence for comparison with the eighteen baseline findings.',
  }
  return [
    click('Scan settings', 'Open Scan settings.', 'A scan profile selects the source revision and analysis scope.', shown('Git branch')),
    { ...inspect('Target kind', 'Keep Git selected for this exercise.', 'Git identifies a source repository. The training repository is simulated locally.'), done: (_, doc) => findGuideTarget({ kind: 'field', name: 'Target kind' }, doc)?.querySelector('[role="radio"][aria-checked="true"]')?.textContent?.trim() === 'Git' },
    field('Scan target', `Use ${TARGET}.`, 'The scan target must be inside the assessment scope.', exact(TARGET)),
    field('Git branch', `Enter ${branch}.`, id === INITIAL_ID ? 'main contains eighteen dependency, source, secret, configuration and license findings.' : 'remediated contains the dependency upgrades, source fixes and configuration changes.', exact(branch)),
    { ...inspect('Scan mode', 'Keep Full selected.', 'Full retains inventory, vulnerability and license results, so the two assessments have comparable coverage.'), done: (_, doc) => findGuideTarget({ kind: 'field', name: 'Scan mode' }, doc)?.querySelector('[role="radio"][aria-checked="true"]')?.textContent?.trim() === 'Full' },
    { ...inspect('Include Static Code Quality Analysis', 'Leave static code quality off for this exercise.', 'The core security scan includes SCA, SAST, secrets, infrastructure configuration and licenses. Static code quality is an additional analysis that can be explored separately.', 'selector'), target: { kind: 'selector', name: '[role="dialog"] input[type="checkbox"]' }, done: (_, doc) => { const el = findGuideTarget({ kind: 'selector', name: '[role="dialog"] input[type="checkbox"]' }, doc); return el instanceof HTMLInputElement && !el.checked } },
    click('Save & Run scan', 'Select Next to start the scan and follow each core phase.', 'The guide follows the simulated execution and waits for finalized results before continuing.', s => Boolean(assessment(s)?.scan)),
    ...CORE_PHASES.map((phase, index): GuideAction => ({ title: phase.title, body: 'Review this phase in the Pipeline Journey Track, then select Next when it completes.', why: id === RETEST_ID ? verification[phase.stage] ?? phase.why : phase.why, pipeline: phase.stage, target: { kind: 'selector', name: '[data-scan-inspector]' }, done: s => phaseCompleted(assessment(s), index) })),
  ]
}
function snapshot(id: string): GuideAction[] {
  return [
    click('Finalize snapshot', 'Select Finalize snapshot. Close Configure comparison first if it is open.', 'A finalized Snapshot retains the assessment results and scan provenance.', shown(`Include scan run ${id}-run-1`)),
    { ...inspect(`Include scan run ${id}-run-1`, 'Include the completed run with Complete coverage.', 'The selected run supplies the immutable results for comparison.'), title: 'Select the scan run', done: (_, doc) => { const el = findGuideTarget({ kind: 'field', name: `Include scan run ${id}-run-1` }, doc); return el instanceof HTMLInputElement && el.checked } },
    click('Finalize snapshot', 'Confirm Finalize snapshot in the dialog.', 'Finalization preserves this revision independently of later Intelligence updates.', s => Boolean((id === INITIAL_ID ? initial(s) : retest(s))?.snapshotAt)),
  ]
}
function retestScan(): GuideAction[] {
  return [
    click('Scan settings', 'Open the Re-test scan profile.', 'The initial walkthrough covered the scan controls. Review the updated revision and keep the same scope and analysis mode.', shown('[role="dialog"][aria-labelledby="scan-config-modal-title"]', 'selector')),
    {
      title: 'Review the remediated revision', body: 'Git and Full mode are prefilled for the same repository. Review branch remediated, then continue.', why: 'Comparable scope and engines let the comparison evaluate the eighteen baseline findings. The source revision changes; execution still uses the Re-test authorization.',
      target: { kind: 'field', name: 'Git branch' }, example: { value: 'remediated' },
      prefill: [
        { target: { kind: 'field', name: 'Target kind' }, example: { choice: 'Git' } },
        { target: { kind: 'field', name: 'Scan target' }, example: { value: TARGET } },
        { target: { kind: 'field', name: 'Scan mode' }, example: { choice: 'Full' } },
        { target: { kind: 'selector', name: '[role="dialog"] input[type="checkbox"]' }, example: { checked: false } },
      ],
      done: (_, doc) => fieldValue({ kind: 'field', name: 'Git branch' }, doc) === 'remediated' && fieldValue({ kind: 'field', name: 'Scan target' }, doc) === TARGET &&
        findGuideTarget({ kind: 'field', name: 'Target kind' }, doc)?.querySelector('[aria-checked="true"]')?.textContent?.trim() === 'Git' &&
        findGuideTarget({ kind: 'field', name: 'Scan mode' }, doc)?.querySelector('[aria-checked="true"]')?.textContent?.trim() === 'Full' &&
        findGuideTarget({ kind: 'selector', name: '[role="dialog"] input[type="checkbox"]' }, doc)?.matches(':not(:checked)') === true,
    },
    click('Save & Run scan', 'Select Next to run the remediated revision.', 'The Re-test executes the same core security pipeline. Its results remain separate from the Initial assessment.', s => Boolean(retest(s)?.scan)),
    { title: 'Verify Re-test coverage', body: 'Wait for the scan to finish, then review the finalized results and Complete engine coverage.', why: 'The Re-test retains twelve packages with zero findings. Complete coverage is required before absence can support a Fixed outcome.', pipeline: 'deriving findings', target: { kind: 'selector', name: '[data-scan-inspector]' }, done: s => Boolean(retest(s)?.scan?.finishedAt) },
  ]
}
const actions: Record<string, GuideAction[]> = {
  asset: [
    click('New Asset', 'Select New Asset to create the product you will assess.', 'An Asset connects ownership and assessment history across revisions.', shown('Key')),
    field('Key', 'Enter checkout-api.', 'The Key is a stable identifier used in URLs. Use lowercase letters, digits and hyphens.', v => /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(v)),
    field('Name', 'Enter Checkout API.', 'Name is the display label used throughout the console.'),
    field('Owner', 'Enter Checkout Team.', 'The Owner is responsible for the product. A Finding Assignee is responsible for an individual issue.'),
    field('Type', 'Keep Application selected.', 'Type classifies the business object. Application fits the API in this exercise.', exact('Application')),
    field('Criticality', 'Select High.', 'Criticality describes business importance. A payment service outage affects revenue; vulnerability severity is assessed separately.', exact('High')),
    field('Description', 'Enter: Payment service for checkout transactions.', 'Description gives reviewers business context. The repository target is configured in the assessment.'),
    click('Create Asset', 'Select Create Asset to save the product and its ownership.', 'The next step links an Initial assessment to this Asset.', s => Boolean(s.asset)),
  ],
  engagement: [
    inspect('Assessment purpose', 'Keep Initial assessment selected.', 'An Initial assessment starts a new Cycle. Its Snapshot becomes the baseline for a later Re-test.'),
    field('Name', 'Enter Checkout API · Initial.', 'The name identifies this assessment of the product.'),
    field('Client', 'Enter Demo Company.', 'Client provides customer context for the assessment.'),
    inspect('Asset', 'Confirm that Checkout API is selected.', 'Linking the Asset preserves product ownership and assessment history.'),
    inspect('Engagement source', 'Keep Linked target selected.', 'A linked target identifies the repository to assess without uploading an archive.'),
    field('Target kind for row 1', 'Select Repo.', 'The target kind describes how this scope entry should be interpreted.', exact('Repo')),
    field('Target value for row 1', `Enter ${TARGET}.`, 'In-scope targets define the permitted boundary. Exclusions take precedence. This .example repository is a local training fixture.', exact(TARGET)),
    click('Create Engagement', 'Select Create Engagement to save the Initial assessment.', 'The new assessment starts as Draft, with no scan or findings.', s => Boolean(initial(s))),
  ],
  authorization: authorization(INITIAL_ID),
  scan: scan(INITIAL_ID),
  packages: [
    inspectRegion('Recorded package inventory', '[data-package-summary]', 'The page has moved to Packages. Review the package count and license coverage.', 'Twelve packages were resolved from three lockfiles. This retained inventory is the basis for advisory matching and Intelligence monitoring.'),
    inspectRegion('Package identity', '[data-package-name="checkout-parser"]', 'Review checkout-parser in the highlighted row.', 'A package name identifies the dependency. Its recorded version and ecosystem determine which advisory applies.'),
    inspectRegion('Installed version', '[data-package-inventory] [role="row"]:has([data-package-name="checkout-parser"]) [role="cell"]:nth-child(2)', 'Review the pinned version 1.0.0.', 'The installed version is evidence from this revision. A fix version is an upgrade target, not the version currently deployed.'),
    inspectRegion('Package URL', '[data-package-inventory] [role="row"]:has([data-package-name="checkout-parser"]) [role="cell"]:nth-child(4)', 'Review pkg:npm/checkout-parser@1.0.0.', 'The PURL combines ecosystem, package identity and version. Python and Go packages use their own ecosystems and lockfiles.'),
    inspectRegion('Retained package for monitoring', '[data-package-inventory] [role="row"]:has([data-package-name="checkout-token"])', 'Review checkout-token@2.0.0 in this row.', 'This dependency has no baseline advisory. It remains after remediation and will match a newly published advisory in the monitoring example.'),
  ],
  triage: [
    { ...inspect('Filter findings by kind', 'Review all eighteen findings before selecting an issue.', 'The scan produced eight dependency advisories, four SAST issues, two secret findings, two IaC findings and two license reviews. Severity spans Critical to Low.'), title: 'Review the core scan results' },
    ...[
      { label: 'SAST', title: 'Review source findings', why: 'Four source issues retain CWE classifications and file locations. Review the data handling boundary before choosing a fix.' },
      { label: 'Secret', title: 'Review credential findings', why: 'Two redacted credential-like placeholders are reported. A real exposure requires revocation and rotation, plus removal from the source.' },
      { label: 'Misconfig', title: 'Review infrastructure findings', why: 'Public storage access and privileged execution are configuration risks. Their evidence comes from Terraform and Kubernetes files.' },
      { label: 'License', title: 'Review license findings', why: 'Copyleft obligations and missing provenance require an ownership and policy decision, independently of security severity.' },
      { label: 'All Kinds', title: 'Return to all findings', why: 'Restore the full result list before triaging the dependency issue. The other findings remain available for review.' },
    ].map(({ label, title, why }): GuideAction => ({ ...field('Filter findings by kind', 'Review the highlighted category, then select Next.', why, exact(label)), title, example: { choice: label } })),
    { ...click('Toggle details for checkout-parser: simulated vulnerable dependency (DEMO-CHECKOUT-001)', 'Open the checkout-parser Finding.', 'The Finding records this advisory’s relevance to the Initial assessment.', shown('New comment')), title: 'Open the Finding' },
    { ...field('Triage status for checkout-parser: simulated vulnerable dependency (DEMO-CHECKOUT-001)', 'Set the status to Confirmed.', 'Triage records the reviewer’s decision. A manually assigned Remediated status does not verify a fix.'), title: 'Confirm the Finding', done: s => finding(s)?.status === 'confirmed' },
    click('Admin User (user-001)', 'Select Admin User in the Assignee list.', 'The Assignee owns this Finding’s investigation and remediation.', s => Boolean(finding(s)?.assignee)),
    field('New comment', 'Enter: Verified against inventory. Upgrade checkout-parser to 1.1.0 and re-test.', 'An investigation note records the evidence and the planned next action.'),
    click('Post', 'Select Post to save the investigation note.', 'Saved notes give the next reviewer the reasoning behind the triage decision.', s => Boolean(finding(s)?.comments.length)),
  ],
  baseline: snapshot(INITIAL_ID),
  'complete-initial': [click('Complete', 'Select Complete in Lifecycle.', 'The finalized baseline remains available. The next revision is assessed in a separate Re-test.', s => initial(s)?.status === 'completed')],
  retest: [
    click('Create Re-test', 'Select Create Re-test in Assessment lifecycle.', 'A Re-test creates a linked assessment to verify remediation.', shown('Based on Assessment')),
    inspect('Based on Assessment', 'Keep Initial selected as the predecessor.', 'The predecessor connects this verification to the baseline assessment.'),
    field('Assessment scope', 'Keep Copy previous scope selected.', 'Comparable scope supports a meaningful comparison. Copying scope does not copy execution permission.', exact('Copy previous scope')),
    click('Create Re-test', 'Select Create Re-test in the dialog.', 'The Re-test starts as Draft in the same Cycle.', s => Boolean(retest(s))),
  ],
  'retest-authorization': authorization(RETEST_ID),
  'retest-scan': retestScan(),
  'retest-snapshot': snapshot(RETEST_ID),
  comparison: [
    click('Configure comparison', 'Open Configure comparison.', 'Comparison evaluates the Initial and Re-test Snapshots under their recorded coverage.', shown('Comparison mode')),
    field('Comparison mode', 'Use Scan → re-scan lifecycle.', 'This mode compares the linked assessment history.', exact('Scan → re-scan lifecycle')),
    field('Comparison result scope', 'Select All findings.', 'Result scope selects the type of result being compared.', exact('All findings')),
    inspect('Baseline assessment', 'Select Initial as the baseline assessment.', 'The baseline contains the eighteen original Findings.'),
    inspect('Baseline snapshot', 'Select Initial Snapshot 1.', 'A finalized Snapshot fixes the baseline results and provenance.'),
    inspect('Current snapshot', 'Select Re-test Snapshot 1.', 'The current Snapshot records the remediated branch and complete coverage.'),
    click('Run comparison', 'Select Next to run comparison. Wait for the summary and compared findings to appear.', 'Fixed requires comparable coverage. Missing evaluation is classified as Not evaluated.', (s, doc) => Boolean(s.comparisonAt && findGuideTarget({ kind: 'selector', name: comparisonResultSelector }, doc))),
  ],
  'complete-retest': [click('Complete', 'Select Complete in Lifecycle.', 'Completing the Re-test finishes verification. Cycle closure is a separate review decision.', s => retest(s)?.status === 'completed')],
  closure: [
    click('Review closure', 'Select Review closure.', 'Closure seals the path from the baseline to the final assessment.', shown('Closure reason')),
    field('Closure reason', 'Enter: Verified eighteen fixes under comparable coverage.', 'The reason records why the Cycle is ready to close.'),
    click('Preview server policy', 'Select Preview server policy and review the assessment path.', 'The authoritative preview checks the final assessment, Snapshots and comparison.', s => Boolean(s.preview)),
    click('Close from authoritative preview', 'Select Close from authoritative preview.', 'Closure retains a historical result while Intelligence continues monitoring the inventory.', s => Boolean(s.closure)),
  ],
  report: [click('Download report', 'Select Download report in the closure history.', 'The demo JSON report preserves the Snapshots, eighteen verified fixes and the retained inventory.', s => s.reportDownloaded)],
  'intelligence-source': [
    click('Add source', 'Select Add source.', 'An Intelligence source supplies advisories for evaluating retained inventory.', shown('Source key')),
    field('Source key', 'Enter checkout-demo.', 'The key is a stable identifier for this advisory feed.'),
    field('Source name', 'Enter Checkout demo feed.', 'The name identifies the feed in Sources and Sync runs.'),
    field('Source adapter', 'Keep OSV selected.', 'The adapter interprets the provider’s advisory format.', exact('osv')),
    field('Source endpoint', 'Enter https://checkout.example/advisories.json.', 'This endpoint is a simulated feed. No connection leaves your browser.', exact('https://checkout.example/advisories.json')),
    field('Cadence hours', 'Set the cadence to 24 hours.', 'Cadence controls how frequently the source synchronizes.', exact('24')),
    field('Stale threshold hours', 'Set the stale threshold to 48 hours.', 'This threshold marks source data as stale when successful synchronization is overdue.', exact('48')),
    field('Default sync mode', 'Keep Incremental selected.', 'Incremental imports feed updates. Full synchronization can be explored separately.', exact('Incremental')),
    field('Adapter configuration', 'Keep the configuration as {}.', 'The adapter’s optional configuration is empty for this exercise.', exact('{}')),
    field('Credential reference', 'Leave the credential reference empty.', 'Credential references identify secrets managed outside the console. This demo requires no credentials.', exact('')),
    { ...inspect('Enabled', 'Keep Enabled checked.', 'An Enabled source can synchronize and evaluate advisory matches.'), done: (_, doc) => { const el = findGuideTarget({ kind: 'field', name: 'Enabled' }, doc); return el instanceof HTMLInputElement && el.checked } },
    click('Test connection', 'Select Test connection.', 'A connection test validates configuration. It does not save the source or import advisories.', s => s.connectionTested),
    click('Save source', 'Select Save source.', 'Saving retains the source configuration for synchronization.', s => Boolean(s.source)),
  ],
  'initial-sync': [click('Sync now', 'Select Sync now and wait for completion. You can review the run in Sync runs.', 'Synchronization imports feed data. The new advisory has not been published yet, so this run inserts zero advisories.', s => s.syncs.some(r => r.finishedAt && !r.feedPublished))],
  'notification-preference': [{ ...field('vulnerability_action.created in_app', 'Select Enabled for in-app delivery.', 'Importing an advisory and delivering an Inbox notification are separate stages.'), done: s => s.notificationPreference === 'enabled' }],
  'monitor-sync': [click('Sync now', 'Select Sync now again, then wait for completion.', 'The new advisory is imported and matched to checkout-token@2.0.0 in retained inventory.', s => Boolean(s.correlatedAt))],
  inbox: [
    click('Open', 'Read the new DEMO notification, then select Open.', 'An inventory match starts an investigation and links to the relevant advisory.', s => Boolean(s.notificationReadAt)),
    { title: 'Affected inventory', body: 'Select checkout-token in Affected inventory.', why: 'Review installed version 2.0.0, fixed version 2.0.1 and the source assessment before planning remediation.', target: { kind: 'button', name: 'checkout-token' }, route: `/vulnerability-intelligence/advisories/${DEMO_ADVISORY}`, done: s => s.monitorInvestigated, auto: true },
  ],
}

const localDate = (days: number) => () => {
  const date = new Date()
  date.setDate(date.getDate() + days)
  date.setHours(days < 0 ? 9 : 18, 0, 0, 0)
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16)
}
const windowExamples: Record<string, GuideAction['example']> = {
  'Authorization window start': { value: localDate(-1) },
  'Authorization window end': { value: localDate(1) },
  'Authorization window timezone': { value: () => Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' },
  'Allow sca tools': { checked: true },
}
const scanExamples: Record<string, GuideAction['example']> = {
  'Target kind': { choice: 'Git' }, 'Scan target': { value: TARGET },
  'Scan mode': { choice: 'Full' }, '[role="dialog"] input[type="checkbox"]': { checked: false },
}
const examples: Record<string, Record<string, GuideAction['example']>> = {
  asset: {
    Key: { value: 'checkout-api' }, Name: { value: 'Checkout API' }, Owner: { value: 'Checkout Team' },
    Type: { choice: 'Application' }, Criticality: { choice: 'High' }, Description: { value: 'Payment service for checkout transactions.' },
  },
  engagement: {
    Name: { value: 'Checkout API · Initial' }, Client: { value: 'Demo Company' },
    'Target kind for row 1': { choice: 'Repo' }, 'Target value for row 1': { value: TARGET },
  },
  authorization: windowExamples, 'retest-authorization': windowExamples,
  scan: { ...scanExamples, 'Git branch': { value: 'main' } },
  triage: {
    'Triage status for checkout-parser: simulated vulnerable dependency (DEMO-CHECKOUT-001)': { choice: 'Confirmed' },
    'New comment': { value: 'Verified against inventory. Upgrade checkout-parser to 1.1.0 and re-test.' },
  },
  baseline: { [`Include scan run ${INITIAL_ID}-run-1`]: { checked: true } },
  'retest-snapshot': { [`Include scan run ${RETEST_ID}-run-1`]: { checked: true } },
  retest: { 'Assessment scope': { choice: 'Copy previous scope' } },
  comparison: { 'Comparison mode': { choice: 'Scan → re-scan lifecycle' }, 'Comparison result scope': { choice: 'All findings' } },
  closure: { 'Closure reason': { value: 'Verified eighteen fixes under comparable coverage.' } },
  'intelligence-source': {
    'Source key': { value: 'checkout-demo' }, 'Source name': { value: 'Checkout demo feed' },
    'Source adapter': { value: 'osv' }, 'Source endpoint': { value: 'https://checkout.example/advisories.json' },
    'Cadence hours': { value: '24' }, 'Stale threshold hours': { value: '48' },
    'Default sync mode': { choice: 'Incremental' }, 'Adapter configuration': { value: '{}' },
    'Credential reference': { value: '' }, Enabled: { checked: true },
  },
  'notification-preference': { 'vulnerability_action.created in_app': { value: 'enabled' } },
}

export function guidedActions(step: ScanStep): GuideAction[] {
  const review: GuideAction = { title: step.title, body: step.read || step.id === 'publish' ? step.action : step.expected, why: step.why, target: step.focus ? { kind: 'selector', name: step.focus } : undefined, done: (s, doc) => step.ready(s) && (!step.focus || Boolean(findGuideTarget({ kind: 'selector', name: step.focus }, doc))) }
  return [...actions[step.id] ?? [], review].map(action => {
    const example = examples[step.id]?.[action.target?.name ?? '']
    return example ? { ...action, example, body: 'Review the highlighted example, then select Next.' } : action
  })
}
export const GUIDED_ACTION_COUNT = SCAN_STEPS.reduce((count, step) => count + guidedActions(step).length, 0)
