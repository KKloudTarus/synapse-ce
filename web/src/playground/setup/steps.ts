import type { AdvancedStep } from '../advanced/steps'
import { findGuideTarget } from '../guided-actions'
import { DEMO_SECRET, REVIEW_GOAL, setupStore } from './store'
const ai = '/demo/setup/ai', ci = '/settings/integrations/ci', intro = '/demo/setup/ci', agent = '/engagements/eng-001/agent', conn = '/settings/connectors'
const state = () => setupStore.getSnapshot()
const connection = (provider: string) => state().connections.find(c => c.provider === provider)
const operation = (type: string) => state().operations.some(o => o.integration_id === connection('jenkins')?.id && o.type === type && o.state === 'succeeded')
const read = (route: string, title: string, body: string, why: string, selector = 'main'): AdvancedStep => ({ chapter: 'Setup & verification', route, title, body, why, target: { kind: 'selector', name: selector }, done: (_, doc) => Boolean(findGuideTarget({ kind: 'selector', name: selector }, doc)) })
const field = (route: string, name: string, value: string, why: string, form?: AdvancedStep['form'], choice = false): AdvancedStep => ({ ...read(route, name, 'Review the prefilled example, then select Next.', why), target: { kind: 'field', name }, example: choice ? { choice: value } : { value }, form, done: (_, doc) => { const el = findGuideTarget({ kind: 'field', name }, doc); return el instanceof HTMLInputElement ? el.value === value : el?.textContent?.trim().startsWith(value) === true } })
const click = (route: string, name: string, why: string, done: AdvancedStep['done'], form?: AdvancedStep['form']): AdvancedStep => ({ ...read(route, name, 'Next performs the highlighted action for you.', why), target: { kind: 'button', name }, auto: true, done, form })
const sim = (route: string, title: string, path: string, why: string, done: AdvancedStep['done']): AdvancedStep => ({ ...read(route, title, 'Next records this browser-local training checkpoint.', why), perform: { path }, done })
export const AI_SETUP_STEPS: AdvancedStep[] = [
  read(ai, 'Understand the three capabilities', 'AI Agent, AI Triage and Fleet Agent serve different purposes.', 'Set up the capability you need before reviewing its output.', '[data-setup="capabilities"]'),
  read(ai, 'Review the deployment prerequisites', 'Provider identity, approved model and credential are configured by an administrator.', 'This is an explanatory preview, not a production configuration form.', '[data-setup="configuration"]'),
  read(agent, 'Inspect blocked readiness', 'The console identifies missing provider configuration while retained evidence remains available.', 'A missing prerequisite must be visible before starting a session.', '[data-agent-readiness]'),
  sim(agent, 'Record the readiness check', '/playground/setup/ai-ready', 'The simulated configuration check succeeds. No credential is saved and no model is contacted.', () => state().aiReady),
  read(agent, 'Verify ready status', 'Review the provider, manual review policy and retained-evidence scope.', 'Ready describes the prerequisites for this example; it is not a finding verdict.', '[data-agent-readiness]'),
  field(agent, 'Agent goal', REVIEW_GOAL, 'Use the bounded review example. It summarizes evidence already recorded in the assessment.', 'agent-review'),
  click(agent, 'Start agent', 'Record a synthetic evidence review with a completed transcript and zero model tokens.', () => Boolean(state().aiRecordedAt), 'agent-review'),
  click(agent, REVIEW_GOAL, 'Open the saved session to inspect the actual result.', (_, doc) => doc.body.textContent?.includes('Synthetic review of retained evidence.') === true),
  read(agent, 'Review the retained transcript', 'The summary prioritizes findings, assigns remediation responsibility and requires comparable re-test evidence.', 'A completed AI session does not accept a proposal or close a finding. Continue to human review.'),
  { ...read(agent, 'AI Setup & Readiness complete', 'You reviewed prerequisites, resolved a simulated readiness blocker and inspected a saved evidence review.', 'Continue to AI Review to compare independent evidence and record human decisions.'), finish: true },
]
export const CI_SETUP_STEPS: AdvancedStep[] = [
  read(intro, 'Separate source access from CI delivery', 'A private-repository connector and a CI/CD integration have different responsibilities.', 'The repository credential allows source acquisition; polling and inbound delivery connect analysis to development activity.', '[data-setup="connections"]'),
  field(conn, 'Name', 'GitHub source access', 'Give the source credential a recognizable name.', 'source-connector'),
  field(conn, 'Host', 'github.com', 'The host must match the persisted Project source. This sample uses GitHub.', 'source-connector'),
  field(conn, 'Personal access token', DEMO_SECRET, 'This visible example is invalid outside the demo. The handler stores metadata only.', 'source-connector'),
  click(conn, 'Add connector', 'Save the connector metadata; the token is not returned or retained in browser storage.', () => state().connectors.length > 0, 'source-connector'),
  read(conn, 'Verify source access metadata', 'Review GitHub source access and its host. The token has been cleared from the form.', 'For a private deployment, provision repository read access with the minimum required permission.'),
  click(ci, 'Add integration', 'Start with Jenkins: read existing pipelines and builds without triggering them.', (_, doc) => Boolean(doc.querySelector('#integration-name'))),
  field(ci, 'Display name', 'Jenkins build evidence', 'This connection records existing build evidence.', 'jenkins'),
  field(ci, 'HTTPS endpoint', 'https://ci.example', 'The demo origin is simulated. Real integrations require a valid approved HTTPS endpoint.', 'jenkins'),
  field(ci, 'Username', 'demo-reader', 'Use a read-only integration identity.', 'jenkins'),
  field(ci, 'API token', DEMO_SECRET, 'The sample token is invalid and discarded after save.', 'jenkins'),
  click(ci, 'Create integration', 'The connection starts disabled until a successful test is recorded.', () => Boolean(connection('jenkins')?.credential_configured), 'jenkins'),
  click(ci, 'Test connection', 'Verify the credential and endpoint before enabling this connection.', () => operation('test')),
  click(ci, 'Discover', 'Read the available pipelines. Discovery creates no build.', () => operation('discover')),
  field(ci, 'Discovered pipeline', 'Synapse CE / main (pipeline)', 'Select the exact pipeline whose existing builds should be read.', undefined, true),
  field(ci, 'Synapse Project', 'Synapse CE', 'A binding associates pipeline runs with one Project.', undefined, true),
  click(ci, 'Bind', 'Persist the pipeline-to-Project relationship.', () => state().bindings.some(b => b.integration_id === connection('jenkins')?.id), 'pipeline-binding'),
  click(ci, 'Enable', 'Enable the tested connection. Scheduled polling still depends on deployment configuration.', () => Boolean(connection('jenkins')?.enabled)),
  click(ci, 'Poll now', 'Read three synthetic builds with matched, missing and ambiguous analysis correlation.', () => operation('poll')),
  read(ci, 'Inspect all three correlation outcomes', 'Build #42 matches analysis an-001 by Project and commit. Missing and ambiguous examples remain unlinked.', 'A successful build is not proof of a passing quality gate. Synapse must not guess when analysis correlation is uncertain.', '[data-integration-runs]'),
  click(ci, 'Add integration', 'Now configure GitHub inbound delivery. This provider has no test, discovery or polling operation.', (_, doc) => Boolean(doc.querySelector('#integration-name'))),
  field(ci, 'Provider', 'GitHub', 'Inbound events resolve through a server-owned Project binding.', 'github', true),
  field(ci, 'Display name', 'GitHub repository events', 'Use a separate connection for repository event delivery.', 'github'),
  field(ci, 'HTTPS endpoint', 'https://github.com', 'This identifies the repository provider; the webhook URL belongs to the Synapse deployment.', 'github'),
  click(ci, 'Create integration', 'Save the inbound connection before binding it to a Git-backed Project.', () => Boolean(connection('github')), 'github'),
  field(ci, 'Synapse Project', 'Synapse CE', 'Exactly one Git Project is allowed for this inbound connection.', undefined, true),
  click(ci, 'Bind Project', 'The webhook payload cannot select an arbitrary repository or Project.', () => state().bindings.some(b => b.integration_id === connection('github')?.id), 'inbound-binding'),
  read(intro, 'Review the deployment handoff', 'An administrator provisions the webhook secret and configures repository events outside this console.', 'The current GitHub integration has no native provisioning form. This preview explains that boundary explicitly.', '[data-setup="webhook"]'),
  sim(intro, 'Record simulated webhook provisioning', '/playground/setup/webhook', 'Retain a demo hook path without storing or displaying a real secret.', () => state().webhookReady),
  click(ci, 'Enable', 'Enable delivery after the Project binding and webhook configuration are ready.', () => Boolean(connection('github')?.enabled)),
  sim(intro, 'Record a pull-request delivery', '/playground/setup/event', 'Load a synthetic PR #42 result for the exact recorded commit. The existing analysis fails its quality gate.', () => Boolean(state().eventAt)),
  read(intro, 'Review analysis and PR feedback', 'The recorded delivery references an-001 and a failed quality gate. Changes are required before release.', 'Delivery, analysis and policy outcome are separate checkpoints. A successful delivery does not mean the code passed.', '[data-setup="delivery"]'),
  read('/code-quality/projects/synapse-ce/analysis', 'Open the linked analysis', 'Inspect the retained analysis for commit a1b2c3d and its failing criteria.', 'Continue to Quality Policies & CI to customize the policy and evaluate an improved revision.'),
  { ...read(intro, 'Repository & CI/CD Setup complete', 'Source access, polling, correlation and inbound delivery have recorded outcomes.', 'The connections remain available to inspect. No repository, CI server or provider was contacted.', '[data-setup="delivery"]'), finish: true },
]
