import { scanStepRoute } from './scan-steps'
import { resetScenario, scenarioStore, updateScenario, type Scenario } from './scenario/store'
import { chooseMode, resetWorkflow, workflowStore, type DemoMode, type Workflows } from './workflows/store'
import { WORKFLOW_NAMES, workflowRoute } from './workflows/steps'
import { advancedStore, isAdvanced, resetAdvanced, updateAdvanced } from './advanced/store'
import { ADVANCED_NAMES, advancedRoute } from './advanced/steps'

export const DEMO_JOURNEY = [
  { mode: 'overview', title: 'Platform Overview', level: 'Foundation', goal: 'Get familiar with the console', description: 'Explore the main areas of Synapse and learn how assets, assessments, findings and Fleet fit together.', detail: '20-step platform tour' },
  { mode: 'quality', title: WORKFLOW_NAMES.quality, level: 'Beginner', goal: 'Learn to read analysis results', description: 'Create a Project, review issues and security hotspots, then compare two analyses under the same Quality Gate.', detail: '24 steps · Prefilled examples' },
  { mode: 'code', title: 'Code Security Walkthrough', level: 'Intermediate', goal: 'Complete a security assessment', description: 'Create an Asset, run the core scan, triage findings and verify fixes with a Re-test. Close the assessment and monitor new advisories with Intelligence.', detail: '26 stages · Prefilled examples' },
  { mode: 'ci-setup', title: ADVANCED_NAMES['ci-setup'], level: 'Intermediate', goal: 'Connect source access and delivery', description: 'Set up repository access, inspect CI build correlation and trace an inbound repository event to its analysis.', detail: '34 steps · Prefilled examples' },
  { mode: 'ai-setup', title: ADVANCED_NAMES['ai-setup'], level: 'Intermediate', goal: 'Understand AI prerequisites and readiness', description: 'Follow the sidebar to AI Agent, review each deployment prerequisite, verify readiness and inspect a retained-evidence review.', detail: '22 steps · Prefilled examples' },
  { mode: 'ai', title: WORKFLOW_NAMES.ai, level: 'Advanced', goal: 'Make informed review decisions', description: 'Apply your triage knowledge to AI proposals. Compare verifier evidence, accept or reject exemptions, and assign remediation with a recorded rationale.', detail: '19 steps · Prefilled examples' },
  { mode: 'runtime', title: WORKFLOW_NAMES.runtime, level: 'Advanced', goal: 'Investigate and respond to runtime incidents', description: 'Connect an Agent, validate host and workload coverage, then investigate an incident and plan, verify and revert a scoped response.', detail: '27 steps · Prefilled examples' },
] as const

export const ADVANCED_CHAPTERS = [
  { mode: 'remediation', title: ADVANCED_NAMES.remediation, prerequisite: 'Code Security Walkthrough', description: 'Route findings, assign and transfer ownership, review mixed Re-test outcomes and close from verified evidence with a recorded release exception.', detail: '26 steps · Prefilled examples' },
  { mode: 'intelligence', title: ADVANCED_NAMES.intelligence, prerequisite: 'Code Security Walkthrough', description: 'Recover a failed feed, reconcile new advisories against retained inventory and verify an acknowledged exposure notification.', detail: '18 steps · Prefilled examples' },
  { mode: 'policy', title: ADVANCED_NAMES.policy, prerequisite: 'Code Quality Walkthrough', description: 'Customize a language profile, define release criteria and evaluate a synthetic pull-request analysis with coverage evidence.', detail: '21 steps · Prefilled examples' },
] as const

export function chapterComplete(mode: DemoMode, scenario: Scenario, workflows: Workflows) {
  if (isAdvanced(mode)) return advancedStore.getSnapshot()[mode].complete
  return mode === 'overview' ? workflows.overviewComplete : mode === 'code' ? scenario.completed.includes('finish') : workflows[mode].complete
}
export function recommendedChapter(scenario: Scenario, workflows: Workflows) {
  return DEMO_JOURNEY.find(chapter => !chapterComplete(chapter.mode, scenario, workflows))
}
export function nextChapter(mode: DemoMode) {
  const index = DEMO_JOURNEY.findIndex(chapter => chapter.mode === mode)
  return index >= 0 && index < DEMO_JOURNEY.length - 1 ? DEMO_JOURNEY[index + 1] : undefined
}
// Mode changes reload the app so each chapter reads its own browser-local dataset.
export function startDemoChapter(mode: DemoMode, restart = false) {
  if (isAdvanced(mode)) {
    if (restart) resetAdvanced(mode)
    chooseMode(mode)
    updateAdvanced(s => { s[mode].open = true })
    window.location.assign(advancedRoute(mode, advancedStore.getSnapshot()))
  } else if (mode === 'code') {
    if (restart) resetScenario()
    chooseMode(mode)
    updateScenario(s => { s.open = true; s.collapsed = false; s.microStep = 0 })
    window.location.assign(scanStepRoute(scenarioStore.getSnapshot()))
  } else if (mode === 'overview') {
    chooseMode(mode)
    window.location.assign('/dashboard?tour=start')
  } else {
    if (restart) resetWorkflow(mode)
    chooseMode(mode)
    window.location.assign(workflowRoute(mode, workflowStore.getSnapshot()))
  }
}
