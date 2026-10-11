import { canClickDemoControl, fillDemoControl } from '../demo-controls'
import { findGuideTarget } from '../guided-actions'
import { WORKFLOW_STEPS } from './steps'
import { isWorkflow, type Workflows } from './store'
import { AI_TITLES } from './data'

// Unsaved form state belongs to the native page. Reconstruct it from the fixed training examples
// after pause/reload; saved mutations remain authoritative and are never repeated here.
export function restoreWorkflowControls(s: Workflows, doc = document) {
  if (!isWorkflow(s.mode)) return
  const mode = s.mode, index = s[mode].step
  const click = (selector: string) => { const el = findGuideTarget({ kind: 'selector', name: selector }, doc); if (canClickDemoControl(el)) el!.click() }
  const button = (name: string) => { const el = findGuideTarget({ kind: 'button', name }, doc); if (canClickDemoControl(el)) el!.click() }
  const fill = (indices: number[]) => indices.forEach(i => fillDemoControl(WORKFLOW_STEPS[mode][i], s, doc))
  if (mode === 'quality') {
    if (index >= 2 && index <= 7 && !s.quality.project) {
      if (!doc.querySelector('#project-name')) { button('New project'); return }
      fill([2, 3, 4, 5, 6].filter(i => i <= index))
    }
    if (index >= 11 && index <= 13 && s.quality.issueStatus === 'open') {
      if (!doc.querySelector('#issue-transition-rationale')) { click('[data-issue-id="learn-issue-1"]'); return }
      if (index >= 12) { const el = doc.querySelector<HTMLElement>('[data-issue-inspector="learn-issue-1"] button[aria-pressed]'); if (el?.getAttribute('aria-pressed') !== 'true') el?.click() }
      if (index === 13) fill([12])
    }
    if (index >= 15 && index <= 18 && s.quality.hotspotStatus === 'to_review') {
      if (!doc.querySelector('[aria-label="Hotspot inspector"]')) { click('[data-hotspot-id="learn-hotspot-1"]'); return }
      if (!doc.querySelector('#rationale')) { button('Review & Audit'); return }
      if (index >= 17) { const el = doc.querySelector<HTMLElement>('[aria-label="Hotspot inspector"] button[aria-pressed]'); if (el?.getAttribute('aria-pressed') !== 'true') el?.click() }
      if (index === 18) fill([17])
    }
  }
  if (mode === 'ai') {
    const i = index >= 3 && index <= 5 ? 0 : index >= 8 && index <= 10 ? 1 : null
    if (i !== null && s.ai.reviews[i].state === 'pending') {
      const el = doc.querySelector<HTMLElement>(`[data-review-id="learn-review-${i + 1}"]`)
      if (el?.getAttribute('aria-expanded') === 'false') { el.click(); return }
      if (index === 5) fill([4])
      if (index === 10) fill([9])
    }
    if (index >= 13 && index <= 16 && !findGuideTarget({ kind: 'field', name: 'New comment' }, doc)) {
      button(`Toggle details for ${AI_TITLES[1]}`); return
    }
    if (index === 16) fill([15])
  }
  if (mode === 'runtime') {
    if (index === 16 && !s.runtime.owner) fill([15])
    if (index === 18 && !s.runtime.comment) fill([17])
    if (index >= 20 && index <= 22 && !s.runtime.appliedAt) {
      fill([19])
      // A dry-run plan is transient on the page. Recreate it only after a saved planning checkpoint.
      if (index >= 21 && s.runtime.planAt && !doc.querySelector('main ol')) button('Plan (dry run)')
    }
  }
}
