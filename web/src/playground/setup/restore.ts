import { fillDemoControl, canClickDemoControl } from '../demo-controls'
import { findGuideTarget } from '../guided-actions'
import { ADVANCED_STEPS } from '../advanced/steps'
import type { AdvancedMode, AdvancedState } from '../advanced/store'

export function restoreSetup(mode: AdvancedMode, s: AdvancedState, doc: Document) {
  if (mode !== 'ci-setup' && mode !== 'ai-setup') return
  const index = s[mode].step, steps = ADVANCED_STEPS[mode], step = steps[index]
  if (step.auto && step.done(s, doc)) return
  const button = (name: string) => { const el = findGuideTarget({ kind: 'button', name }, doc); if (canClickDemoControl(el)) el!.click() }
  if (mode === 'ai-setup' && index === 0 && !findGuideTarget(step.target, doc)) { button('Open menu'); return }
  if (mode === 'ci-setup' && step.route === '/settings/integrations/ci' && !['jenkins', 'github'].includes(step.form ?? '') && index !== 6 && index !== 20) {
    const name = index >= 25 ? 'GitHub repository events' : 'Jenkins build evidence'
    const el = [...doc.querySelectorAll<HTMLElement>('button[aria-pressed]')].find(el => el.textContent?.includes(name))
    if (el?.getAttribute('aria-pressed') === 'false') { el.click(); return }
  }
  if (step.form === 'jenkins' || step.form === 'github') {
    if (!doc.querySelector('#integration-name')) { button('Add integration'); return }
  }
  const fields = steps.filter((st, i) => st.form === step.form && st.example && i <= index)
  if (step.form && !['pipeline-binding', 'inbound-binding'].includes(step.form)) {
    // Finish each portalled select before looking for the next field.
    for (const st of fields) { if (!st.done(s, doc)) { fillDemoControl(st, s, doc); return } }
  }
  if (mode === 'ci-setup' && [15, 16, 26].includes(index)) {
    const preceding = index === 26 ? [steps[25]] : index === 15 ? [steps[14]] : [steps[14], steps[15]]
    for (const st of preceding) if (!st.done(s, doc)) { fillDemoControl(st, s, doc); return }
  }
}
