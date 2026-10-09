import { restoreSetup } from '../setup/restore'
import { canClickDemoControl, fillDemoControl } from '../demo-controls'
import { findGuideTarget } from '../guided-actions'
import { ADVANCED_STEPS, COVERAGE_ARTIFACT } from './steps'
import { CLOSURE_REASON, OVERRIDE_REASON, type AdvancedMode, type AdvancedState } from './store'

export function restoreAdvancedControls(mode: AdvancedMode, s: AdvancedState, doc = document) {
  if (mode === 'ai-setup' || mode === 'ci-setup') { restoreSetup(mode, s, doc); return }
  const index = s[mode].step, steps = ADVANCED_STEPS[mode], step = steps[index]
  const button = (name: string) => { const el = findGuideTarget({ kind: 'button', name }, doc); if (canClickDemoControl(el)) el!.click() }
  const value = (name: string, content: string, checked?: boolean) => fillDemoControl({ title: '', body: '', why: '', done: () => false, target: { kind: 'field', name }, example: checked === undefined ? { value: content } : { checked } }, s, doc)
  if (step.form?.startsWith('ownership')) {
    if (!findGuideTarget({ kind: 'field', name: 'Ownership action' }, doc)) { button('View ownership'); return }
    const transfer = step.form === 'ownership-transfer'
    const group = steps.filter((st, i) => st.form === step.form && i <= index && st.example)
    group.forEach(st => fillDemoControl(st, s, doc))
    if (!transfer && step.title === 'Apply ownership action' && !doc.body.textContent?.includes('Selected: Admin User')) button('Admin User')
  }
  if (step.form === 'closure') {
    if (!findGuideTarget({ kind: 'field', name: 'Closure reason' }, doc)) { button('Review closure'); return }
    value('Closure reason', CLOSURE_REASON)
    if (index >= 21) {
      if (!findGuideTarget({ kind: 'field', name: 'Override' }, doc)) { button('Preview server policy'); return }
      if (index >= 22) value('Override', '', true)
      if (index >= 23) value('Override reason', OVERRIDE_REASON)
    }
  }
  if (step.form === 'profile') {
    if (!doc.querySelector('#copy-key')) { button('Copy profile'); return }
    steps.forEach((st, i) => { if (st.form === 'profile' && i <= index && st.example) fillDemoControl(st, s, doc) })
  }
  if (mode === 'policy' && index === 7 && !findGuideTarget({ kind: 'field', name: steps[7].target!.name }, doc)) { button('Checkout TypeScript'); return }
  if (step.form === 'gate' || mode === 'policy' && index === 12) {
    if (!doc.querySelector('#gate-key')) { button('New gate'); return }
    steps.forEach((st, i) => { if (st.form === 'gate' && st.example && i <= index) fillDemoControl(st, s, doc) })
    const fillCondition = (i: number, metric: string, op: string, threshold: string) => {
      // Radix portals hide the other fields while open. Finish one selection before
      // opening another so an option cannot be applied to a different condition.
      for (const [selector, choice] of [[`#gate-metric-${i}`, metric], [`#gate-op-${i}`, op]]) {
        if (doc.querySelector(selector)?.textContent?.trim() !== choice) {
          fillDemoControl({ title: '', body: '', why: '', done: () => false, target: { kind: 'selector', name: selector }, example: { choice } }, s, doc)
          return false
        }
      }
      fillDemoControl({ title: '', body: '', why: '', done: () => false, target: { kind: 'selector', name: `#gate-threshold-${i}` }, example: { value: threshold } }, s, doc)
      return true
    }
    if (index >= 12) {
      if (!doc.querySelector('#gate-metric-2')) { button('Add condition'); return }
      if (!fillCondition(0, 'New critical issues', '<=', '0')) return
      if (!fillCondition(1, 'Line coverage', '>=', '85')) return
      fillCondition(2, 'Duplication density', '<=', '3')
    }
  }
  if (mode === 'policy' && index === 17 && !s.policy.ciImportedAt) fillDemoControl({ title: '', body: '', why: '', done: () => false, target: { kind: 'field', name: 'Coverage report (optional)' }, example: { file: COVERAGE_ARTIFACT } }, s, doc)
}
