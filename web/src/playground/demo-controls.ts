import { findGuideTarget, type GuideAction } from './guided-actions'

const normalize = (s: string) => s.replace(/\s+/g, ' ').trim().toLowerCase()
const visible = (el: Element) => !el.closest('[data-guided-demo], [aria-hidden="true"], [inert], [hidden]') && el.getClientRects().length > 0
export function demoValue<S>(action: GuideAction<S>, s: S): string | undefined {
  return typeof action.example?.value === 'function' ? action.example.value(s) : action.example?.value ?? action.example?.choice ?? action.example?.file?.name
}

// Use the existing forms and their change handlers. Only the playground guide calls this helper;
// no fixture is created or marked successful until the normal simulated API action completes.
export function fillDemoControl<S>(action: GuideAction<S>, s: S, doc = document): HTMLElement | null {
  for (const field of action.prefill ?? []) fillDemoControl({ ...field, title: '', body: '', why: '', done: () => false }, s, doc)
  const example = action.example
  if (!example) return null
  const el = findGuideTarget(action.target, doc)
  let value = demoValue(action, s)
  if (example.choice) {
    const wanted = normalize(example.choice)
    const matches = (text: string) => normalize(text) === wanted || normalize(text).startsWith(`${wanted} `)
    // Radix moves its options into a portal and hides the form while the listbox is open.
    const option = [...doc.querySelectorAll<HTMLElement>('[role="option"]')].find(o => visible(o) && matches(o.textContent ?? ''))
    if (option) { option.click(); return el }
    if (!el) return null
    if (el instanceof HTMLSelectElement) {
      const selected = [...el.options].find(option => matches(option.value) || matches(option.textContent ?? ''))
      if (!selected) return el
      value = selected.value
    }
    const radio = [...el.querySelectorAll<HTMLElement>('[role="radio"]')].find(r => matches(r.textContent ?? ''))
    if (radio) { if (radio.getAttribute('aria-checked') !== 'true') radio.click(); return el }
    if (el.getAttribute('role') === 'combobox') {
      if (!matches(el.textContent ?? '') && el.getAttribute('aria-expanded') !== 'true') el.click()
      return el
    }
  }
  if (!el) return null
  if (example.file && el instanceof HTMLInputElement && el.type === 'file') {
    if (el.files?.[0]?.name !== example.file.name) {
      const transfer = new DataTransfer()
      transfer.items.add(new File([example.file.content], example.file.name, { type: example.file.type }))
      el.files = transfer.files
      el.dispatchEvent(new Event('change', { bubbles: true }))
    }
  } else if (example.checked !== undefined) {
    if (el instanceof HTMLInputElement && el.checked !== example.checked) el.click()
    else if (el.getAttribute('aria-pressed') !== null && (el.getAttribute('aria-pressed') === 'true') !== example.checked) el.click()
  } else if (value !== undefined && (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement) && el.value !== value) {
    const prototype = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype
    Object.getOwnPropertyDescriptor(prototype, 'value')?.set?.call(el, value)
    el.dispatchEvent(new Event('input', { bubbles: true }))
    el.dispatchEvent(new Event('change', { bubbles: true }))
  }
  return el
}

export function canClickDemoControl(el: HTMLElement | null): boolean {
  return Boolean(el && visible(el) && !el.matches(':disabled, [aria-disabled="true"], [data-loading="true"]'))
}
