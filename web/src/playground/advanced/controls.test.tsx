import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useEffect, useState } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { GateEditorModal } from '@/pages/CodeQuality/components/GateEditorModal'
import { api } from '@/lib/api'
import { fillDemoControl } from '../demo-controls'
import { restoreAdvancedControls } from './restore'
import { advancedStore, resetAdvanced, updateAdvanced } from './store'
import { ADVANCED_STEPS } from './steps'
import { gateConditions } from './data'
import { AdvancedWalkthrough } from './AdvancedWalkthrough'
import { chooseMode } from '../workflows/store'
import * as restoration from './restore'
import { updateSetup } from '../setup/store'
import { Select } from '@/components/ui'

beforeEach(() => {
  resetAdvanced('policy')
  vi.spyOn(HTMLElement.prototype, 'getClientRects').mockReturnValue([{}] as unknown as DOMRectList)
  HTMLElement.prototype.scrollIntoView = vi.fn()
})

describe('Advanced native form automation', () => {
  it('makes the completed action and Continue control explicit before advancing', async () => {
    chooseMode('ai-setup')
    const step = ADVANCED_STEPS['ai-setup'].findIndex(s => s.perform?.path === '/playground/setup/ai-ready')
    expect(step).toBeGreaterThanOrEqual(0)
    updateAdvanced(s => { s['ai-setup'].step = step; s['ai-setup'].open = true })
    updateSetup(s => { s.aiReady = true })
    render(<MemoryRouter initialEntries={[ADVANCED_STEPS['ai-setup'][step].route]}><main><h1>AI Agent readiness</h1></main><AdvancedWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(screen.getByRole('button', { name: /^Continue$/ })).toBeEnabled())
    expect(screen.getByRole('status')).toHaveTextContent('Action complete.')
    fireEvent.click(screen.getByRole('button', { name: /^Continue$/ }))
    expect(advancedStore.getSnapshot()['ai-setup'].step).toBe(step + 1)
  })
  it('mounts Select options inside the current dialog on first open and reopen', async () => {
    const mounts: HTMLElement[] = []
    const observer = new MutationObserver(records => {
      for (const record of records) for (const node of record.addedNodes) {
        if (node instanceof HTMLElement && (node.matches('[role="listbox"]') || node.querySelector('[role="listbox"]'))) mounts.push(record.target as HTMLElement)
      }
    })
    const view = render(<div role="dialog" aria-label="First"><Select ariaLabel="Metric" value="coverage" onValueChange={() => {}} options={[{ value: 'coverage', label: 'Coverage' }]} /></div>)
    observer.observe(document.body, { subtree: true, childList: true })
    try {
      fireEvent.click(screen.getByRole('combobox'))
      await waitFor(() => expect(screen.getByRole('listbox')).toBeInTheDocument())
      const first = screen.getByRole('listbox')
      expect(first.closest('[role="dialog"]')?.getAttribute('aria-label')).toBe('First')
      fireEvent.keyDown(first, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('listbox')).not.toBeInTheDocument())
      view.rerender(<div role="dialog" aria-label="Second"><Select ariaLabel="Metric" value="coverage" onValueChange={() => {}} options={[{ value: 'coverage', label: 'Coverage' }]} /></div>)
      fireEvent.click(screen.getByRole('combobox'))
      await waitFor(() => expect(screen.getByRole('listbox')).toBeInTheDocument())
      expect(screen.getByRole('listbox').closest('[role="dialog"]')?.getAttribute('aria-label')).toBe('Second')
      expect(mounts.length).toBeGreaterThan(0)
      expect(mounts.every(node => node !== document.body)).toBe(true)
    } finally { observer.disconnect() }
  })
  it('waits for another Next after opening a form instead of advancing a ready field automatically', async () => {
    chooseMode('policy')
    updateAdvanced(s => { s.policy.step = 9; s.policy.open = true })
    function Page() {
      const [open, setOpen] = useState(false)
      return <><button onClick={() => setOpen(true)}>New gate</button>{open && <div role="dialog"><label>Name<input /></label><label>Key<input id="gate-key" /></label></div>}</>
    }
    render(<MemoryRouter initialEntries={['/code-quality/gates']}><Page /><AdvancedWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(screen.getByRole('button', { name: /^Next$/ })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: /^Next$/ }))
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Name' })).toBeInTheDocument())
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 700)) })
    expect(advancedStore.getSnapshot().policy.step).toBe(10)
    expect(screen.getByRole('heading', { name: 'Name' })).toBeInTheDocument()
  })
  it('does not restore forms again in response to scrolling or resizing the guide', async () => {
    chooseMode('policy')
    updateAdvanced(s => { s.policy.step = 12; s.policy.open = true })
    const restore = vi.spyOn(restoration, 'restoreAdvancedControls')
    render(<MemoryRouter initialEntries={['/code-quality/gates']}><GateEditorModal gate={null} onClose={() => undefined} onSaved={() => undefined} /><AdvancedWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(ADVANCED_STEPS.policy[12].done(advancedStore.getSnapshot(), document)).toBe(true), { timeout: 6000 })
    restore.mockClear()
    act(() => { for (let i = 0; i < 20; i++) { window.dispatchEvent(new Event('scroll')); window.dispatchEvent(new Event('resize')) } })
    expect(restore).not.toHaveBeenCalled()
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Review all three release conditions' })).toBeInTheDocument()
    restore.mockRestore()
  })
  it('does not reopen a gate editor after its save checkpoint succeeds', () => {
    const reopen = vi.fn()
    updateAdvanced(s => { s.policy.step = 13; s.policy.gate = { key: 'checkout-release', name: 'Checkout Release', conditions: gateConditions } })
    render(<button onClick={reopen}>New gate</button>)
    restoreAdvancedControls('policy', advancedStore.getSnapshot())
    expect(reopen).not.toHaveBeenCalled()
  })
  it('prefills datetime-local fields through onChange without duplicate input handlers', () => {
    const changed = vi.fn()
    function WindowField() {
      const [value, setValue] = useState('')
      return <label>Authorized from<input type="datetime-local" value={value} onChange={e => { setValue(e.target.value); changed(e.target.value) }} /></label>
    }
    render(<WindowField />)
    act(() => { fillDemoControl({ title: '', body: '', why: '', target: { kind: 'field', name: 'Authorized from' }, example: { value: '2026-10-09T09:30' }, done: () => false }, {}) })
    expect(screen.getByLabelText('Authorized from')).toHaveValue('2026-10-09T09:30')
    expect(changed).toHaveBeenCalledExactlyOnceWith('2026-10-09T09:30')
  })

  it('selects a native option by its displayed label and submits its stable key', async () => {
    const assigned = vi.fn()
    function GateAssignment() {
      const [value, setValue] = useState('default')
      useEffect(() => { fillDemoControl(ADVANCED_STEPS.policy[14], advancedStore.getSnapshot()) }, [])
      return <select aria-label="Quality gate" value={value} onChange={e => { setValue(e.target.value); assigned(e.target.value) }}>
        <option value="default">Synapse Way</option><option value="checkout-release">Checkout Release</option>
      </select>
    }
    render(<GateAssignment />)
    await waitFor(() => expect(screen.getByLabelText('Quality gate')).toHaveValue('checkout-release'))
    expect(assigned).toHaveBeenCalledExactlyOnceWith('checkout-release')
  })

  it('restores all three conditions through the real gate editor without mixing portal options', async () => {
    updateAdvanced(s => { s.policy.step = 12 })
    const saved = vi.spyOn(api, 'createQualityGate').mockResolvedValue({ key: 'checkout-release', name: 'Checkout Release', conditions: gateConditions, builtIn: false })
    const onSaved = vi.fn()
    function RestoreGate() {
      useEffect(() => {
        const timer = window.setInterval(() => restoreAdvancedControls('policy', advancedStore.getSnapshot()), 40)
        return () => window.clearInterval(timer)
      }, [])
      return <GateEditorModal gate={null} onClose={() => undefined} onSaved={onSaved} />
    }
    render(<RestoreGate />)
    await waitFor(() => expect(ADVANCED_STEPS.policy[12].done(advancedStore.getSnapshot(), document)).toBe(true), { timeout: 6000 })
    fireEvent.click(screen.getByRole('button', { name: 'Create gate' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalledOnce())
    expect(saved).toHaveBeenCalledExactlyOnceWith({ key: 'checkout-release', name: 'Checkout Release', conditions: gateConditions })
  })
})
