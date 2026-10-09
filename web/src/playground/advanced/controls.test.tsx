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

beforeEach(() => {
  resetAdvanced('policy')
  vi.spyOn(HTMLElement.prototype, 'getClientRects').mockReturnValue([{}] as unknown as DOMRectList)
  HTMLElement.prototype.scrollIntoView = vi.fn()
})

describe('Advanced native form automation', () => {
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
