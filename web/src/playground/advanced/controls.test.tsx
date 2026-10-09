import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useEffect, useState } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { GateEditorModal } from '@/pages/CodeQuality/components/GateEditorModal'
import { api } from '@/lib/api'
import { fillDemoControl } from '../demo-controls'
import { restoreAdvancedControls } from './restore'
import { advancedStore, resetAdvanced, updateAdvanced } from './store'
import { ADVANCED_STEPS } from './steps'
import { gateConditions } from './data'

beforeEach(() => {
  resetAdvanced('policy')
  vi.spyOn(HTMLElement.prototype, 'getClientRects').mockReturnValue([{}] as unknown as DOMRectList)
  HTMLElement.prototype.scrollIntoView = vi.fn()
})

describe('Advanced native form automation', () => {
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
