import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { QualityGates } from './QualityGates'

vi.mock('../../lib/api', () => ({ api: { listQualityGates: vi.fn(), createQualityGate: vi.fn(), updateQualityGate: vi.fn(), deleteQualityGate: vi.fn() } }))
const builtIn = { key: 'synapse-way', name: 'Synapse way', builtIn: true, conditions: [{ metric: 'new_high', op: '<=' as const, threshold: 0 }] }
const custom = { key: 'release', name: 'Release', builtIn: false, conditions: [{ metric: 'coverage', op: '>=' as const, threshold: 80 }] }

describe('QualityGates', () => {
  beforeEach(() => { vi.resetAllMocks(); vi.mocked(api.listQualityGates).mockResolvedValue([builtIn, custom]); vi.spyOn(window, 'confirm').mockReturnValue(true) })
  it('protects built-ins and edits a custom multi-condition gate', async () => { vi.mocked(api.updateQualityGate).mockResolvedValue(custom); render(<QualityGates />); expect(await screen.findByText('Synapse way')).toBeInTheDocument(); expect(screen.getAllByRole('button', { name: /Edit/i })).toHaveLength(1); fireEvent.click(screen.getByRole('button', { name: /Edit/i })); expect(screen.getByDisplayValue('release')).toBeDisabled(); fireEvent.click(screen.getByRole('button', { name: 'Add condition' })); expect(screen.getByLabelText('Condition 2 metric')).toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Save changes' })); await waitFor(() => expect(api.updateQualityGate).toHaveBeenCalledWith('release', expect.objectContaining({ conditions: expect.arrayContaining([expect.any(Object), expect.any(Object)]) }))) })
  it('resets the editor when switching custom gates', async () => {
    const strict = { key: 'strict', name: 'Strict', builtIn: false, conditions: [{ metric: 'new_high', op: '<=' as const, threshold: 0 }] }
    vi.mocked(api.listQualityGates).mockResolvedValue([builtIn, custom, strict])
    render(<QualityGates />)
    await screen.findByText('Release')
    fireEvent.click(screen.getAllByRole('button', { name: /Edit/i })[0])
    expect(screen.getByDisplayValue('Release')).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: /Edit/i })[1])
    expect(screen.getByDisplayValue('Strict')).toBeInTheDocument()
    expect(screen.getByDisplayValue('strict')).toBeInTheDocument()
  })

  it('validates a create form before calling the API', async () => { render(<QualityGates />); fireEvent.click(await screen.findByRole('button', { name: /New gate/i })); fireEvent.click(screen.getByRole('button', { name: 'Create gate' })); expect(screen.getByText('Name and key are required.')).toBeInTheDocument(); expect(api.createQualityGate).not.toHaveBeenCalled() })
  it('confirms custom deletion', async () => { vi.mocked(api.deleteQualityGate).mockResolvedValue(); render(<QualityGates />); fireEvent.click(await screen.findByRole('button', { name: /Delete/i })); expect(window.confirm).toHaveBeenCalled(); await waitFor(() => expect(api.deleteQualityGate).toHaveBeenCalledWith('release')) })
})
