import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../../components/synapse/Toast'
import { api } from '../../lib/api'
import type { WriteupDraft } from '../../lib/api'
import { WriteupDraftsTab } from './WriteupDraftsTab'

vi.mock('../../lib/api', () => ({
  api: {
    listWriteupDrafts: vi.fn(),
    editWriteupDraft: vi.fn(),
    acceptWriteupDraft: vi.fn(),
    rejectWriteupDraft: vi.fn(),
  },
}))

function draft(over: Partial<WriteupDraft> = {}): WriteupDraft {
  return {
    id: 'draft-001',
    engagementId: 'eng-001',
    findingId: 'finding-001',
    description: 'Deserialization of untrusted data',
    remediation: 'Pin the type allow-list',
    state: 'proposed',
    proposedBy: 'agent:writer-01',
    decidedBy: '',
    createdAt: '2026-09-01T00:00:00Z',
    updatedAt: '2026-09-01T00:00:00Z',
    ...over,
  }
}

function renderTab() {
  render(
    <MemoryRouter>
      <ToastProvider>
        <WriteupDraftsTab engagementId="eng-001" />
      </ToastProvider>
    </MemoryRouter>,
  )
}

describe('WriteupDraftsTab', () => {
  beforeEach(() => vi.resetAllMocks())

  it('lists drafts and shows the awaiting-sign-off count', async () => {
    vi.mocked(api.listWriteupDrafts).mockResolvedValue([
      draft(),
      draft({ id: 'draft-002', state: 'accepted', decidedBy: 'alice', description: 'Reflected XSS in search' }),
    ])
    renderTab()

    expect(await screen.findByText(/1 awaiting sign-off/)).toBeInTheDocument()
    expect(screen.getByText('Deserialization of untrusted data')).toBeInTheDocument()
    expect(screen.getByText('Reflected XSS in search')).toBeInTheDocument()
    expect(screen.getByText('accepted')).toBeInTheDocument()
  })

  it('accepts a proposed draft', async () => {
    vi.mocked(api.listWriteupDrafts).mockResolvedValue([draft()])
    vi.mocked(api.acceptWriteupDraft).mockResolvedValue(draft({ state: 'accepted', decidedBy: 'you' }))
    renderTab()

    fireEvent.click(await screen.findByRole('button', { name: /accept/i }))
    await waitFor(() => expect(api.acceptWriteupDraft).toHaveBeenCalledWith('eng-001', 'draft-001'))
  })

  it('only offers accept/edit/reject on a proposed draft', async () => {
    vi.mocked(api.listWriteupDrafts).mockResolvedValue([draft({ state: 'accepted', decidedBy: 'alice' })])
    renderTab()

    await screen.findByText('accepted')
    expect(screen.queryByRole('button', { name: /accept/i })).not.toBeInTheDocument()
  })
})
