import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { OwnershipSnapshot } from '../../lib/api/ownership'
import { SnapshotManager } from './RoutingPolicies'

vi.mock('../../lib/api', () => ({
  api: {
    ownershipSnapshot: vi.fn(), approveOwnershipSnapshot: vi.fn(), importOwnershipSnapshot: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    constructor(public status: number, message: string) { super(message) }
  },
}))

const snapshot: OwnershipSnapshot = {
  id: 'snapshot-1', engagement_id: 'eng-1', repository: 'github.com/acme/payments',
  source_revision: `git:${'a'.repeat(40)}`, file_path: '.github/CODEOWNERS', content_hash: 'sha256-content',
  parser_version: '1', trust: 'untrusted', accept_diagnostics: false, created_at: '2026-09-12T00:00:00Z',
}

describe('CODEOWNERS snapshot review', () => {
  beforeEach(() => {
    vi.mocked(api.ownershipSnapshot).mockResolvedValue({
      ...snapshot, content: '/payments/** @acme/payments',
      diagnostics: [{ line: 1, code: 'unknown_owner', message: 'Map this exact token before activation.' }],
    })
    vi.mocked(api.approveOwnershipSnapshot).mockResolvedValue({ ...snapshot, trust: 'admin_import' })
  })

  it('does not approve a scan-captured snapshot before exact content and diagnostics are acknowledged', async () => {
    const reload = vi.fn()
    render(<SnapshotManager engagement="eng-1" snapshots={[snapshot]} reload={reload} disabled={false} />)

    expect(screen.queryByText('/payments/** @acme/payments')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Review exact content' }))
    expect(await screen.findByText('/payments/** @acme/payments')).toBeInTheDocument()
    expect(screen.getByText(/unknown_owner/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Approve exact hash' })).toBeDisabled()

    fireEvent.click(screen.getByRole('checkbox', { name: /I verified the repository/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Approve exact hash' }))
    await waitFor(() => expect(api.approveOwnershipSnapshot).toHaveBeenCalledWith('snapshot-1', 'sha256-content', true))
    expect(reload).toHaveBeenCalled()
  })
})
