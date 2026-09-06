import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { PrivacyAssignment } from '../../lib/api'
import { TelemetryPrivacy } from './TelemetryPrivacy'

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api')
  return {
    ...actual,
    api: {
      activePrivacyPolicy: vi.fn(),
      privacyPolicyHistory: vi.fn(),
      admitPrivacyPolicy: vi.fn(),
      activatePrivacyPolicy: vi.fn(),
    },
  }
})

const POLICY = {
  dispositions: { 'process.arg': 'redact', 'file.path': 'hash', 'process.env': 'drop' } as Record<string, 'allow' | 'redact' | 'hash' | 'drop'>,
  redactSecrets: true,
  maxArgLen: 4096,
  maxArgCount: 64,
  maxPathLen: 1024,
  version: 'v1',
}
const ACTIVE: PrivacyAssignment = { tenantId: 't1', policy: POLICY, digest: 'sha256:aa11bb22cc33', createdBy: 'operator', createdAt: '2026-02-01T00:00:00Z' }
const OLDER: PrivacyAssignment = { ...ACTIVE, digest: 'sha256:ff99ee88dd77', createdAt: '2026-01-01T00:00:00Z' }

describe('TelemetryPrivacy', () => {
  beforeEach(() => vi.resetAllMocks())

  it('shows the active policy and activates a historical one', async () => {
    vi.mocked(api.activePrivacyPolicy).mockResolvedValue(ACTIVE)
    vi.mocked(api.privacyPolicyHistory).mockResolvedValue([ACTIVE, OLDER])
    vi.mocked(api.activatePrivacyPolicy).mockResolvedValue({ ...OLDER })

    render(<TelemetryPrivacy />)

    // Active policy surfaces per-category dispositions.
    expect(await screen.findByText('redact')).toBeInTheDocument()
    expect(screen.getByText('hash')).toBeInTheDocument()
    expect(screen.getByText('drop')).toBeInTheDocument()

    // The non-active historical policy can be activated behind an inline confirm.
    await userEvent.click(screen.getByRole('button', { name: /Activate/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() =>
      expect(api.activatePrivacyPolicy).toHaveBeenCalledWith('sha256:ff99ee88dd77', expect.any(String)),
    )
  })

  it('admits a new policy from the form', async () => {
    vi.mocked(api.activePrivacyPolicy).mockResolvedValue(null)
    vi.mocked(api.privacyPolicyHistory).mockResolvedValue([])
    vi.mocked(api.admitPrivacyPolicy).mockResolvedValue({ assignment: { ...ACTIVE, digest: 'sha256:new' }, created: true })

    render(<TelemetryPrivacy />)
    await userEvent.click(await screen.findByRole('button', { name: 'Admit only' }))
    await waitFor(() => expect(api.admitPrivacyPolicy).toHaveBeenCalled())
  })
})
