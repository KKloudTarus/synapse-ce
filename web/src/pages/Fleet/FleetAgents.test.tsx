import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { FleetAgents } from './FleetAgents'

vi.mock('../../lib/api', () => ({
  ApiError: class ApiError extends Error {},
  api: {
    me: vi.fn(),
    mintEnrolToken: vi.fn(),
    getFleetRollout: vi.fn(),
    setFleetRolloutTarget: vi.fn(),
    promoteFleetRollout: vi.fn(),
    pauseFleetRollout: vi.fn(),
    resumeFleetRollout: vi.fn(),
    listFleetAgents: vi.fn(),
    listAgentKeys: vi.fn(),
    revokeFleetAgent: vi.fn(),
    revokeAgentKey: vi.fn(),
  },
}))

const ADMIN = { id: 'u1', name: 'Ana', role: 'admin' }
const AGENT = { id: 'agent-1', name: 'web01-agent', platform: 'linux', agentVersion: '1.4.0', state: 'healthy', lastSeen: '2026-09-05T09:00:00Z', capabilities: [], currentWork: 0 }
const ROLLOUT_CONFIGURED = {
  channel: 'stable',
  configured: true,
  reason: '',
  rollout: { channel: 'stable', targetVersion: '1.4.2', canaryGroups: ['canary-a'], promotedToAll: false, paused: false, pauseReason: '', updatedBy: 'ana', updatedAt: '2026-09-05T09:00:00Z' },
}
const ROLLOUT_NONE = { channel: 'stable', configured: false, reason: 'no rollout plan is configured for this channel', rollout: null }

function primeDefaults() {
  vi.mocked(api.me).mockResolvedValue(ADMIN as never)
  vi.mocked(api.listFleetAgents).mockResolvedValue([AGENT] as never)
  vi.mocked(api.getFleetRollout).mockResolvedValue(ROLLOUT_NONE as never)
}

describe('FleetAgents', () => {
  beforeEach(() => vi.resetAllMocks())

  it('renders the three sections and lists enrolled agents', async () => {
    primeDefaults()
    render(<FleetAgents />)
    expect(await screen.findByText('web01-agent')).toBeInTheDocument()
    expect(screen.getByText('Agent enrolment')).toBeInTheDocument()
    expect(screen.getByText('Agent rollout')).toBeInTheDocument()
    expect(screen.getByText(/no rollout plan is configured/i)).toBeInTheDocument()
  })

  it('mints an enrolment token and shows it once', async () => {
    primeDefaults()
    vi.mocked(api.mintEnrolToken).mockResolvedValue('ENROL-abc123' as never)
    render(<FleetAgents />)
    await screen.findByText('web01-agent')
    fireEvent.click(screen.getByRole('button', { name: /Mint token/ }))
    expect(await screen.findByText('ENROL-abc123')).toBeInTheDocument()
    expect(screen.getByText(/shown only once/i)).toBeInTheDocument()
    expect(vi.mocked(api.mintEnrolToken)).toHaveBeenCalled()
  })

  it('shows a configured rollout plan with its target version', async () => {
    vi.mocked(api.me).mockResolvedValue(ADMIN as never)
    vi.mocked(api.listFleetAgents).mockResolvedValue([AGENT] as never)
    vi.mocked(api.getFleetRollout).mockResolvedValue(ROLLOUT_CONFIGURED as never)
    render(<FleetAgents />)
    expect(await screen.findByText('1.4.2')).toBeInTheDocument()
    expect(screen.getByText('canary-a')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Promote to all/ })).toBeInTheDocument()
  })

  it('expands an agent to list and revoke its signing keys', async () => {
    primeDefaults()
    vi.mocked(api.listAgentKeys).mockResolvedValue([
      { keyId: 'key-1', purpose: 'signing', algorithm: 'ed25519', notBefore: '', notAfter: '2027-01-01T00:00:00Z', revoked: false, replacedBy: '' },
    ] as never)
    render(<FleetAgents />)
    await screen.findByText('web01-agent')
    fireEvent.click(screen.getByRole('button', { name: /Keys/ }))
    expect(await screen.findByText('key-1')).toBeInTheDocument()
    expect(vi.mocked(api.listAgentKeys)).toHaveBeenCalledWith('agent-1')
    expect(screen.getByText('ed25519')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument()
  })

  it('hides administrator actions from a read-only user', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'u2', name: 'Ro', role: 'readonly' } as never)
    vi.mocked(api.listFleetAgents).mockResolvedValue([AGENT] as never)
    vi.mocked(api.getFleetRollout).mockResolvedValue(ROLLOUT_CONFIGURED as never)
    render(<FleetAgents />)
    await screen.findByText('web01-agent')
    await waitFor(() => expect(screen.getByText(/needs the administrator role/i)).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /Mint token/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Promote to all/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Revoke agent/ })).not.toBeInTheDocument()
  })
})
