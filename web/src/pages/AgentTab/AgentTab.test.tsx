import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../../lib/api'
import { AgentTab } from './index'

vi.mock('../../lib/api', () => {
  class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.name = 'ApiError'
      this.status = status
    }
  }
  return {
    ApiError,
    api: {
      agentSessions: vi.fn(),
      agentApprovals: vi.fn(),
      agentReadiness: vi.fn(),
      startAgentSession: vi.fn(),
      decideAgentApproval: vi.fn(),
    },
  }
})

describe('AgentTab', () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  it('names SYNAPSE_AGENT_ENABLED when the orchestrator route is absent', async () => {
    vi.mocked(api.agentSessions).mockRejectedValue(new ApiError(404, 'HTTP 404'))
    vi.mocked(api.agentApprovals).mockRejectedValue(new ApiError(404, 'HTTP 404'))
    vi.mocked(api.agentReadiness).mockRejectedValue(new ApiError(404, 'HTTP 404'))

    render(<AgentTab engagementId="eng-1" />)

    expect(await screen.findByText('The AI agent is not enabled')).toBeInTheDocument()
    expect(screen.getByText(/SYNAPSE_AGENT_ENABLED=true/)).toBeInTheDocument()
    expect(screen.queryByText('HTTP 404')).not.toBeInTheDocument()
  })

  it('still reports a real failure as an error', async () => {
    vi.mocked(api.agentSessions).mockRejectedValue(new ApiError(500, 'orchestrator exploded'))
    vi.mocked(api.agentApprovals).mockResolvedValue([])
    vi.mocked(api.agentReadiness).mockResolvedValue(null as never)

    render(<AgentTab engagementId="eng-1" />)

    expect(await screen.findByText('orchestrator exploded')).toBeInTheDocument()
  })
})
