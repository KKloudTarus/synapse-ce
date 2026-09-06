import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { ResponseOps } from './ResponseOps'

vi.mock('../../lib/api', () => ({
  api: {
    listResponses: vi.fn(),
    listEngagements: vi.fn().mockResolvedValue([]),
    planResponse: vi.fn(),
    applyResponse: vi.fn(),
    revertResponse: vi.fn(),
    haltOffensive: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    constructor(public status: number, message: string) {
      super(message)
    }
  },
}))

describe('ResponseOps', () => {
  beforeEach(() => vi.resetAllMocks())

  it('renders governed responses, the simulation notice, and the kill switch', async () => {
    vi.mocked(api.listResponses).mockResolvedValue([
      { id: 'resp-1', kind: 'isolate_host', target: 'host-web-01', state: 'applied', approver: 'alice', verification: 'succeeded' },
    ] as never)
    vi.mocked(api.listEngagements).mockResolvedValue([] as never)
    render(<ResponseOps />)
    expect(await screen.findByText('isolate host')).toBeInTheDocument()
    expect(screen.getByText('host-web-01')).toBeInTheDocument()
    expect(screen.getByText(/Executor is simulation/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Halt offensive work/ })).toBeInTheDocument()
  })

  it('says so when governed response is not enabled', async () => {
    vi.mocked(api.listResponses).mockResolvedValue(null as never)
    vi.mocked(api.listEngagements).mockResolvedValue([] as never)
    render(<ResponseOps />)
    expect(await screen.findByText('Governed response is not enabled on this deployment')).toBeInTheDocument()
  })
})
