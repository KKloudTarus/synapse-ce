import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { Connectors } from './Connectors'

vi.mock('../../lib/api', () => ({
  api: {
    listConnectors: vi.fn(),
    createConnector: vi.fn(),
    deleteConnector: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message)
    }
  },
}))

const CONNECTORS = [
  { id: 'conn-1', name: 'Production GitHub', provider: 'github', host: 'github.com', username: 'x-access-token', authKind: 'pat', createdAt: '', updatedAt: '' },
  { id: 'conn-2', name: 'Internal GitLab', provider: 'gitlab', host: 'gitlab.corp.internal', username: 'oauth2', authKind: 'pat', createdAt: '', updatedAt: '' },
]

describe('Connectors', () => {
  beforeEach(() => vi.resetAllMocks())

  it('lists connectors with provider and host, never a token', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue(CONNECTORS as never)
    render(<Connectors />)
    expect(await screen.findByText('Production GitHub')).toBeInTheDocument()
    expect(screen.getByText('gitlab.corp.internal · oauth2')).toBeInTheDocument()
    // No token value is ever rendered.
    expect(screen.queryByText(/ghp_/)).not.toBeInTheDocument()
  })

  it('keeps the token field masked and creates a connector write-only', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue([] as never)
    vi.mocked(api.createConnector).mockResolvedValue({ id: 'conn-new' } as never)
    render(<Connectors />)
    await screen.findByText('No connectors yet')

    const token = screen.getByLabelText(/Personal access token/) as HTMLInputElement
    expect(token.type).toBe('password') // masked by default
    fireEvent.click(screen.getByRole('button', { name: 'Show token' }))
    expect((screen.getByLabelText(/Personal access token/) as HTMLInputElement).type).toBe('text')

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Prod' } })
    fireEvent.change(screen.getByLabelText(/^Host/), { target: { value: 'github.com' } })
    fireEvent.change(screen.getByLabelText(/Personal access token/), { target: { value: 'ghp_secret' } })
    fireEvent.click(screen.getByRole('button', { name: /Add connector/ }))

    await waitFor(() => expect(api.createConnector).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'Prod', provider: 'github', host: 'github.com', token: 'ghp_secret' }),
    ))
  })

  it('says so when connectors are not enabled on the deployment', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue(null as never)
    render(<Connectors />)
    expect(await screen.findByText('Connectors are not enabled on this deployment')).toBeInTheDocument()
  })
})
