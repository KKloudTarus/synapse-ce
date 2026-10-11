import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { Connectors } from './Connectors'

vi.mock('../../lib/api', () => ({
  api: {
    me: vi.fn(),
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
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.me).mockResolvedValue({ id: 'u-admin', name: 'Admin', role: 'admin' } as never)
  })

  // #1358: an integration_admin sees the connectors but cannot add or remove one; the server
  // refuses both with 403 anyway.
  it('lets an integration_admin list connectors without offering add or remove', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'u-int', name: 'Integrator', role: 'integration_admin' } as never)
    vi.mocked(api.listConnectors).mockResolvedValue(CONNECTORS as never)
    render(<Connectors />)
    expect(await screen.findByText('Production GitHub')).toBeInTheDocument()
    expect(await screen.findByText('Only tenant administrators can add or remove a connector.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Add connector/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Remove connector/ })).not.toBeInTheDocument()
  })

  it('stops the loading spinner when the list cannot be loaded', async () => {
    vi.mocked(api.listConnectors).mockRejectedValue(new Error('insufficient permissions: this action requires the administer capability'))
    render(<Connectors />)
    expect(await screen.findByText(/insufficient permissions/)).toBeInTheDocument()
    expect(screen.queryByText('Loading connectors…')).not.toBeInTheDocument()
  })

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

  it('sends an optional GitHub Enterprise API base and shows it on the list', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue([] as never)
    vi.mocked(api.createConnector).mockResolvedValue({ id: 'conn-ghes' } as never)
    render(<Connectors />)
    await screen.findByText('No connectors yet')

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'GHES' } })
    fireEvent.change(screen.getByLabelText(/^Host/), { target: { value: 'ghe.example.com' } })
    fireEvent.change(screen.getByLabelText(/^API base URL/), { target: { value: 'https://ghe.example.com/api/v3' } })
    fireEvent.change(screen.getByLabelText(/Personal access token/), { target: { value: 'ghp_secret' } })
    fireEvent.click(screen.getByRole('button', { name: /Add connector/ }))

    await waitFor(() => expect(api.createConnector).toHaveBeenCalledWith(
      expect.objectContaining({ host: 'ghe.example.com', apiBase: 'https://ghe.example.com/api/v3', token: 'ghp_secret' }),
    ))
  })

  it('shows an inline error and blocks submit for an unsafe API base', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue([] as never)
    render(<Connectors />)
    await screen.findByText('No connectors yet')

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'GHES' } })
    fireEvent.change(screen.getByLabelText(/^Host/), { target: { value: 'ghe.example.com' } })
    fireEvent.change(screen.getByLabelText(/Personal access token/), { target: { value: 'ghp_secret' } })
    const apiBase = screen.getByLabelText(/^API base URL/)
    const submit = screen.getByRole('button', { name: /Add connector/ })

    for (const [value, message] of [
      ['http://ghe.example.com/api/v3', 'must use https'],
      ['https://bot:pw@ghe.example.com/api/v3', 'must not contain credentials'],
      ['https://ghe.example.com/api/v3?x=1', 'must not have a query'],
      ['https://ghe.example.com/api/v4', 'must end in /api/v3'],
    ] as const) {
      fireEvent.change(apiBase, { target: { value } })
      expect(screen.getByRole('alert')).toHaveTextContent(message)
      expect(apiBase).toHaveAttribute('aria-invalid', 'true')
      expect(submit).toBeDisabled()
    }
    expect(api.createConnector).not.toHaveBeenCalled()
  })

  it('shows a server refusal of the API base', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue([] as never)
    const { ApiError } = await import('../../lib/api')
    vi.mocked(api.createConnector).mockRejectedValue(new ApiError(400, 'integration host "ghe.example.com" is not on the operator\'s allowlist'))
    render(<Connectors />)
    await screen.findByText('No connectors yet')
    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'GHES' } })
    fireEvent.change(screen.getByLabelText(/^Host/), { target: { value: 'ghe.example.com' } })
    fireEvent.change(screen.getByLabelText(/^API base URL/), { target: { value: 'https://ghe.example.com/api/v3' } })
    fireEvent.change(screen.getByLabelText(/Personal access token/), { target: { value: 'ghp_secret' } })
    fireEvent.click(screen.getByRole('button', { name: /Add connector/ }))
    expect(await screen.findByText(/not on the operator's allowlist/)).toBeInTheDocument()
  })

  it('lists a connector API base and offers no API base field for Bitbucket', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue([
      { ...CONNECTORS[1], apiBase: 'https://gitlab.corp.internal/api/v4' },
    ] as never)
    render(<Connectors />)
    expect(await screen.findByText('API https://gitlab.corp.internal/api/v4')).toBeInTheDocument()
    expect(screen.getByLabelText(/^API base URL/)).toBeInTheDocument()

    const nativeProvider = document.querySelector('select') as HTMLSelectElement
    fireEvent.change(nativeProvider, { target: { value: 'bitbucket' } })
    expect(screen.queryByLabelText(/^API base URL/)).not.toBeInTheDocument()
    fireEvent.change(nativeProvider, { target: { value: 'gitlab' } })
    expect(screen.getByPlaceholderText('https://gitlab.example.com/api/v4')).toBeInTheDocument()
  })

  it('says so when connectors are not enabled on the deployment', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue(null as never)
    render(<Connectors />)
    expect(await screen.findByText('Connectors are not enabled on this deployment')).toBeInTheDocument()
  })
  it('displays Azure DevOps connector metadata without exposing the PAT', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue([{
      id: 'azure-conn', name: 'Azure project', provider: 'azure-devops',
      host: 'dev.azure.com', username: 'pat', authKind: 'pat',
      createdAt: '', updatedAt: '',
    }] as never)
    render(<Connectors />)
    expect(await screen.findByText('Azure project')).toBeInTheDocument()
    expect(screen.getAllByText('Azure DevOps').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('dev.azure.com · pat')).toBeInTheDocument()
    expect(screen.queryByText('secret-azure-pat')).not.toBeInTheDocument()
  })

  it('creates an Azure DevOps connector with the provider-specific defaults', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue([] as never)
    vi.mocked(api.createConnector).mockResolvedValue({ id: 'azure-new' } as never)
    render(<Connectors />)
    await screen.findByText('No connectors yet')

    const nativeProvider = document.querySelector('select') as HTMLSelectElement | null
    expect(nativeProvider).not.toBeNull()
    fireEvent.change(nativeProvider!, { target: { value: 'azure-devops' } })
    expect(screen.getByPlaceholderText('dev.azure.com')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('pat')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Azure DevOps PAT')).toHaveAttribute('type', 'password')
    expect(screen.getByText(/Code \(Read & write\).*Code \(Status\)/)).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Azure project' } })
    fireEvent.change(screen.getByLabelText(/^Host/), { target: { value: 'dev.azure.com' } })
    fireEvent.change(screen.getByLabelText(/Personal access token/), { target: { value: 'azure-secret-pat' } })
    fireEvent.click(screen.getByRole('button', { name: /Add connector/ }))

    await waitFor(() => expect(api.createConnector).toHaveBeenCalledWith(expect.objectContaining({
      name: 'Azure project',
      provider: 'azure-devops',
      host: 'dev.azure.com',
      token: 'azure-secret-pat',
    })))
  })

})
