import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { SIEMSink } from '../../lib/api'
import { SIEM, SIEM_PROVIDER_FIELDS, SIEM_PROVIDER_OPTIONS } from './SIEM'

vi.mock('../../lib/api', () => ({
  api: {
    me: vi.fn(),
    listSIEMSinks: vi.fn(),
    createSIEMSink: vi.fn(),
    testSIEMSink: vi.fn(),
    pauseSIEMSink: vi.fn(),
    resumeSIEMSink: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

import { ApiError, api } from '../../lib/api'

const blockedSink: SIEMSink = {
  id: 'sink-blocked',
  tenant_id: 'tenant-a',
  name: 'Blocked collector',
  provider: 'splunk_hec',
  origin: 'https://splunk.example:8088',
  target: '/services/collector/event',
  data_class: 'signal',
  ack_mode: 'hec_acceptance',
  indexer_ack_supported: false,
  paused: false,
  enabled: true,
  generation: 1,
  secret_version: 1,
  version: 4,
  channel: 'channel',
  blocked_reason: 'provider rejected a record',
  created_at: '2026-09-27T00:00:00Z',
  updated_at: '2026-09-27T00:00:00Z',
}

describe('SIEM settings', () => {
  beforeEach(() => {
	Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() })
    vi.mocked(api.me).mockReset()
    vi.mocked(api.listSIEMSinks).mockReset()
    vi.mocked(api.createSIEMSink).mockReset()
    vi.mocked(api.testSIEMSink).mockReset()
    vi.mocked(api.pauseSIEMSink).mockReset()
    Element.prototype.scrollIntoView = vi.fn()
    vi.mocked(api.resumeSIEMSink).mockReset()
    vi.mocked(api.createSIEMSink).mockReset()
  })

  it('shows a permission state for a reader', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'readonly' } as never)
    render(<SIEM />)
    expect(await screen.findByText('Administrator access required')).toBeInTheDocument()
  })

  it('shows an empty stream list', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listSIEMSinks).mockResolvedValue([])
    render(<SIEM />)
    expect(await screen.findByText('No SIEM destinations')).toBeInTheDocument()
    expect(screen.getByText(/Microsoft Sentinel sink/i)).toBeInTheDocument()
    expect(screen.getByLabelText('Name')).toBeInTheDocument()
    expect(SIEM_PROVIDER_OPTIONS).toContainEqual({ value: 'microsoft_sentinel', label: 'Microsoft Sentinel' })
    expect(SIEM_PROVIDER_FIELDS.microsoft_sentinel).toMatchObject({
      targetLabel: 'DCR / stream',
      targetPlaceholder: 'dcr-0123456789abcdef0123456789abcdef/Custom-SynapseSIEM',
      credentialLabel: 'Entra client credential JSON',
      targetHint: expect.stringContaining('Custom-'),
    })
    expect(screen.getByText(/not currently available/i)).toBeInTheDocument()
    expect(screen.queryByLabelText('Data class')).not.toBeInTheDocument()
  })

  it('shows the RFC 5424 TLS fields when syslog is selected', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listSIEMSinks).mockResolvedValue([])
    render(<SIEM />)
    const provider = await screen.findByLabelText('Provider')
    fireEvent.click(provider)
    fireEvent.click(await screen.findByRole('option', { name: 'Syslog TLS (RFC 5424)' }))
    expect(screen.getByLabelText('Syslog TLS endpoint')).toHaveAttribute('placeholder', 'tls://syslog.example:6514')
    expect(screen.getByLabelText('Application name')).toHaveAttribute('placeholder', 'synapse')
    expect(screen.getByLabelText('TLS credential JSON')).toBeInTheDocument()
  })


  it('switches the form to Microsoft Sentinel and submits its contract', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listSIEMSinks).mockResolvedValue([])
    vi.mocked(api.createSIEMSink).mockResolvedValue({} as never)
    render(<SIEM />)

    await screen.findByText('No SIEM destinations')
    fireEvent.click(screen.getByLabelText('Provider'))
    fireEvent.click(await screen.findByRole('option', { name: 'Microsoft Sentinel' }))

    expect(screen.getByLabelText('DCR / stream')).toBeRequired()
    expect(screen.getByPlaceholderText('dcr-0123456789abcdef0123456789abcdef/Custom-SynapseSIEM')).toBeInTheDocument()
    expect(screen.getByLabelText('Entra client credential JSON')).toHaveAttribute('type', 'password')
    expect(screen.getByText(/Custom- stream declaration/i)).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Sentinel' } })
    fireEvent.change(screen.getByLabelText('HTTPS origin'), { target: { value: 'https://example.eastus-1.ingest.monitor.azure.com' } })
    fireEvent.change(screen.getByLabelText('DCR / stream'), { target: { value: 'dcr-0123456789abcdef0123456789abcdef/Custom-SynapseSIEM' } })
    fireEvent.change(screen.getByLabelText('Entra client credential JSON'), {
      target: { value: '{"tenant_id":"11111111-1111-4111-8111-111111111111","client_id":"22222222-2222-4222-8222-222222222222","client_secret":"secret-value"}' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add sink' }))

    await waitFor(() => {
      expect(api.createSIEMSink).toHaveBeenCalledWith({
        name: 'Sentinel',
        provider: 'microsoft_sentinel',
        origin: 'https://example.eastus-1.ingest.monitor.azure.com',
        target: 'dcr-0123456789abcdef0123456789abcdef/Custom-SynapseSIEM',
        data_class: 'signal',
        secret: '{"tenant_id":"11111111-1111-4111-8111-111111111111","client_id":"22222222-2222-4222-8222-222222222222","client_secret":"secret-value"}',
      })
    })
  })

  it('shows an API permission-denied state', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listSIEMSinks).mockRejectedValue(new ApiError(403, 'forbidden'))
    render(<SIEM />)
    expect(await screen.findByText('Permission denied. This session cannot manage SIEM streams.')).toBeInTheDocument()
  })

  it('tests an existing SIEM sink through the connection-test API', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listSIEMSinks).mockResolvedValue([blockedSink])
    vi.mocked(api.testSIEMSink).mockResolvedValue({ guarantee: 'hec_acceptance', result: 'accepted' })
    render(<SIEM />)
    expect(await screen.findByText('Blocked collector')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Test' }))
    await waitFor(() => {
      expect(api.testSIEMSink).toHaveBeenCalledWith('sink-blocked')
    })
    expect(await screen.findByRole('status')).toHaveTextContent('Connection test accepted (hec_acceptance).')
  })

  it('resumes a blocked sink that is not paused', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listSIEMSinks).mockResolvedValue([blockedSink])
    vi.mocked(api.resumeSIEMSink).mockResolvedValue({ ...blockedSink, blocked_reason: undefined, version: 5 })
    render(<SIEM />)
    expect(await screen.findByText('provider rejected a record')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Pause' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Resume' }))
    await waitFor(() => {
      expect(api.resumeSIEMSink).toHaveBeenCalledWith('sink-blocked', 4)
    })
  })

  // #1358: an integration_admin runs existing sinks; adding one stays with administrators.
  it('lets an integration_admin pause and resume a sink but not add one', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'integration_admin' } as never)
    vi.mocked(api.listSIEMSinks).mockResolvedValue([blockedSink])
    vi.mocked(api.resumeSIEMSink).mockResolvedValue({ ...blockedSink, blocked_reason: undefined, version: 5 })
    vi.mocked(api.testSIEMSink).mockResolvedValue({ guarantee: 'hec_acceptance', result: 'accepted' })
    render(<SIEM />)
    expect(await screen.findByText('Blocked collector')).toBeInTheDocument()
    expect(screen.getByText(/Only tenant administrators can add a sink/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add sink' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Test' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Connection test accepted (hec_acceptance).')
    expect(api.testSIEMSink).toHaveBeenCalledWith('sink-blocked')
    fireEvent.click(screen.getByRole('button', { name: 'Resume' }))
    await waitFor(() => expect(api.resumeSIEMSink).toHaveBeenCalledWith('sink-blocked', 4))
  })

  it('shows a load error', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listSIEMSinks).mockRejectedValue(new Error('database unavailable'))
    render(<SIEM />)
    expect(await screen.findByText('database unavailable')).toBeInTheDocument()
  })
})
