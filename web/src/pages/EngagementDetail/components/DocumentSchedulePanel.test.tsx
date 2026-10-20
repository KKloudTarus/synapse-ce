import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DocumentSchedulePanel } from './DocumentSchedulePanel'

vi.mock('../../../lib/api/integrations', () => ({ integrationsApi: { listIntegrations: vi.fn() } }))
vi.mock('../../../lib/api/document-schedules', () => ({ documentSchedulesApi: { list: vi.fn(), runs: vi.fn(), save: vi.fn(), disable: vi.fn(), emailDestinations: vi.fn() } }))
vi.mock('../../../components/synapse/ConfirmDialog', () => ({ ConfirmDialog: ({ open, onConfirm }: { open: boolean; onConfirm: () => void }) => open ? <button onClick={onConfirm}>Confirm disable</button> : null }))

import { integrationsApi } from '../../../lib/api/integrations'
import { documentSchedulesApi } from '../../../lib/api/document-schedules'

const sources = [{ kind: 'engagement_report' as const, sourceRef: 'engagement:eng-1', label: 'Engagement report' }]

function ready() {
  vi.mocked(documentSchedulesApi.list).mockResolvedValue([])
	vi.mocked(documentSchedulesApi.runs).mockResolvedValue([])
  vi.mocked(integrationsApi.listIntegrations).mockResolvedValue([{ id: 'confluence-1', name: 'Confluence', provider: 'confluence-cloud', enabled: true, archived: false, credentialConfigured: true }] as never)
  vi.mocked(documentSchedulesApi.emailDestinations).mockResolvedValue([{ id: 'mail-1', name: 'Security recipients', recipientCount: 2 }])
}

afterEach(() => vi.clearAllMocks())

describe('DocumentSchedulePanel', () => {
  it('keeps disabled schedule history without offering another disable or future due time', async () => {
    ready()
    vi.mocked(documentSchedulesApi.list).mockResolvedValue([{ id: 'disabled-schedule', enabled: false, frequency: 'weekly', weekday: 1, hour: 9, minute: 0, destination: 'email', timezone: 'UTC', nextDueAt: '2026-10-20T00:00:00Z', version: 2 }] as never)
    vi.mocked(documentSchedulesApi.runs).mockResolvedValue([{ id: 'run', dueAt: '2026-10-19T00:00:00Z', state: 'done', contentHash: 'a'.repeat(64), remoteVersion: 0, deliveredCount: 2, uncertainCount: 0, failedCount: 0, updatedAt: '2026-10-19T00:01:00Z' }])
    render(<DocumentSchedulePanel scope="engagement" scopeID="eng-1" sources={sources} canManage />)
    expect(await screen.findByText(/Disabled · v2/)).toBeInTheDocument()
    expect(screen.getByText(/delivered 2, uncertain 0, failed 0/)).toBeInTheDocument()
    expect(screen.queryByText(/Next due:/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument()
  })

  it('creates an engagement schedule from derived source and configured destination only', async () => {
    ready()
    vi.mocked(documentSchedulesApi.save).mockResolvedValue({} as never)
    render(<DocumentSchedulePanel scope="engagement" scopeID="eng-1" sources={sources} canManage />)
    fireEvent.change(await screen.findByLabelText('Schedule destination type'), { target: { value: 'email' } })
    fireEvent.change(screen.getByLabelText('Schedule frequency'), { target: { value: 'monthly' } })
    fireEvent.change(screen.getByLabelText('Schedule day'), { target: { value: '31' } })
    fireEvent.change(screen.getByLabelText('Schedule time'), { target: { value: '09:30' } })
    fireEvent.change(screen.getByLabelText('Schedule timezone'), { target: { value: 'Asia/Ho_Chi_Minh' } })
    fireEvent.click(screen.getByRole('button', { name: 'Schedule delivery' }))
    await waitFor(() => expect(documentSchedulesApi.save).toHaveBeenCalledWith(expect.objectContaining({ sourceKind: 'engagement_report', sourceRef: 'engagement:eng-1', scopeId: 'eng-1', destination: 'email', emailChannelId: 'mail-1', timezone: 'Asia/Ho_Chi_Minh', frequency: 'monthly', day: 31, hour: 9, minute: 30 })))
    expect(screen.queryByLabelText(/recipient/i)).not.toBeInTheDocument()
  })

  it('offers each enabled document publishing profile while retaining the legacy schedule value', async () => {
    ready()
    vi.mocked(integrationsApi.listIntegrations).mockResolvedValue([
      { id: 'drive-1', name: 'Restricted Drive', provider: 'google-drive', enabled: true, archived: false, credentialConfigured: true },
      { id: 'sharepoint-1', name: 'Restricted SharePoint', provider: 'sharepoint', enabled: true, archived: false, credentialConfigured: true },
      { id: 'notion-1', name: 'Notion', provider: 'notion', enabled: true, archived: false, credentialConfigured: true },
    ] as never)
    vi.mocked(documentSchedulesApi.save).mockResolvedValue({} as never)
    render(<DocumentSchedulePanel scope="engagement" scopeID="eng-1" sources={sources} canManage />)
    expect(await screen.findByRole('option', { name: 'Restricted Drive' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Restricted SharePoint' })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: 'Notion' })).not.toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Document publishing' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Schedule delivery' }))
    await waitFor(() => expect(documentSchedulesApi.save).toHaveBeenCalledWith(expect.objectContaining({ destination: 'confluence', integrationId: 'drive-1' })))
  })

  it('does not let a stale scope response replace a newer scope', async () => {
    let resolveFirst: (value: any) => void = () => {}
    vi.mocked(documentSchedulesApi.list).mockImplementationOnce(() => new Promise((resolve) => { resolveFirst = resolve }) as never).mockResolvedValueOnce([])
    vi.mocked(integrationsApi.listIntegrations).mockResolvedValue([] as never)
    const { rerender } = render(<DocumentSchedulePanel scope="engagement" scopeID="eng-old" sources={sources} canManage={false} />)
    rerender(<DocumentSchedulePanel scope="engagement" scopeID="eng-new" sources={sources} canManage={false} />)
    resolveFirst([{ id: 'old', frequency: 'weekly', weekday: 1, hour: 9, minute: 0, destination: 'email', timezone: 'UTC', nextDueAt: '2026-10-20T00:00:00Z', version: 1 }])
    await screen.findByText('No scheduled delivery')
    expect(screen.queryByText(/Monday at/)).not.toBeInTheDocument()
  })

	it('shows aggregate run state without exposing recipient or raw delivery errors', async () => {
		vi.mocked(documentSchedulesApi.list).mockResolvedValue([{ id: 'schedule-1', frequency: 'weekly', weekday: 1, hour: 9, minute: 0, destination: 'confluence', timezone: 'UTC', nextDueAt: '2026-10-20T00:00:00Z', version: 3 }] as never)
		vi.mocked(documentSchedulesApi.runs).mockResolvedValue([{ id: 'run-1', dueAt: '2026-10-19T00:00:00Z', state: 'uncertain', contentHash: 'a'.repeat(64), remotePageId: 'page-1', remoteVersion: 4, deliveredCount: 1, uncertainCount: 1, failedCount: 0, updatedAt: '2026-10-19T00:01:00Z' }])
		render(<DocumentSchedulePanel scope="engagement" scopeID="eng-1" sources={sources} canManage={false} />)
		expect((await screen.findAllByText(/uncertain/)).length).toBeGreaterThan(0)
		expect(screen.getByText(/delivered 1, uncertain 1, failed 0/)).toBeInTheDocument()
		expect(screen.getByText(/page page-1 v4/)).toBeInTheDocument()
		expect(screen.getByText(/Document publishing/)).toBeInTheDocument()
		expect(screen.queryByText(/hidden@example|error_code|recipient/i)).not.toBeInTheDocument()
	})
})
