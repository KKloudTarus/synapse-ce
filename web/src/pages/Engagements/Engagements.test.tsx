import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Sidebar } from '../../components/layout/Sidebar'
import { api } from '../../lib/api'
import { Engagements, NewEngagement } from '.'

vi.mock('../../lib/api', () => ({
  api: {
    listEngagements: vi.fn(),
    listBusinessAssets: vi.fn(),
    createEngagement: vi.fn(),
    createEngagementFromSource: vi.fn(),
    startScan: vi.fn(),
    importBundle: vi.fn(),
    transitionEngagement: vi.fn(),
  },
}))

describe('Engagements', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.listBusinessAssets).mockResolvedValue({
      items: [
        {
          id: 'a1',
          key: 'mobile',
          name: 'Mobile Banking',
          description: '',
          type: 'application',
          criticality: 'critical',
          lifecycle: 'active',
          owner: 'Mobile Team',
          metadata: {},
          version: 1,
          createdAt: null,
          updatedAt: null,
        },
      ],
      total: 1,
      limit: 200,
      offset: 0,
    })
  })

  it('keeps the Engagements page focused on the assessment queue', async () => {
    render(
      <MemoryRouter initialEntries={['/engagements']}>
        <Engagements />
      </MemoryRouter>,
    )

    expect(screen.getByRole('heading', { name: 'Engagements' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Engagement details' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'New Engagement' })).toHaveAttribute('href', '/engagements/new')
  })

  it('renders creation separately and preselects the Asset from query parameters', async () => {
    render(
      <MemoryRouter initialEntries={['/engagements/new?assetId=a1']}>
        <NewEngagement />
      </MemoryRouter>,
    )

    expect(screen.getByRole('heading', { name: 'New Engagement' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Engagement details' })).toBeInTheDocument()
    expect((await screen.findAllByText('Mobile Banking (mobile)')).length).toBeGreaterThan(0)
    await waitFor(() => expect(api.listBusinessAssets).toHaveBeenCalledWith('limit=200'))
  })

  it('navigates to the dedicated creation route from the sidebar', async () => {
    render(
      <MemoryRouter initialEntries={['/engagements']}>
        <Sidebar />
        <Routes>
          <Route path="/engagements" element={<Engagements />} />
          <Route path="/engagements/new" element={<NewEngagement />} />
        </Routes>
      </MemoryRouter>,
    )

    await screen.findByText('No engagements yet')
    const newEngagementLinks = screen.getAllByRole('link', { name: 'New Engagement' })
    fireEvent.click(newEngagementLinks[0])
    expect(await screen.findByRole('heading', { name: 'New Engagement' })).toBeInTheDocument()
  })

  it('uploads a source package, creates the engagement, and starts its scan', async () => {
    const created = {
      id: 'eng-upload', name: 'Uploaded assessment', client: '', status: 'draft',
      inScope: [{ kind: 'repo', value: `uploaded-source/sha256/${'b'.repeat(64)}` }], outOfScope: [],
      authorizedFrom: null, authorizedTo: null, roe: { allowedToolClasses: [], blackouts: [] },
      liveReconEnabled: false, createdAt: '2026-08-28T00:00:00Z', businessAssetId: '',
    }
    vi.mocked(api.createEngagementFromSource).mockResolvedValue(created)
    vi.mocked(api.startScan).mockResolvedValue({
      id: 'scan-upload', engagementId: created.id, target: created.inScope[0].value, kind: 'upload',
      status: 'running', stage: 'queued', progress: 0, error: '', startedAt: null, finishedAt: null, debugEvents: [],
    })

    render(
      <MemoryRouter initialEntries={['/engagements/new']}>
        <Routes>
          <Route path="/engagements/new" element={<NewEngagement />} />
          <Route path="/engagements/:id" element={<div>Uploaded engagement detail</div>} />
        </Routes>
      </MemoryRouter>,
    )

    fireEvent.change(screen.getByLabelText(/Name/), { target: { value: 'Uploaded assessment' } })
    fireEvent.click(screen.getByRole('radio', { name: /Upload package/i }))
    fireEvent.change(screen.getByLabelText('Source package'), {
      target: { files: [new File(['archive'], 'source.tar.gz', { type: 'application/gzip' })] },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Create & Scan' }))

    await waitFor(() => expect(api.createEngagementFromSource).toHaveBeenCalled())
    expect(api.startScan).toHaveBeenCalledWith('eng-upload', '', 'upload')
    expect(await screen.findByText('Uploaded engagement detail')).toBeInTheDocument()
  })

  it('renders engagement rows and supports searching and filtering', async () => {
    vi.mocked(api.listEngagements).mockResolvedValue([
      {
        id: 'eng-1',
        name: 'Payment Gateway Audit',
        client: 'Acme Payments',
        status: 'Active',
        inScope: [{ kind: 'repo', value: 'github.com/acme/payment-service' }],
        outOfScope: [],
        authorizedFrom: null,
        authorizedTo: null,
        roe: { allowedToolClasses: [], blackouts: [] },
        liveReconEnabled: false,
        createdAt: '2026-08-20T10:00:00Z',
        businessAssetId: 'a1',
      },
      {
        id: 'eng-2',
        name: 'Legacy Portal Test',
        client: 'Legacy Inc',
        status: 'Draft',
        inScope: [{ kind: 'url', value: 'https://legacy.portal.io' }],
        outOfScope: [],
        authorizedFrom: null,
        authorizedTo: null,
        roe: { allowedToolClasses: [], blackouts: [] },
        liveReconEnabled: false,
        createdAt: '2026-08-10T10:00:00Z',
        businessAssetId: '',
      },
    ])

    render(
      <MemoryRouter initialEntries={['/engagements']}>
        <Engagements />
      </MemoryRouter>,
    )

    expect(await screen.findByText('Payment Gateway Audit')).toBeInTheDocument()
    expect(screen.getByText('Legacy Portal Test')).toBeInTheDocument()
    expect(screen.getByText('github.com/acme/payment-service')).toBeInTheDocument()

    // Test Search
    const searchInput = screen.getByPlaceholderText('Search engagements...')
    fireEvent.change(searchInput, { target: { value: 'Payment' } })

    await waitFor(() => {
      expect(screen.getByText('Payment Gateway Audit')).toBeInTheDocument()
      expect(screen.queryByText('Legacy Portal Test')).not.toBeInTheDocument()
    })

    // Test Clear
    const clearButton = screen.getByRole('button', { name: 'Clear filters' })
    fireEvent.click(clearButton)

    await waitFor(() => {
      expect(screen.getByText('Payment Gateway Audit')).toBeInTheDocument()
      expect(screen.getByText('Legacy Portal Test')).toBeInTheDocument()
    })
  })
})
