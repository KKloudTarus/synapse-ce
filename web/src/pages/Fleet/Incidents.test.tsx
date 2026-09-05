import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../../lib/api'
import type { Incident } from '../../lib/types'
import { installVirtualViewport } from '../../test/virtualize'
import { Incidents } from './Incidents'

vi.mock('../../lib/api', () => ({ api: { listIncidents: vi.fn() } }))

function incident(overrides: Partial<Incident>): Incident {
  return {
    id: 'inc-1',
    assetId: 'asset-1',
    title: 'Beaconing from web01',
    severity: 'high',
    state: 'open',
    disposition: 'unknown',
    risk: null,
    createdAt: '2026-09-05T08:00:00Z',
    updatedAt: '2026-09-05T09:00:00Z',
    ...overrides,
  } as unknown as Incident
}

const fixtures: Incident[] = [
  incident({ id: 'inc-1' }),
  incident({ id: 'inc-2', title: 'Credential access on db01', severity: 'critical', state: 'investigating', updatedAt: '2026-09-05T10:00:00Z' }),
  incident({ id: 'inc-3', title: 'Closed test incident', severity: 'low', state: 'resolved' }),
]

function renderPage() {
  return render(<MemoryRouter><Incidents /></MemoryRouter>)
}

describe('Incidents', () => {
  let restoreViewport: () => void
  beforeEach(() => {
    vi.resetAllMocks()
    restoreViewport = installVirtualViewport()
  })
  afterEach(() => restoreViewport())

  it('shows the strip, the state chips with counts, and the table', async () => {
    vi.mocked(api.listIncidents).mockResolvedValue({ incidents: fixtures, truncated: false })
    renderPage()
    expect(await screen.findByText('Beaconing from web01')).toBeInTheDocument()
    expect(screen.getByLabelText('Open: 1')).toBeInTheDocument()
    expect(screen.getByLabelText('Critical open: 1')).toBeInTheDocument()
    expect(screen.getByLabelText('In progress: 1')).toBeInTheDocument()
    expect(screen.getByLabelText('Resolved: 1')).toBeInTheDocument()
    expect(screen.getByText(/Last incident update/)).toBeInTheDocument()
    expect(screen.getByText('3 incidents')).toBeInTheDocument()

    // Filtering keeps the strip on the whole set and narrows the table.
    fireEvent.click(screen.getByRole('button', { name: /^Investigating/ }))
    expect(screen.getByText('Credential access on db01')).toBeInTheDocument()
    expect(screen.queryByText('Beaconing from web01')).not.toBeInTheDocument()
    expect(screen.getByText('1 incident')).toBeInTheDocument()
    expect(screen.getByLabelText('Open: 1')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /^Closed/ }))
    expect(screen.getByText('No closed incidents')).toBeInTheDocument()
    expect(screen.getByText('3 incidents in other states')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Show all' }))
    expect(screen.getByText('Beaconing from web01')).toBeInTheDocument()
  })

  it('frames the empty state inside the table and says what fills it', async () => {
    vi.mocked(api.listIncidents).mockResolvedValue({ incidents: [], truncated: false })
    renderPage()
    expect(await screen.findByText('No active incidents')).toBeInTheDocument()
    expect(screen.getByText(/correlation promotes a detection group/)).toBeInTheDocument()
    expect(screen.getByText(/none open yet/)).toBeInTheDocument()
    expect(screen.getByLabelText('Open: 0')).toBeInTheDocument()
  })

  it('shows a framed error with retry', async () => {
    vi.mocked(api.listIncidents).mockRejectedValueOnce(new Error('HTTP 500: boom')).mockResolvedValueOnce({ incidents: fixtures, truncated: false })
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load incidents')
    expect(screen.getByText(/HTTP 500: boom/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByText('Beaconing from web01')).toBeInTheDocument())
  })
})
