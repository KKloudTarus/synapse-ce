import { render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { api } from '../../lib/api'
import { resetCapabilityCache } from '../../lib/capabilities'

vi.mock('../../lib/api', () => ({
  api: { listCapabilities: vi.fn() },
  ApiError: class ApiError extends Error {},
}))

vi.mock('../../auth/AuthContext', () => ({
  useOptionalAuth: () => null,
}))

function renderSidebar() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Sidebar />
    </MemoryRouter>,
  )
}

const CATALOG = [
  { key: 'fleet', name: 'Agent fleet transport', enabled: false, switch: 'SYNAPSE_FLEET_ENABLED', requires: [] },
  { key: 'ai_triage', name: 'AI false-positive triage', enabled: false, switch: 'SYNAPSE_FP_TRIAGE_ENABLED', requires: [] },
]

describe('Sidebar capability gating', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.resetAllMocks()
    resetCapabilityCache()
  })

  it('renders a disabled subsystem inert, with its switch named', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue(CATALOG)
    renderSidebar()

    // A 404-answering link is worse than no link: it reads as a broken build.
    await waitFor(() => expect(screen.queryByRole('link', { name: 'Fleet' })).toBeNull())
    const fleet = screen.getByRole('button', { name: /^Fleet\./ })
    expect(fleet).toHaveAttribute('aria-disabled', 'true')
    expect(fleet.getAttribute('aria-label')).toContain('SYNAPSE_FLEET_ENABLED')

    const reviews = screen.getByRole('button', { name: /^Review Queue\./ })
    expect(reviews.getAttribute('aria-label')).toContain('SYNAPSE_FP_TRIAGE_ENABLED')
    expect(screen.queryByRole('link', { name: 'Review Queue' })).toBeNull()
  })

  it('keeps ungated destinations as live links', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue(CATALOG)
    renderSidebar()
    await waitFor(() => expect(screen.queryByRole('link', { name: 'Fleet' })).toBeNull())
    expect(screen.getByRole('link', { name: 'Engagements' })).toHaveAttribute('href', '/engagements')
    expect(screen.getByRole('link', { name: 'Rules' })).toHaveAttribute('href', '/rules')
  })

  it('links an enabled subsystem', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue([{ ...CATALOG[0], enabled: true }, CATALOG[1]])
    renderSidebar()
    await waitFor(() => expect(screen.getByRole('link', { name: 'Fleet' })).toHaveAttribute('href', '/fleet'))
  })

  it('shows everything on a server that does not report capabilities', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue(null)
    renderSidebar()
    expect(await screen.findByRole('link', { name: 'Fleet' })).toHaveAttribute('href', '/fleet')
    expect(screen.getByRole('link', { name: 'Review Queue' })).toHaveAttribute('href', '/ai-triage/reviews')
  })

  it('shows everything before the catalog arrives', async () => {
    let release: (value: null) => void = () => {}
    vi.mocked(api.listCapabilities).mockReturnValue(new Promise((resolve) => { release = resolve }))
    renderSidebar()
    expect(screen.getByRole('link', { name: 'Fleet' })).toHaveAttribute('href', '/fleet')
    release(null)
  })
})
