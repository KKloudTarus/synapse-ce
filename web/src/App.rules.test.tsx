import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import App from './App'
import { api } from './lib/api'
import { Sidebar } from './components/layout/Sidebar'

vi.mock('./lib/api', () => ({
  api: {
    listRules: vi.fn(),
    getRule: vi.fn(),
    listEngagements: vi.fn(),
    listBusinessAssets: vi.fn(),
    fleetCoverageSummary: vi.fn(),
    dashboardSecurityOperations: vi.fn(),
    listProjects: vi.fn(),
    getProject: vi.fn(),
    getAuditLogs: vi.fn(),
    getTeam: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    constructor(public status: number, message: string) {
      super(message)
    }
  },
}))

vi.mock('./auth/AuthContext', () => ({
  AuthProvider: ({ children }: any) => children,
  useAuth: () => ({ phase: 'ready', logout: vi.fn() }),
}))

describe('App Routing - Rules', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.resetAllMocks()
    vi.mocked(api.listRules).mockResolvedValue([])
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [], total: 0, limit: 200, offset: 0 })
    vi.mocked(api.fleetCoverageSummary).mockResolvedValue({ agentsByState: {}, rowsByVerdict: {}, oldestPerCapability: {}, assetsWithoutAgent: 0 })
    vi.mocked(api.dashboardSecurityOperations).mockResolvedValue({ rangeDays: 30, generatedAt: '', assetPosture: {}, assetsByCriticality: {}, activeFindingsBySeverity: {}, findingsOverTime: [], findingsWithoutTimestamp: 0, externalFindingsIncluded: true })
    vi.mocked(api.listProjects).mockResolvedValue([])
    vi.mocked(api.getRule).mockResolvedValue({
      key: 'go:sql',
      name: 'SQL Injection',
      language: 'go',
      type: 'vulnerability',
      qualities: [],
      defaultSeverity: 'high',
      tags: [],
      cwe: [],
      owasp: [],
      description: 'Desc',
      rationale: '',
      remediation: '',
      compliantExample: '',
      noncompliantExample: '',
      remediationEffort: 10,
      detection: 'ast',
    })
  })

  it('renders Rules page on /rules route', async () => {
    render(
      <MemoryRouter initialEntries={['/rules']}>
        <App />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Rules' })).toBeInTheDocument()
    }, { timeout: 8000 })
  })

  it('renders Dashboard as the default route', async () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    )

    expect(await screen.findByRole('heading', { name: 'Security Operations' }, { timeout: 8000 })).toBeInTheDocument()
  })

  it('renders RuleDetail page on /rules/:key route and decodes colon exactly once', async () => {
    render(
      <MemoryRouter initialEntries={['/rules/go%3Asql']}>
        <App />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'SQL Injection' })).toBeInTheDocument()
    }, { timeout: 8000 })

    expect(api.getRule).toHaveBeenCalledWith('go:sql')
  })

  it('maintains active state on Rules list', async () => {
    render(
      <MemoryRouter initialEntries={['/rules']}>
        <Sidebar />
      </MemoryRouter>
    )

    const rulesLink = screen.getByRole('link', { name: /Rules/i })
    expect(rulesLink.className).toMatch(/bg-active|bg-navactive|text-white/)
  })

  it('maintains active state on Rules detail', async () => {
    render(
      <MemoryRouter initialEntries={['/rules/go:sql']}>
        <Sidebar />
      </MemoryRouter>
    )

    const rulesLink = screen.getByRole('link', { name: /Rules/i })
    expect(rulesLink.className).toMatch(/bg-active|bg-navactive|text-white/)
  })

  it('keeps Code Quality active on project shells', () => {
    render(
      <MemoryRouter initialEntries={['/code-quality/projects/synapse']}>
        <Sidebar />
      </MemoryRouter>
    )
    const link = screen.getByRole('link', { name: /Code Quality/i })
    expect(link.className).toMatch(/bg-active|bg-navactive|text-white/)
  })

  it('keeps Dashboard active in the command center', () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <Sidebar />
      </MemoryRouter>
    )
    const link = screen.getByRole('link', { name: /Dashboard/i })
    expect(link.className).toMatch(/bg-active|bg-navactive|text-white/)
  })

  it('supports collapsed navigation', () => {
    render(
      <MemoryRouter initialEntries={['/assets']}>
        <Sidebar />
      </MemoryRouter>
    )

    fireEvent.click(screen.getByRole('button', { name: 'Collapse sidebar' }))
    expect(screen.getByRole('button', { name: 'Expand sidebar' })).toBeInTheDocument()
  })

  it('separates the create action from the active Engagements destination', () => {
    render(
      <MemoryRouter initialEntries={['/engagements/new']}>
        <Sidebar />
      </MemoryRouter>
    )

    const newEngagement = screen.getByRole('link', { name: 'New Engagement' })
    expect(newEngagement.getAttribute('href')).toBe('/engagements/new')
    expect(newEngagement).not.toHaveAttribute('aria-current')
    expect(screen.getByRole('link', { name: 'Engagements' })).toHaveAttribute('aria-current', 'page')
  })

  it('groups shipped capabilities by operator workflow without placeholder navigation', () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <Sidebar />
      </MemoryRouter>
    )

    expect(screen.getByRole('heading', { name: 'Security operations' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Exposure management' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Security engineering' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Runtime security' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Settings' })).toHaveAttribute('href', '/settings')
    expect(screen.getByRole('link', { name: /Review [Qq]ueue/i })).toHaveAttribute('href', '/ai-triage/reviews')
    expect(screen.queryByText('Coming soon')).not.toBeInTheDocument()
  })

  it('opens mobile navigation and navigates to Rules', async () => {
    render(
      <MemoryRouter initialEntries={['/engagements']}>
        <App />
      </MemoryRouter>
    )

    // Wait for Engagements page to render
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Engagements' })).toBeInTheDocument()
    })

    // Open menu button MUST exist — mandatory assertion
    const menuButton = screen.getByRole('button', { name: /open menu/i })
    expect(menuButton).toBeDefined()
    fireEvent.click(menuButton)

    // The mobile sidebar must now be open — find the dialog
    const dialog = screen.getByRole('dialog', { name: /navigation/i })
    expect(dialog).toBeInTheDocument()

    // Find the Rules link inside the dialog and click it
    const allRulesLinks = screen.getAllByRole('link', { name: /^Rules$/i })
    const mobileRulesLink = allRulesLinks.at(-1)!
    expect(mobileRulesLink).toBeDefined()
    fireEvent.click(mobileRulesLink)

    // Route must change to /rules
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Rules' })).toBeInTheDocument()
    })

    await waitFor(() => {
      expect(
        screen.queryByRole('dialog', { name: /navigation/i }),
      ).not.toBeInTheDocument()
    })
  })

  it('switches theme from settings config', async () => {
    render(
      <MemoryRouter initialEntries={['/settings/config']}>
        <App />
      </MemoryRouter>
    )

    await screen.findByRole('heading', { name: 'Settings' })
    fireEvent.click(await screen.findByRole('button', { name: 'Dark theme' }))
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(document.documentElement.classList.contains('dark-mode')).toBe(true)
    fireEvent.click(await screen.findByRole('button', { name: 'Light theme' }))
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(document.documentElement.classList.contains('dark-mode')).toBe(false)
  })
})
