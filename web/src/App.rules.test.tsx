import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import App from './App'
import { api } from './lib/api'
import { Sidebar } from './components/Sidebar'

vi.mock('./lib/api', () => ({
  api: {
    listRules: vi.fn(),
    getRule: vi.fn(),
    listEngagements: vi.fn(),
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
    vi.mocked(api.listRules).mockResolvedValue([])
    vi.mocked(api.listEngagements).mockResolvedValue([])
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
    })
  })

  it('renders RuleDetail page on /rules/:key route and decodes colon exactly once', async () => {
    render(
      <MemoryRouter initialEntries={['/rules/go%3Asql']}>
        <App />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'SQL Injection' })).toBeInTheDocument()
    })

    expect(api.getRule).toHaveBeenCalledWith('go:sql')
  })

  it('maintains active state on Rules list', async () => {
    render(
      <MemoryRouter initialEntries={['/rules']}>
        <Sidebar />
      </MemoryRouter>
    )

    const rulesLink = screen.getByRole('link', { name: /Rules/i })
    expect(rulesLink.className).toMatch(/bg-brand\/10|text-branddim/)
  })

  it('maintains active state on Rules detail', async () => {
    render(
      <MemoryRouter initialEntries={['/rules/go:sql']}>
        <Sidebar />
      </MemoryRouter>
    )

    const rulesLink = screen.getByRole('link', { name: /Rules/i })
    expect(rulesLink.className).toMatch(/bg-brand\/10|text-branddim/)
  })

  it('keeps Code Quality active on project shells', () => {
    render(
      <MemoryRouter initialEntries={['/code-quality/projects/synapse']}>
        <Sidebar />
      </MemoryRouter>
    )
    const link = screen.getByRole('link', { name: /Code Quality/i })
    expect(link.className).toMatch(/bg-brand\/10|text-branddim/)
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
})
