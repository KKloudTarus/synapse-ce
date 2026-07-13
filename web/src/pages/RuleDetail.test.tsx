import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import RuleDetail from './RuleDetail'
import { api, ApiError } from '../lib/api'
import type { RuleDetail as RuleDetailType } from '../lib/types'

vi.mock('../lib/api', () => ({
  api: {
    getRule: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    constructor(public status: number, message: string) {
      super(message)
    }
  },
}))

function renderRuleDetail(initialEntry = '/rules/go:sql-injection', state?: any) {
  return render(
    <MemoryRouter initialEntries={[{ pathname: initialEntry, state }]}>
      <Routes>
        <Route path="/rules/:key" element={<RuleDetail />} />
        <Route path="/rules" element={<div data-testid="rules-list">Rules List Fallback</div>} />
      </Routes>
    </MemoryRouter>
  )
}

describe('RuleDetail Page', () => {
  const mockRule: RuleDetailType = {
    key: 'go:sql-injection',
    name: 'SQL Injection',
    language: 'go',
    type: 'vulnerability',
    qualities: ['security'],
    defaultSeverity: 'high',
    tags: ['owasp'],
    cwe: ['CWE-89'],
    owasp: ['A03:2021'],
    description: 'A simple description with <script>alert(1)</script>',
    rationale: 'Why it matters',
    remediation: 'How to fix it',
    compliantExample: 'good code',
    noncompliantExample: 'bad code',
    remediationEffort: 30,
    detection: 'ast',
  }

  const otherRule: RuleDetailType = {
    ...mockRule,
    key: 'py:xss',
    name: 'XSS Vulnerability',
    language: 'python',
    description: 'Cross-site scripting',
  }

  beforeEach(() => {
    vi.mocked(api.getRule).mockReset()
  })

  it('renders loading state initially', async () => {
    vi.mocked(api.getRule).mockReturnValue(new Promise(() => {}))
    renderRuleDetail()
    expect(screen.getByRole('link', { name: /Back to rules/i })).toBeInTheDocument()
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })

  it('renders rule details correctly', async () => {
    vi.mocked(api.getRule).mockResolvedValue(mockRule)
    renderRuleDetail()

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'SQL Injection' })).toBeInTheDocument()
    })

    expect(screen.getByText('go:sql-injection')).toBeInTheDocument()
    expect(screen.getByText(/A simple description with <script>alert\(1\)<\/script>/)).toBeInTheDocument()
    expect(screen.getByText('Why it matters')).toBeInTheDocument()
    expect(screen.getByText('How to fix it')).toBeInTheDocument()
    expect(screen.getByText('good code')).toBeInTheDocument()
    expect(screen.getByText('bad code')).toBeInTheDocument()
  })

  it('renders dedicated 404 state', async () => {
    vi.mocked(api.getRule).mockRejectedValue(new ApiError(404, 'Rule not found'))
    renderRuleDetail()

    await waitFor(() => {
      expect(screen.getByText('Rule not found')).toBeInTheDocument()
      expect(screen.getByText('The requested rule key does not exist in the catalog.')).toBeInTheDocument()
    })
  })

  it('renders generic error state', async () => {
    vi.mocked(api.getRule).mockRejectedValue(new ApiError(500, 'Server error'))
    renderRuleDetail()

    await waitFor(() => {
      expect(screen.getByText('Failed to load rule details')).toBeInTheDocument()
      expect(screen.getByText('Server error')).toBeInTheDocument()
    })
  })

  it('retries on generic error', async () => {
    vi.mocked(api.getRule).mockRejectedValueOnce(new ApiError(500, 'Server error'))
    renderRuleDetail()

    await waitFor(() => {
      expect(screen.getByText('Server error')).toBeInTheDocument()
    })

    vi.mocked(api.getRule).mockResolvedValue(mockRule)
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))

    await waitFor(() => {
      expect(screen.getByText('SQL Injection')).toBeInTheDocument()
    })
  })

  it('navigates back to list with preserved query params', async () => {
    vi.mocked(api.getRule).mockResolvedValue(mockRule)
    renderRuleDetail('/rules/go:sql-injection', { from: '?q=sql' })

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'SQL Injection' })).toBeInTheDocument()
    })

    const backLink = screen.getByRole('link', { name: /Back to rules/i })
    expect(backLink.getAttribute('href')).toBe('/rules?q=sql')
  })

  it('navigates back to list via direct visit fallback', async () => {
    vi.mocked(api.getRule).mockResolvedValue(mockRule)
    renderRuleDetail('/rules/go:sql-injection')

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'SQL Injection' })).toBeInTheDocument()
    })

    const backLink = screen.getByRole('link', { name: /Back to rules/i })
    expect(backLink.getAttribute('href')).toBe('/rules')
  })

  it('does not overwrite new rule with stale response when key changes', async () => {
    // First key loads slowly
    let resolveFirst!: (val: RuleDetailType) => void
    vi.mocked(api.getRule).mockImplementationOnce(
      () => new Promise<RuleDetailType>((resolve) => { resolveFirst = resolve }),
    )

    const { createMemoryRouter, RouterProvider } = await import('react-router-dom')

    const router = createMemoryRouter(
      [
        {
          path: '/rules/:key',
          element: <RuleDetail />,
        },
      ],
      {
        initialEntries: ['/rules/go:sql-injection'],
      },
    )

    render(<RouterProvider router={router} />)

    // Loading state for first key
    expect(screen.getByText('Loading…')).toBeInTheDocument()

    // Second request resolves immediately
    vi.mocked(api.getRule).mockResolvedValueOnce(otherRule)

    // Navigate in the same instance
    await waitFor(() => {
      router.navigate('/rules/py:xss')
    })

    // Second request resolves and displays
    expect(
      await screen.findByRole('heading', {
        name: 'XSS Vulnerability',
      }),
    ).toBeInTheDocument()

    // Now resolve the stale first response
    resolveFirst(mockRule)

    await waitFor(() => {
      expect(
        screen.getByRole('heading', {
          name: 'XSS Vulnerability',
        }),
      ).toBeInTheDocument()
    })

    expect(
      screen.queryByRole('heading', {
        name: 'SQL Injection',
      }),
    ).not.toBeInTheDocument()
  })
})
