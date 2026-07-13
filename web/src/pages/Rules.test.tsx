import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import Rules from './Rules'
import { api, ApiError } from '../lib/api'
import type { RuleSummary } from '../lib/types'

vi.mock('../lib/api', () => ({
  api: {
    listRules: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    constructor(public status: number, message: string) {
      super(message)
    }
  },
}))

function renderRules(initialUrl = '/rules') {
  return render(
    <MemoryRouter initialEntries={[initialUrl]}>
      <Rules />
    </MemoryRouter>
  )
}

describe('Rules Page', () => {
  const mockRules: RuleSummary[] = [
    {
      key: 'go:sql',
      name: 'SQL Injection',
      language: 'go',
      type: 'vulnerability',
      qualities: ['security'],
      defaultSeverity: 'high',
      tags: ['owasp'],
      cwe: ['CWE-89'],
      owasp: ['A03:2021'],
      description: 'SQL injection vulnerability',
      remediationEffort: 30,
      detection: 'ast',
    },
  ]

  const originalGetBoundingClientRect = Element.prototype.getBoundingClientRect

  beforeEach(() => {
    vi.mocked(api.listRules).mockReset()

    window.ResizeObserver = class ResizeObserver {
      constructor(private cb: ResizeObserverCallback) {}
      observe(target: Element) {
        this.cb([{ target, contentRect: target.getBoundingClientRect() } as ResizeObserverEntry], this)
      }
      unobserve() {}
      disconnect() {}
    }
    Element.prototype.getBoundingClientRect = vi.fn(() => ({
      width: 1000,
      height: 800,
      top: 0,
      left: 0,
      bottom: 800,
      right: 1000,
      x: 0,
      y: 0,
      toJSON: () => {},
    }))
    Object.defineProperty(HTMLElement.prototype, 'offsetHeight', { configurable: true, value: 800 })
    Object.defineProperty(HTMLElement.prototype, 'clientHeight', { configurable: true, value: 800 })
  })

  afterEach(() => {
    Element.prototype.getBoundingClientRect = originalGetBoundingClientRect
    delete (window as any).ResizeObserver
  })

  it('makes exactly one initial API request when no filters', async () => {
    vi.mocked(api.listRules).mockResolvedValue(mockRules)
    renderRules()

    await waitFor(() => {
      expect(screen.getAllByText('SQL Injection').length).toBeGreaterThan(0)
    })

    expect(api.listRules).toHaveBeenCalledTimes(1)
    expect(api.listRules).toHaveBeenCalledWith()
  })

  it('makes exactly two API requests for initially filtered URL', async () => {
    vi.mocked(api.listRules)
      .mockResolvedValueOnce(mockRules)  // catalog
      .mockResolvedValue(mockRules)      // filtered

    renderRules('/rules?q=sql')

    await waitFor(() => {
      expect(screen.getAllByText('SQL Injection').length).toBeGreaterThan(0)
    })

    // Wait for all effects to settle
    await waitFor(() => {
      expect(api.listRules).toHaveBeenCalledTimes(2)
    })

    // Verify: call 0 = catalog (no args), call 1 = filtered (with filters)
    expect(vi.mocked(api.listRules).mock.calls[0]).toEqual([])
    expect(vi.mocked(api.listRules).mock.calls[1][0]).toEqual(
      expect.objectContaining({ query: 'sql' }),
    )

    // Confirm it stays at 2, not 3
    await new Promise((r) => setTimeout(r, 100))
    expect(api.listRules).toHaveBeenCalledTimes(2)
  })

  it('reuses catalogRules when filters are cleared', async () => {
    vi.mocked(api.listRules).mockResolvedValue(mockRules)
    renderRules('/rules?q=sql')

    await waitFor(() => {
      expect(api.listRules).toHaveBeenCalledTimes(2)
    })

    // Clear filters
    const clearBtn = screen.getByRole('button', { name: 'Clear search' })
    fireEvent.click(clearBtn)

    await waitFor(() => {
      expect(api.listRules).toHaveBeenCalledTimes(2)
      expect(screen.getByText('1 rules')).toBeInTheDocument()
    })
  })

  it('renders loading state initially', async () => {
    vi.mocked(api.listRules).mockReturnValue(new Promise(() => {}))
    renderRules()
    expect(screen.getByRole('heading', { name: 'Rules' })).toBeInTheDocument()
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })

  it('renders initial error and retry', async () => {
    vi.mocked(api.listRules).mockRejectedValueOnce(new ApiError(500, 'Network error'))
    vi.mocked(api.listRules).mockResolvedValue(mockRules)
    renderRules()

    await waitFor(() => {
      expect(screen.getByText('Failed to load catalog')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))

    await waitFor(() => {
      expect(screen.getAllByText('SQL Injection').length).toBeGreaterThan(0)
    })
  })

  it('renders filtered error with visible Retry that works', async () => {
    vi.mocked(api.listRules).mockResolvedValueOnce(mockRules) // catalog
    renderRules()

    await waitFor(() => {
      expect(screen.getAllByText('SQL Injection').length).toBeGreaterThan(0)
    })

    // Trigger filter — filtered request fails
    vi.mocked(api.listRules).mockRejectedValueOnce(new ApiError(500, 'Filter error'))
    const searchInput = screen.getByRole('textbox', { name: 'Search rules' })
    fireEvent.change(searchInput, { target: { value: 'test' } })

    await waitFor(() => {
      expect(screen.getByText('Failed to load filtered results')).toBeInTheDocument()
    })

    // Previous results are still visible
    expect(screen.getAllByText('SQL Injection').length).toBeGreaterThan(0)

    // Retry button is visible and clickable
    const retryBtn = screen.getByRole('button', { name: 'Retry' })
    expect(retryBtn).toBeVisible()

    const callsBefore = vi.mocked(api.listRules).mock.calls.length
    vi.mocked(api.listRules).mockResolvedValueOnce([]) // success on retry

    fireEvent.click(retryBtn)

    await waitFor(() => {
      // One more filtered call was made
      expect(vi.mocked(api.listRules).mock.calls.length).toBe(callsBefore + 1)
      // Error disappears
      expect(screen.queryByText('Failed to load filtered results')).not.toBeInTheDocument()
    })
  })

  it('renders full empty catalog state', async () => {
    vi.mocked(api.listRules).mockResolvedValue([])
    renderRules()

    await waitFor(() => {
      expect(screen.getByText('No rules are available.')).toBeInTheDocument()
    })
  })

  it('renders no-match state', async () => {
    vi.mocked(api.listRules)
      .mockResolvedValueOnce(mockRules) // catalog
      .mockResolvedValue([])            // filtered

    renderRules('/rules?q=nomatch')

    await waitFor(() => {
      expect(screen.getByText('No rules match these filters.')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Clear all filters' })).toBeInTheDocument()
    })
  })

  it('debounces search input and applies to URL', async () => {
    vi.mocked(api.listRules).mockResolvedValue(mockRules)
    renderRules()

    await waitFor(() => {
      expect(screen.getAllByText('SQL Injection').length).toBeGreaterThan(0)
    })

    const searchInput = screen.getByRole('textbox', { name: 'Search rules' })
    fireEvent.change(searchInput, { target: { value: 'test' } })

    expect(api.listRules).toHaveBeenCalledTimes(1)

    await waitFor(() => {
      expect(api.listRules).toHaveBeenCalledTimes(2)
      expect(vi.mocked(api.listRules).mock.calls[1][0]).toEqual(expect.objectContaining({ query: 'test' }))
    }, { timeout: 500 })
  })

  it('clears search with Escape', async () => {
    vi.mocked(api.listRules).mockResolvedValue(mockRules)
    renderRules('/rules?q=test')

    await waitFor(() => {
      expect(screen.getByRole('textbox', { name: 'Search rules' })).toHaveValue('test')
    })

    const searchInput = screen.getByRole('textbox', { name: 'Search rules' })
    fireEvent.keyDown(searchInput, { key: 'Escape' })

    await waitFor(() => {
      expect(searchInput).toHaveValue('')
    })
  })

  it('renders active filter chips and clears them', async () => {
    vi.mocked(api.listRules).mockResolvedValue(mockRules)
    renderRules('/rules?type=vulnerability')

    await waitFor(() => {
      expect(screen.getAllByText(/Vulnerability/i).length).toBeGreaterThan(0)
    })

    const removeBtn = screen.getByRole('button', { name: 'Remove Vulnerability filter' })
    fireEvent.click(removeBtn)

    await waitFor(() => {
      expect(screen.queryByLabelText('Remove Vulnerability filter')).not.toBeInTheDocument()
    })
  })

  it('renders Clear all button', async () => {
    vi.mocked(api.listRules).mockResolvedValue(mockRules)
    renderRules('/rules?type=vulnerability')

    await waitFor(() => {
      const clearAllBtn = screen.getByRole('button', { name: 'Clear all' })
      expect(clearAllBtn).toBeInTheDocument()
    })
  })

  it('virtualizes large rule catalogs for desktop and mobile', async () => {
    // Generate a fixture with 1000 rules to trigger virtualization constraints
    const largeCatalog: RuleSummary[] = Array.from({ length: 1000 }).map((_, i) => ({
      ...mockRules[0],
      key: `rule-${i}`,
      name: `Virtual Rule ${i}`,
    }))

    vi.mocked(api.listRules).mockResolvedValue(largeCatalog)
    renderRules()

    await waitFor(() => {
      // Must have the table semantics for Desktop
      const table = screen.getByRole('table')
      expect(table).toBeInTheDocument()
      expect(table).toHaveAttribute('aria-rowcount', '1001')

      // Must have the list semantics for Mobile cards
      const mobileList = screen.getByLabelText('Rule results')
      expect(mobileList).toBeInTheDocument()
      expect(mobileList).toHaveAttribute('aria-rowcount', '1000')
    })

    // Desktop: DOM should not have one row for every item
    const rows = screen.getAllByRole('row')
    expect(rows.length).toBeLessThan(100)

    // Mobile: DOM should not have one card for every item
    const cards = screen.getAllByRole('heading', { name: /Virtual Rule/ })
    expect(cards.length).toBeLessThan(100)

    // The first visible items should retain links and metadata
    const firstRuleName = screen.getAllByText('Virtual Rule 0')[0]
    expect(firstRuleName).toBeInTheDocument()
    expect(firstRuleName.closest('a')).toHaveAttribute('href', '/rules/rule-0')
  })
})
