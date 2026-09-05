import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Finding, ScanResult, Severity, Vulnerability } from '../../lib/types'
import { FindingsTab, findingSearchIndex } from './FindingsTab'

vi.mock('../../lib/api', () => ({
  ApiError: class ApiError extends Error {
    status = 500
  },
  api: {
    addFindingComment: vi.fn().mockResolvedValue(undefined),
    createFinding: vi.fn().mockResolvedValue(undefined),
    findingComments: vi.fn().mockResolvedValue([]),
    findingRetests: vi.fn().mockResolvedValue([]),
    judgments: vi.fn().mockResolvedValue([]),
    recordRetest: vi.fn().mockResolvedValue(undefined),
    setFindingAssignee: vi.fn().mockResolvedValue(undefined),
    updateFindingStatus: vi.fn().mockResolvedValue(undefined),
    verifyFinding: vi.fn().mockResolvedValue(undefined),
    writeups: vi.fn().mockResolvedValue([]),
  },
}))

function finding(id: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    engagementId: 'eng-1',
    title: `Finding ${id}`,
    description: '',
    severity: 'high',
    cvssVector: '',
    cwe: 'CWE-79',
    status: 'open',
    dedupKey: id,
    kev: false,
    riskScore: 10,
    class: 'third_party',
    scope: 'production',
    reachability: '',
    impact: '',
    priority: 2,
    assignee: '',
    version: 1,
    kind: 'sca',
    evidenceScore: 0,
    proposedBy: '',
    complianceControls: [],
    ...overrides,
  }
}

function vulnerability(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: 'CVE-2020-7774',
    source: 'grype',
    severity: 'high',
    cvssVector: '',
    cvssScore: 7.5,
    component: 'y18n',
    version: '3.2.1',
    fixedVersion: '4.0.1',
    description: '',
    kev: false,
    epss: 0,
    path: ['nodegoat@1.3.0', 'yargs@13.3.2', 'y18n@3.2.1'],
    direct: false,
    sources: ['grype'],
    confidence: 'high',
    ...overrides,
  } as Vulnerability
}

function scanWith(vulns: Vulnerability[]): ScanResult {
  return {
    target: '',
    scanMode: 'full',
    languages: [],
    components: [],
    dependencies: [],
    vulnerabilities: vulns,
    licenses: [],
    findings: [],
    toolVersions: {},
    vulnDBSnapshot: '',
    completeness: { warning: '' },
    licenseCoverage: {},
    manifest: {},
    findingQuality: {},
    debugEvents: [],
  } as unknown as ScanResult
}

function LocationProbe() {
  const location = useLocation()
  return <span data-testid="search">{location.search}</span>
}

function renderTab({
  findings,
  scan = null,
  initialEntry = '/engagements/eng-1/findings',
  readOnly = false,
}: {
  findings: Finding[]
  scan?: ScanResult | null
  initialEntry?: string
  readOnly?: boolean
}) {
  const setFilter = vi.fn()
  function Harness() {
    return (
      <>
        <FindingsTab
          findings={findings}
          scan={scan}
          engagementId="eng-1"
          filter="all"
          setFilter={setFilter}
          focusedFindingId=""
          onUpdated={() => {}}
          onReload={() => {}}
          readOnly={readOnly}
          readOnlyReason={readOnly ? 'This engagement is archived.' : undefined}
        />
        <LocationProbe />
      </>
    )
  }
  render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/engagements/:id/findings" element={<Harness />} />
      </Routes>
    </MemoryRouter>,
  )
  return { setFilter }
}

const search = () => screen.getByLabelText('Search findings') as HTMLInputElement
const query = () => screen.getByTestId('search').textContent ?? ''

describe('findingSearchIndex', () => {
  it('indexes the package, the dependency path, the CVE id and the priority label', () => {
    const index = findingSearchIndex(finding('f-1', { priority: 1 }), vulnerability())
    for (const needle of ['y18n', 'yargs', 'cve-2020-7774', 'p1', '3.2.1']) {
      expect(index).toContain(needle)
    }
  })

  it('still indexes the identity carried by the dedup key with no scan loaded', () => {
    const index = findingSearchIndex(finding('f-1', { dedupKey: 'sca:CVE-2020-7774:yargs-parser' }), undefined)
    expect(index).toContain('yargs-parser')
    expect(index).toContain('cve-2020-7774')
  })
})

describe('FindingsTab search', () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn()
  })

  it('matches the package shown in the row via text', () => {
    const rows = [finding('f-1'), finding('f-2', { title: 'Unrelated', dedupKey: 'f-2' })]
    const scan = scanWith([vulnerability()])
    // The table keys the vulnerability off the finding's dedup key.
    rows[0].dedupKey = 'vuln:CVE-2020-7774:y18n:3.2.1'
    renderTab({ findings: rows, scan })

    fireEvent.change(search(), { target: { value: 'yargs' } })
    expect(screen.getByText('Finding f-1')).toBeInTheDocument()
    expect(screen.queryByText('Unrelated')).not.toBeInTheDocument()
  })

  it('matches a priority label', () => {
    renderTab({ findings: [finding('f-1', { priority: 1 }), finding('f-2', { priority: 3 })] })

    fireEvent.change(search(), { target: { value: 'P1' } })
    expect(screen.getByText('Finding f-1')).toBeInTheDocument()
    expect(screen.queryByText('Finding f-2')).not.toBeInTheDocument()
  })

  it('matches a CVE id carried by the dedup key', () => {
    renderTab({
      findings: [
        finding('f-1', { dedupKey: 'sca:CVE-2020-7774:y18n' }),
        finding('f-2', { dedupKey: 'sca:CVE-2019-0001:other' }),
      ],
    })

    fireEvent.change(search(), { target: { value: 'CVE-2020-7774' } })
    expect(screen.getByText('Finding f-1')).toBeInTheDocument()
    expect(screen.queryByText('Finding f-2')).not.toBeInTheDocument()
  })
})

describe('FindingsTab URL state', () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn()
  })

  it('puts the search, page size and sort in the query string', () => {
    renderTab({ findings: [finding('f-1'), finding('f-2')] })

    fireEvent.change(search(), { target: { value: 'f-1' } })
    expect(query()).toContain('q=f-1')

    fireEvent.click(screen.getByRole('button', { name: /Severity/ }))
    expect(query()).toContain('sort=severity')
    expect(query()).toContain('dir=desc')
  })

  it('restores a shared link: severity, search and page size', () => {
    const { setFilter } = renderTab({
      findings: [finding('f-1'), finding('f-2', { title: 'Other' })],
      initialEntry: '/engagements/eng-1/findings?sev=critical&q=f-1&size=50',
    })

    expect(setFilter).toHaveBeenCalledWith('critical')
    expect(search().value).toBe('f-1')
    expect((screen.getByLabelText('Findings per page') as HTMLElement).textContent).toContain('50')
  })

  it('shows 25 rows per page by default and 50 once the control is used', () => {
    const rows = Array.from({ length: 30 }, (_, i) => finding(`f-${String(i).padStart(2, '0')}`))
    renderTab({ findings: rows })

    // Header row plus one row per finding on the page.
    expect(screen.getAllByRole('row').length).toBe(26)
    expect(screen.getByText('30').closest('span')?.parentElement?.textContent).toContain('Showing')

    fireEvent.click(screen.getByLabelText('Findings per page'))
    fireEvent.click(screen.getByRole('option', { name: '50 / page' }))
    expect(query()).toContain('size=50')
    expect(screen.getAllByRole('row').length).toBe(31)
  })
})

describe('FindingsTab sorting', () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn()
  })

  it('orders by severity, most severe first, and reverses on a second click', () => {
    const rows = [
      finding('low', { severity: 'low' as Severity, title: 'Low one' }),
      finding('crit', { severity: 'critical' as Severity, title: 'Critical one' }),
      finding('med', { severity: 'medium' as Severity, title: 'Medium one' }),
    ]
    renderTab({ findings: rows })

    fireEvent.click(screen.getByRole('button', { name: /Severity/ }))
    const first = () => within(screen.getAllByRole('row')[1]).getByText(/one$/).textContent
    expect(first()).toBe('Critical one')

    fireEvent.click(screen.getByRole('button', { name: /Severity/ }))
    expect(first()).toBe('Low one')
  })

  it('marks the sorted column for assistive tech', () => {
    renderTab({ findings: [finding('f-1')] })
    fireEvent.click(screen.getByRole('button', { name: /^Pri/ }))

    const header = screen.getByRole('columnheader', { name: /Pri/ })
    expect(header).toHaveAttribute('aria-sort', 'ascending')
  })
})

describe('FindingsTab on an archived engagement', () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn()
  })

  it('disables New finding and the per-row status control, and says why', () => {
    renderTab({ findings: [finding('f-1')], readOnly: true })

    expect(screen.getByRole('button', { name: /New finding/ })).toBeDisabled()
    expect(screen.getByText('This engagement is archived.')).toBeInTheDocument()
    expect(screen.getByLabelText(/Triage status for Finding f-1/)).toBeDisabled()
  })

  it('leaves them enabled otherwise', () => {
    renderTab({ findings: [finding('f-1')] })

    expect(screen.getByRole('button', { name: /New finding/ })).toBeEnabled()
    expect(screen.getByLabelText(/Triage status for Finding f-1/)).toBeEnabled()
  })
})
