import { render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { CodeQualityReport, Finding } from '../../lib/types'
import { CodeQualityReportView } from './CodeQualityReportView'

const finding: Finding = {
  id: 'f1', engagementId: 'e1', title: 'Nested control flow (web/src/App.tsx:42)', description: '', severity: 'medium', cvssVector: '', cwe: '', status: 'open', dedupKey: 'quality:nested', kev: false, riskScore: 0, class: '', scope: '', reachability: '', impact: '', priority: 3, assignee: '', version: 1, kind: 'quality', evidenceScore: 0, proposedBy: '', complianceControls: [],
}

const report: CodeQualityReport = {
  inventory: [
    { language: 'TypeScript', files: 20, codeLines: 1500, commentLines: 80, blankLines: 120, functions: 90, functionsKnown: true },
    { language: 'Go', files: 40, codeLines: 3200, commentLines: 150, blankLines: 200, functions: 0, functionsKnown: false },
  ],
  findings: [finding],
  duplication: {
    totalLines: 4700,
    duplicatedLines: 235,
    files: 2,
    blocks: [{ tokens: 85, occurrences: [{ file: 'internal/a.go', startLine: 10, endLine: 20 }, { file: 'internal/b.go', startLine: 30, endLine: 40 }] }],
  },
  rating: { security: 'A', reliability: 'C', maintainability: 'D', techDebtMinutes: 135, debtRatioPct: 2.8, linesOfCode: 4700 },
}

const originalGetBoundingClientRect = Element.prototype.getBoundingClientRect

beforeEach(() => {
  Element.prototype.getBoundingClientRect = vi.fn(() => ({ width: 800, height: 600, top: 0, left: 0, bottom: 600, right: 800, x: 0, y: 0, toJSON: () => {} }))
  Object.defineProperty(HTMLElement.prototype, 'offsetHeight', { configurable: true, value: 600 })
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', { configurable: true, value: 600 })
})

afterEach(() => { Element.prototype.getBoundingClientRect = originalGetBoundingClientRect })

describe('CodeQualityReportView', () => {
  it('renders ratings, measures, and languages', () => {
    render(<CodeQualityReportView report={report} empty={<div>Unavailable</div>} />)

    expect(screen.getByLabelText('Security rating A')).toBeInTheDocument()
    expect(screen.getByLabelText('Reliability rating C')).toBeInTheDocument()
    expect(screen.getByLabelText('Maintainability rating D')).toBeInTheDocument()
    expect(screen.getByText('Worst security issue severity')).toBeInTheDocument()
    expect(screen.getByText('Worst reliability issue severity')).toBeInTheDocument()
    expect(screen.getByText('2.80% technical-debt ratio')).toBeInTheDocument()
    expect(screen.getByText('2h 15m')).toBeInTheDocument()
    expect(screen.getByText('4,700')).toBeInTheDocument()
    expect(screen.getByText('5.0%')).toBeInTheDocument()

    const languageTable = screen.getAllByRole('table')[0]
    const cells = within(languageTable).getAllByRole('cell')
    expect(cells[0]).toHaveTextContent('Go')
    expect(within(languageTable).getByText('n/a')).toBeInTheDocument()
    expect(within(languageTable).getByText('TypeScript')).toBeInTheDocument()
  })

  it('discloses when duplicated blocks are limited', () => {
    const blocks = Array.from({ length: 21 }, (_, index) => ({ tokens: index + 1, occurrences: [{ file: `file-${index}.go`, startLine: 1, endLine: 2 }] }))
    render(<CodeQualityReportView report={{ ...report, duplication: { ...report.duplication, blocks } }} empty={<div>Unavailable</div>} />)
    expect(screen.getByText('Showing 20 of 21')).toBeInTheDocument()
  })

  it('renders duplicate locations and quality findings', () => {
    render(<CodeQualityReportView report={report} empty={<div>Unavailable</div>} />)

    expect(screen.getByText('85 tokens · 2 locations')).toBeInTheDocument()
    expect(screen.getByText('internal/a.go')).toBeInTheDocument()
    expect(screen.getByText('lines 10–20')).toBeInTheDocument()
    expect(screen.getByText('Nested control flow (web/src/App.tsx:42)')).toBeInTheDocument()
  })

  it('renders factual empty sections for a completed report', () => {
    render(<CodeQualityReportView report={{ ...report, inventory: [], findings: [], duplication: { blocks: [], duplicatedLines: 0, totalLines: 0, files: 0 } }} empty={<div>Unavailable</div>} />)

    expect(screen.getByText('No source files detected in this analysis.')).toBeInTheDocument()
    expect(screen.getByText('No duplicated code blocks were detected.')).toBeInTheDocument()
    expect(screen.getByText('No code-quality issues were detected in this analysis.')).toBeInTheDocument()
    expect(screen.queryByText('Unavailable')).not.toBeInTheDocument()
  })

  it('renders the caller unavailable state when no report exists', () => {
    render(<CodeQualityReportView report={undefined} empty={<div>Unavailable</div>} />)
    expect(screen.getByText('Unavailable')).toBeInTheDocument()
  })
})
