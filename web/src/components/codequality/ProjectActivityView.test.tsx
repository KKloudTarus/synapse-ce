import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ProjectActivityView } from './ProjectActivityView'

const analysis = {
  id: 'a1', createdAt: '2026-07-16T12:00:00Z', origin: 'server' as const, ci: null, sourceRef: 'main', sourceCommit: 'abcdef1234567890',
  gate: { passed: false, results: [{ condition: { metric: 'new_high', op: '<=', threshold: 0 }, actual: 1, passed: false }] }, gateInfo: { key: 'synapse-way', name: 'Synapse way', source: 'default' as const }, issues: { total: 2, byKind: {}, bySeverity: { critical: 1 }, byStatus: {} },
  newCode: { previousId: '', counts: { total: 2, byKind: {}, bySeverity: { critical: 1 }, byStatus: {} }, rating: { security: 'E' as const, reliability: 'A' as const, maintainability: null } },
  delta: null, measures: {}, coverage: null,
  duplication: { blocks: [], duplicatedLines: 0, totalLines: 0, files: 0 }, rating: { security: 'E' as const, reliability: 'A' as const, maintainability: 'A' as const, techDebtMinutes: 0, debtRatioPct: 0, linesOfCode: 10 },
}

describe('ProjectActivityView', () => {
  it('labels the first baseline, explains the gate, and does not fabricate coverage', () => {
    render(<ProjectActivityView analyses={[analysis]} />)
    expect(screen.getByText(/first analysis/i)).toBeInTheDocument()
    expect(screen.getByText(/Line coverage is unavailable/i)).toBeInTheDocument()
    expect(screen.getAllByText('Gate failed')).not.toHaveLength(0)
    expect(screen.getByText('New high issues')).toBeInTheDocument()
    expect(screen.getByText(/no previous successful result/i)).toBeInTheDocument()
  })

  it('omits coverage direction when the immediate predecessor has no coverage', () => {
    const older = { ...analysis, id: 'a0', createdAt: '2026-07-14T12:00:00Z', coverage: { coveredLines: 80, totalLines: 100 } }
    const missing = { ...analysis, id: 'a1', createdAt: '2026-07-15T12:00:00Z', coverage: null }
    const current = { ...analysis, id: 'a2', createdAt: '2026-07-16T12:00:00Z', coverage: { coveredLines: 75, totalLines: 100 } }
    render(<ProjectActivityView analyses={[current, missing, older]} />)
    fireEvent.click(screen.getByRole('combobox', { name: 'Trend metric' }))
    fireEvent.click(screen.getByRole('option', { name: 'Line coverage' }))
    expect(screen.queryByText('Regressing')).not.toBeInTheDocument()
    expect(screen.queryByText('Improving')).not.toBeInTheDocument()
  })

  it('switches to scoped New Code metrics with an accessible toggle', () => {
    render(<ProjectActivityView analyses={[analysis]} />)
    const toggle = screen.getByRole('button', { name: 'New Code' })
    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('combobox', { name: 'Trend metric' })).toHaveTextContent('New issues')
    expect(screen.queryByText(/Line coverage is unavailable/i)).not.toBeInTheDocument()
  })

  it('omits unavailable grades from the trend', () => {
    const unknown = { ...analysis, rating: { ...analysis.rating, security: '?' as const } }
    render(<ProjectActivityView analyses={[unknown]} />)
    fireEvent.click(screen.getByRole('combobox', { name: 'Trend metric' }))
    fireEvent.click(screen.getByRole('option', { name: 'Security rating' }))
    expect(screen.getByText(/Rating is unavailable because the analysis did not provide a grade/i)).toBeInTheDocument()
    expect(screen.queryByLabelText(/Security rating trend/)).not.toBeInTheDocument()
  })

  it('marks a pipeline-recorded analysis and links its run', () => {
    const fromCI = {
      ...analysis,
      id: 'ci-1',
      origin: 'ci' as const,
      ci: { provider: 'github-actions', runUrl: 'https://github.com/acme/app/actions/runs/7', runId: '7', branch: 'main', actor: 'octocat' },
    }
    render(<ProjectActivityView analyses={[fromCI, analysis]} />)
    expect(screen.getByText(/from CI · github-actions/i)).toBeInTheDocument()
    const link = screen.getByRole('link', { name: /pipeline run #7/i })
    expect(link).toHaveAttribute('href', 'https://github.com/acme/app/actions/runs/7')
    // The server analysis beside it carries no such marker.
    expect(screen.getAllByText(/from CI/i)).toHaveLength(1)
  })

  it('loads older history on demand', () => {
    const onLoadOlder = vi.fn()
    render(<ProjectActivityView analyses={[analysis]} hasOlder onLoadOlder={onLoadOlder} />)
    fireEvent.click(screen.getByRole('button', { name: 'Load older analyses' }))
    expect(onLoadOlder).toHaveBeenCalledOnce()
    expect(screen.queryByText(/first analysis/i)).not.toBeInTheDocument()
  })
})
