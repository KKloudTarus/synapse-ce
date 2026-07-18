import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { buildAnalyzedOverview, buildFailedGate, buildPassedGate, unavailablePercentage } from '../../../test/projectOverviewFixtures'
import { CodeLensToggle } from './CodeLensToggle'
import { OverviewIssueSummary } from './OverviewIssueSummary'
import { OverviewMetricCard } from './OverviewMetricCard'
import { OverviewMetricGrid } from './OverviewMetricGrid'
import { QualityGateBanner } from './QualityGateBanner'

describe('Project Overview components', () => {
  it('exposes the controlled lens selection accessibly', () => {
    const onChange = vi.fn()
    render(<CodeLensToggle value="overall" onChange={onChange} />)
    expect(screen.getByRole('group', { name: 'Overview lens' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Overall Code' })).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(screen.getByRole('button', { name: 'New Code' }))
    expect(onChange).toHaveBeenCalledWith('new-code')
  })

  it('renders passed and failed gate evidence without recomputing verdict', () => {
    render(<QualityGateBanner gate={buildPassedGate({ source: null })} />)
    expect(screen.getByText('Quality Gate Passed')).toBeInTheDocument()
    expect(screen.queryByText(/undefined|null/)).not.toBeInTheDocument()

    render(<QualityGateBanner gate={buildFailedGate()} />)
    expect(screen.getByText('Quality Gate Failed')).toBeInTheDocument()
    expect(screen.getByText('Release · Managed policy')).toBeInTheDocument()
    expect(screen.getByText('2 conditions failed')).toBeInTheDocument()
    const first = screen.getByText('New high issues')
    const second = screen.getByText('Coverage')
    expect(first.compareDocumentPosition(second) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(screen.getByText('2 — expected <= 0')).toBeInTheDocument()
    expect(screen.getByText('72.3% — expected >= 80%')).toBeInTheDocument()
  })

  it('uses singular copy for one failed gate condition', () => {
    const gate = buildFailedGate()
    render(<QualityGateBanner gate={{ ...gate, failedConditions: gate.failedConditions.slice(0, 1) }} />)
    expect(screen.getByText('1 condition failed')).toBeInTheDocument()
  })

  it('renders issue summaries without fabricating unavailable accepted issues', () => {
    const overview = buildAnalyzedOverview()
    render(<OverviewIssueSummary summary={overview.issueSummary} />)
    expect(screen.getByText('New Code issues')).toBeInTheDocument()
    expect(screen.getByText('Accepted issues (Overall Code)')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.queryByText('0')).not.toBeInTheDocument()
    expect(screen.getByText(/Accepted-issue tracking/i)).toBeInTheDocument()
  })

  it('renders metric cards with explicit non-color status cues', () => {
    const overview = buildAnalyzedOverview()
    render(<OverviewMetricCard card={{ key: 'security', kind: 'rating', label: 'Security', metric: overview.lenses.overall.security, detailTarget: null }} lensLabel="Overall Code" />)
    expect(screen.getByText('B')).toBeInTheDocument()
    expect(screen.getByText('Grade B')).toBeInTheDocument()
    expect(screen.getByText('Details not available yet')).toBeInTheDocument()

    render(<OverviewMetricCard card={{ key: 'coverage', kind: 'percentage', label: 'Coverage', metric: overview.lenses.overall.coverage, detailTarget: null }} lensLabel="Overall Code" />)
    expect(screen.getByText('72.3%')).toBeInTheDocument()
    expect(screen.getByText('Measured on Overall Code')).toBeInTheDocument()

    render(<OverviewMetricCard card={{ key: 'coverage', kind: 'percentage', label: 'Coverage', metric: { ...unavailablePercentage('coverage_not_supplied'), availability: 'not_supplied' }, detailTarget: null }} lensLabel="Overall Code" />)
    expect(screen.getByText('Not supplied')).toBeInTheDocument()
    expect(screen.getByText('No coverage report was supplied.')).toBeInTheDocument()
    expect(screen.queryByText('0%')).not.toBeInTheDocument()
    expect(screen.queryByText('100%')).not.toBeInTheDocument()
  })

  it('renders exactly six metric cards in fixed order for mixed availability', () => {
    const overview = buildAnalyzedOverview()
    render(<OverviewMetricGrid lens="new-code" metrics={overview.lenses.newCode} />)
    const headings = screen.getAllByRole('heading', { level: 3 }).map((heading) => heading.textContent)
    expect(headings).toEqual([
      'Security',
      'Reliability',
      'Maintainability',
      'Security Hotspots Reviewed',
      'Coverage',
      'Duplications',
    ])
    expect(screen.getAllByText('Details not available yet')).toHaveLength(6)
    expect(screen.getAllByText('—').length).toBeGreaterThan(0)
  })
})
