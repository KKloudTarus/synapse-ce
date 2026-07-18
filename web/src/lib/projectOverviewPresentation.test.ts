import { describe, expect, it } from 'vitest'
import type { MetricAvailability, ProjectOverviewLens, UnavailableReason } from './projectOverview'
import {
  availabilityLabel,
  formatGateEvidenceValue,
  formatOverviewCount,
  formatOverviewPercentage,
  gateMetricLabel,
  gateSourceLabel,
  isValidCodeLens,
  metricCardsForLens,
  parseCodeLens,
  serializeCodeLens,
  unavailableReasonText,
} from './projectOverviewPresentation'

const unavailableReasons: UnavailableReason[] = [
  'no_analysis',
  'rating_not_available',
  'issue_lifecycle_not_available',
  'security_hotspots_not_available',
  'changed_line_metrics_not_available',
  'coverage_not_supplied',
  'no_executable_lines',
  'duplication_not_available',
]

describe('projectOverviewPresentation', () => {
  it('parses and serializes overview lens URL values', () => {
    expect(parseCodeLens(null)).toBe('overall')
    expect(parseCodeLens('')).toBe('overall')
    expect(parseCodeLens('overall')).toBe('overall')
    expect(parseCodeLens('new-code')).toBe('new-code')
    expect(parseCodeLens('new')).toBe('overall')
    expect(serializeCodeLens('overall')).toBe('overall')
    expect(serializeCodeLens('new-code')).toBe('new-code')
    expect(isValidCodeLens('overall')).toBe(true)
    expect(isValidCodeLens('bad')).toBe(false)
  })

  it('formats percentages and counts for display without mutating inputs', () => {
    const value = 72.34
    expect(formatOverviewPercentage(0)).toBe('0%')
    expect(formatOverviewPercentage(0.01)).toBe('<0.1%')
    expect(formatOverviewPercentage(0.04)).toBe('<0.1%')
    expect(formatOverviewPercentage(0.05)).toBe('0.1%')
    expect(formatOverviewPercentage(value)).toBe('72.3%')
    expect(formatOverviewPercentage(99.94)).toBe('99.9%')
    expect(formatOverviewPercentage(99.96)).toBe('99.9%')
    expect(formatOverviewPercentage(100)).toBe('100%')
    expect(value).toBe(72.34)
    expect(formatOverviewCount(0)).toBe('0')
    expect(formatOverviewCount(12345)).toBe('12,345')
  })

  it('maps availability and unavailable reasons to user copy', () => {
    const labels: Record<MetricAvailability, string> = {
      available: 'Available',
      unavailable: 'Unavailable',
      not_supplied: 'Not supplied',
      not_applicable: 'Not applicable',
    }
    for (const [status, label] of Object.entries(labels) as Array<[MetricAvailability, string]>) {
      expect(availabilityLabel(status)).toBe(label)
    }
    for (const reason of unavailableReasons) {
      const text = unavailableReasonText(reason)
      expect(text).not.toContain(reason)
      expect(text).not.toMatch(/_/)
    }
  })

  it('maps gate sources, metrics, and values', () => {
    expect(gateSourceLabel('default')).toBe('Built-in')
    expect(gateSourceLabel('repository')).toBe('Repository policy')
    expect(gateSourceLabel('managed')).toBe('Managed policy')
    expect(gateSourceLabel(null)).toBeNull()
    expect(gateMetricLabel('new_critical')).toBe('New critical issues')
    expect(gateMetricLabel('new_high')).toBe('New high issues')
    expect(gateMetricLabel('new_issues')).toBe('New issues')
    expect(gateMetricLabel('security_rating')).toBe('Security rating')
    expect(gateMetricLabel('coverage')).toBe('Coverage')
    expect(gateMetricLabel('duplication_density')).toBe('Duplications')
    expect(formatGateEvidenceValue('new_high', 2)).toBe('2')
    expect(formatGateEvidenceValue('coverage', 72.34)).toBe('72.3%')
    expect(formatGateEvidenceValue('coverage', 99.96)).toBe('99.9%')
    expect(formatGateEvidenceValue('security_rating', 2)).toBe('B')
  })

  it('builds six metric cards in fixed order for any availability mix', () => {
    const lens = overviewLens()
    expect(metricCardsForLens(lens).map((card) => card.label)).toEqual([
      'Security',
      'Reliability',
      'Maintainability',
      'Security Hotspots Reviewed',
      'Coverage',
      'Duplications',
    ])
    const unavailableLens = overviewLens('unavailable')
    expect(metricCardsForLens(unavailableLens).map((card) => card.label)).toEqual(
      metricCardsForLens(lens).map((card) => card.label),
    )
  })
})

function overviewLens(availability: MetricAvailability = 'available'): ProjectOverviewLens {
  const reason: UnavailableReason = 'changed_line_metrics_not_available'
  return {
    security: availability === 'available' ? { availability, grade: 'A', unavailableReason: null } : { availability, grade: null, unavailableReason: reason },
    reliability: availability === 'available' ? { availability, grade: 'B', unavailableReason: null } : { availability, grade: null, unavailableReason: reason },
    maintainability: availability === 'available' ? { availability, grade: 'C', unavailableReason: null } : { availability, grade: null, unavailableReason: reason },
    securityHotspotsReviewed:
      availability === 'available'
        ? { availability, value: 95, unavailableReason: null }
        : { availability, value: null, unavailableReason: reason },
    coverage:
      availability === 'available'
        ? { availability, value: 72.34, unavailableReason: null }
        : { availability, value: null, unavailableReason: reason },
    duplications:
      availability === 'available'
        ? { availability, value: 4.2, unavailableReason: null }
        : { availability, value: null, unavailableReason: reason },
  }
}
