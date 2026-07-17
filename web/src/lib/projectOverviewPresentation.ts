import type {
  CountMetric,
  MetricAvailability,
  PercentageMetric,
  ProjectOverviewGateMetric,
  ProjectOverviewGateSource,
  ProjectOverviewLens,
  RatingMetric,
  UnavailableReason,
} from './projectOverview'

export type CodeLens = 'overall' | 'new-code'
export type OverviewMetricKey =
  | 'security'
  | 'reliability'
  | 'maintainability'
  | 'securityHotspotsReviewed'
  | 'coverage'
  | 'duplications'

export type OverviewMetricCardModel =
  | {
      key: OverviewMetricKey
      kind: 'rating'
      label: string
      metric: RatingMetric
      detailTarget: null
    }
  | {
      key: OverviewMetricKey
      kind: 'percentage'
      label: string
      metric: PercentageMetric
      detailTarget: null
    }

const percentFormatter = new Intl.NumberFormat(undefined, {
  maximumFractionDigits: 1,
})

export function parseCodeLens(value: string | null): CodeLens {
  return value === 'new-code' ? 'new-code' : 'overall'
}

export function serializeCodeLens(value: CodeLens): string {
  return value
}

export function isValidCodeLens(value: string | null): value is CodeLens {
  return value === 'overall' || value === 'new-code'
}

export function formatOverviewPercentage(value: number): string {
  return `${percentFormatter.format(value)}%`
}

export function formatOverviewCount(value: number): string {
  return value.toLocaleString()
}

export function availabilityLabel(status: MetricAvailability): string {
  switch (status) {
    case 'available':
      return 'Available'
    case 'unavailable':
      return 'Unavailable'
    case 'not_supplied':
      return 'Not supplied'
    case 'not_applicable':
      return 'Not applicable'
  }
}

export function unavailableReasonText(reason: UnavailableReason): string {
  switch (reason) {
    case 'no_analysis':
      return 'No completed analysis is available.'
    case 'rating_not_available':
      return 'This rating is not available for the latest analysis.'
    case 'issue_lifecycle_not_available':
      return 'Accepted-issue tracking will be available with issue lifecycle support.'
    case 'security_hotspots_not_available':
      return 'Security hotspot review is not available yet.'
    case 'changed_line_metrics_not_available':
      return 'Changed-line metrics are not available for this analysis.'
    case 'coverage_not_supplied':
      return 'No coverage report was supplied.'
    case 'no_executable_lines':
      return 'No executable lines were found.'
    case 'duplication_not_available':
      return 'Duplication data is not available for this analysis.'
  }
}

export function gateSourceLabel(source: ProjectOverviewGateSource | null): string | null {
  switch (source) {
    case 'default':
      return 'Built-in'
    case 'repository':
      return 'Repository policy'
    case 'managed':
      return 'Managed policy'
    case null:
      return null
  }
}

export function gateMetricLabel(metric: ProjectOverviewGateMetric): string {
  switch (metric) {
    case 'new_critical':
      return 'New critical issues'
    case 'new_high':
      return 'New high issues'
    case 'new_medium':
      return 'New medium issues'
    case 'new_secret':
      return 'New secrets'
    case 'new_vulnerability':
      return 'New vulnerabilities'
    case 'new_issues':
      return 'New issues'
    case 'total_critical':
      return 'Total critical issues'
    case 'duplication_density':
      return 'Duplications'
    case 'coverage':
      return 'Coverage'
    case 'security_rating':
      return 'Security rating'
    case 'reliability_rating':
      return 'Reliability rating'
    case 'maintainability_rating':
      return 'Maintainability rating'
  }
}

export function formatGateEvidenceValue(metric: ProjectOverviewGateMetric, value: number): string {
  if (metric === 'coverage' || metric === 'duplication_density') return formatOverviewPercentage(value)
  if (metric.endsWith('_rating')) return gradeFromNumericGateValue(value)
  return Number.isInteger(value) ? formatOverviewCount(value) : value.toLocaleString(undefined, { maximumFractionDigits: 2 })
}

export function metricCardsForLens(lens: ProjectOverviewLens): OverviewMetricCardModel[] {
  return [
    { key: 'security', kind: 'rating', label: 'Security', metric: lens.security, detailTarget: null },
    { key: 'reliability', kind: 'rating', label: 'Reliability', metric: lens.reliability, detailTarget: null },
    { key: 'maintainability', kind: 'rating', label: 'Maintainability', metric: lens.maintainability, detailTarget: null },
    {
      key: 'securityHotspotsReviewed',
      kind: 'percentage',
      label: 'Security Hotspots Reviewed',
      metric: lens.securityHotspotsReviewed,
      detailTarget: null,
    },
    { key: 'coverage', kind: 'percentage', label: 'Coverage', metric: lens.coverage, detailTarget: null },
    { key: 'duplications', kind: 'percentage', label: 'Duplications', metric: lens.duplications, detailTarget: null },
  ]
}

export function countMetricDisplay(metric: CountMetric): { value: string; label: string; reason: string | null } {
  if (metric.availability === 'available' && metric.value !== null) {
    return { value: formatOverviewCount(metric.value), label: 'Available', reason: null }
  }
  return {
    value: '—',
    label: availabilityLabel(metric.availability),
    reason: metric.unavailableReason ? unavailableReasonText(metric.unavailableReason) : null,
  }
}

export function overviewDetailTarget(): null {
  return null
}

function gradeFromNumericGateValue(value: number): string {
  switch (Math.round(value)) {
    case 1:
      return 'A'
    case 2:
      return 'B'
    case 3:
      return 'C'
    case 4:
      return 'D'
    case 5:
      return 'E'
    default:
      return value.toLocaleString(undefined, { maximumFractionDigits: 2 })
  }
}
