import type {
  CountMetric,
  PercentageMetric,
  ProjectOverview,
  ProjectOverviewGate,
  RatingMetric,
  UnavailableReason,
} from '../lib/projectOverview'

export function availableRating(grade: 'A' | 'B' | 'C' | 'D' | 'E' = 'A'): RatingMetric {
  return { availability: 'available', grade, unavailableReason: null }
}

export function unavailableRating(reason: UnavailableReason = 'rating_not_available'): RatingMetric {
  return { availability: 'unavailable', grade: null, unavailableReason: reason }
}

export function availablePercentage(value = 72.34): PercentageMetric {
  return { availability: 'available', value, unavailableReason: null }
}

export function unavailablePercentage(reason: UnavailableReason = 'changed_line_metrics_not_available'): PercentageMetric {
  return { availability: 'unavailable', value: null, unavailableReason: reason }
}

export function availableCount(value = 4): CountMetric {
  return { availability: 'available', value, unavailableReason: null }
}

export function unavailableCount(reason: UnavailableReason = 'issue_lifecycle_not_available'): CountMetric {
  return { availability: 'unavailable', value: null, unavailableReason: reason }
}

export function buildPassedGate(overrides: Partial<ProjectOverviewGate> = {}): ProjectOverviewGate {
  return {
    status: 'passed',
    key: 'synapse-way',
    name: 'Synapse way',
    source: 'default',
    failedConditions: [],
    ...overrides,
  }
}

export function buildFailedGate(overrides: Partial<ProjectOverviewGate> = {}): ProjectOverviewGate {
  return {
    status: 'failed',
    key: 'release',
    name: 'Release',
    source: 'managed',
    failedConditions: [
      { metric: 'new_high', operator: '<=', threshold: 0, actual: 2 },
      { metric: 'coverage', operator: '>=', threshold: 80, actual: 72.34 },
    ],
    ...overrides,
  }
}

export function buildAnalyzedOverview(overrides: Partial<ProjectOverview> = {}): ProjectOverview {
  return {
    state: 'analyzed',
    project: { key: 'synapse', name: 'Synapse' },
    latestAnalysis: {
      id: 'analysis-1',
      createdAt: '2026-07-17T10:00:00Z',
      sourceRef: 'main',
      sourceCommit: 'abcdef1234567890',
      newCode: { firstAnalysis: false, hasBaseline: true, baselineAnalysisId: 'analysis-0' },
    },
    gate: buildFailedGate(),
    issueSummary: {
      newCodeTotal: availableCount(4),
      acceptedOverallTotal: unavailableCount('issue_lifecycle_not_available'),
    },
    lenses: {
      overall: {
        security: availableRating('B'),
        reliability: availableRating('A'),
        maintainability: availableRating('C'),
        securityHotspotsReviewed: unavailablePercentage('security_hotspots_not_available'),
        coverage: availablePercentage(72.34),
        duplications: availablePercentage(4.2),
      },
      newCode: {
        security: availableRating('A'),
        reliability: availableRating('B'),
        maintainability: unavailableRating('changed_line_metrics_not_available'),
        securityHotspotsReviewed: unavailablePercentage('security_hotspots_not_available'),
        coverage: unavailablePercentage('changed_line_metrics_not_available'),
        duplications: unavailablePercentage('changed_line_metrics_not_available'),
      },
    },
    ...overrides,
  }
}

export function buildNotAnalyzedOverview(overrides: Partial<ProjectOverview> = {}): ProjectOverview {
  return {
    state: 'not_analyzed',
    project: { key: 'synapse', name: 'Synapse' },
    latestAnalysis: null,
    gate: null,
    issueSummary: {
      newCodeTotal: unavailableCount('no_analysis'),
      acceptedOverallTotal: unavailableCount('no_analysis'),
    },
    lenses: {
      overall: {
        security: unavailableRating('no_analysis'),
        reliability: unavailableRating('no_analysis'),
        maintainability: unavailableRating('no_analysis'),
        securityHotspotsReviewed: unavailablePercentage('no_analysis'),
        coverage: unavailablePercentage('no_analysis'),
        duplications: unavailablePercentage('no_analysis'),
      },
      newCode: {
        security: unavailableRating('no_analysis'),
        reliability: unavailableRating('no_analysis'),
        maintainability: unavailableRating('no_analysis'),
        securityHotspotsReviewed: unavailablePercentage('no_analysis'),
        coverage: unavailablePercentage('no_analysis'),
        duplications: unavailablePercentage('no_analysis'),
      },
    },
    ...overrides,
  }
}
