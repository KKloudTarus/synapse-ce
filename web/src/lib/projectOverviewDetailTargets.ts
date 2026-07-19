import {
  projectAnalysisPath,
  type ProjectAnalysisFocus,
  type ProjectCodeLens,
} from './projectAnalysisNavigation'
import type { OverviewMetricCardModel } from './projectOverviewPresentation'

export interface OverviewDetailTarget {
  destination: 'analysis' | 'hotspots'
  focus?: ProjectAnalysisFocus
  lens: ProjectCodeLens
  to: string
  label: string
}

export function overviewDetailTarget(
  projectKey: string,
  lens: ProjectCodeLens,
  card: OverviewMetricCardModel,
): OverviewDetailTarget | null {
  if (!metricHasValue(card)) return null
  if (card.key === 'securityHotspotsReviewed') {
    return {
      destination: 'hotspots',
      lens,
      to: `/code-quality/projects/${encodeURIComponent(projectKey)}/hotspots?lens=${lens}`,
      label: 'View security hotspots',
    }
  }
  if (lens === 'new-code' && (card.key === 'coverage' || card.key === 'duplications')) return null

  const focus: ProjectAnalysisFocus = card.key
  return {
    destination: 'analysis',
    focus,
    lens,
    to: projectAnalysisPath(projectKey, focus, lens),
    label: `View ${card.label} details`,
  }
}

function metricHasValue(card: OverviewMetricCardModel): boolean {
  if (card.metric.availability !== 'available') return false
  return card.kind === 'rating' ? card.metric.grade !== null : card.metric.value !== null
}
