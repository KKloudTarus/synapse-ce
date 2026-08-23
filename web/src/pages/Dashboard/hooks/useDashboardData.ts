import { useState } from 'react'
import { useFetch } from '../../../hooks'
import { api } from '../../../lib/api'
import type { BusinessAsset, DashboardSecurityOperations, FleetCoverageSummary } from '../../../lib/types'
import type { DashboardData, DashboardHookResult } from '../types'

const ENGAGEMENT_ORDER = ['active', 'draft', 'completed', 'archived'] as const
const POSTURE_WEIGHT: Record<string, number> = { critical: 5, high_risk: 4, attention: 3, unknown: 2, good: 1 }
const CRITICALITY_WEIGHT: Record<BusinessAsset['criticality'], number> = { critical: 4, high: 3, medium: 2, low: 1 }

async function loadAllAssets(): Promise<{ assets: BusinessAsset[]; assetTotal: number }> {
  const first = await api.listBusinessAssets('limit=200')
  if (first.total <= first.items.length) return { assets: first.items, assetTotal: first.total }
  const offsets = Array.from({ length: Math.ceil(first.total / 200) - 1 }, (_, index) => (index + 1) * 200)
  const pages = await Promise.all(offsets.map((offset) => api.listBusinessAssets(`limit=200&offset=${offset}`)))
  return { assets: [first.items, ...pages.map((page) => page.items)].flat(), assetTotal: first.total }
}

export function useDashboardData(): DashboardHookResult {
  const [rangeDays, setRangeDays] = useState(30)

  const { data, error } = useFetch<DashboardData>(
    () =>
      Promise.all([loadAllAssets(), api.listEngagements()]).then(([assetResult, engagements]) => ({
        ...assetResult,
        engagements,
      })),
    { deps: [] },
  )

  const { data: fleet, error: fleetError } = useFetch<FleetCoverageSummary>(
    () => api.fleetCoverageSummary(),
    { deps: [] },
  )

  const { data: analytics, error: analyticsError } = useFetch<DashboardSecurityOperations>(
    () => api.dashboardSecurityOperations(rangeDays),
    { deps: [rangeDays] },
  )

  if (!data) {
    return {
      data: null,
      error,
      fleet,
      fleetError,
      analytics,
      analyticsError,
      rangeDays,
      setRangeDays,
      highRiskAssets: 0,
      activeEngagements: 0,
      coverageGaps: null,
      priorityAssets: [],
      assessmentQueue: [],
      assetNames: {},
    }
  }

  const assetNames = Object.fromEntries(data.assets.map((asset) => [asset.id, asset.name]))
  const highRiskAssets = data.assets.filter((asset) =>
    ['critical', 'high_risk'].includes(asset.posture ?? 'unknown'),
  ).length
  const activeEngagements = data.engagements.filter(
    (engagement) => engagement.status.toLowerCase() === 'active',
  ).length
  const coverageGaps = fleet
    ? Object.entries(fleet.rowsByVerdict).reduce(
        (total, [verdict, count]) => total + (verdict === 'covered' ? 0 : count),
        0,
      )
    : null

  const priorityAssets = [...data.assets]
    .filter((asset) => (asset.posture ?? 'unknown') !== 'good' && asset.lifecycle !== 'retired')
    .sort((left, right) => {
      const postureDelta =
        (POSTURE_WEIGHT[right.posture ?? 'unknown'] ?? 0) - (POSTURE_WEIGHT[left.posture ?? 'unknown'] ?? 0)
      return (
        postureDelta ||
        CRITICALITY_WEIGHT[right.criticality] - CRITICALITY_WEIGHT[left.criticality] ||
        left.name.localeCompare(right.name)
      )
    })
    .slice(0, 4)

  const assessmentQueue = [...data.engagements]
    .sort((left, right) => {
      const leftStatus = ENGAGEMENT_ORDER.indexOf(left.status.toLowerCase() as (typeof ENGAGEMENT_ORDER)[number])
      const rightStatus = ENGAGEMENT_ORDER.indexOf(right.status.toLowerCase() as (typeof ENGAGEMENT_ORDER)[number])
      return (
        (leftStatus < 0 ? ENGAGEMENT_ORDER.length : leftStatus) -
          (rightStatus < 0 ? ENGAGEMENT_ORDER.length : rightStatus) ||
        Date.parse(right.createdAt ?? '') - Date.parse(left.createdAt ?? '')
      )
    })
    .slice(0, 6)

  return {
    data,
    error,
    fleet,
    fleetError,
    analytics,
    analyticsError,
    rangeDays,
    setRangeDays,
    highRiskAssets,
    activeEngagements,
    coverageGaps,
    priorityAssets,
    assessmentQueue,
    assetNames,
  }
}
