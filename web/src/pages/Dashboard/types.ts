import type { ComponentType } from 'react'
import type { BusinessAsset, DashboardSecurityOperations, Engagement, FleetCoverageSummary } from '../../lib/types'

export type DashboardData = {
  assets: BusinessAsset[]
  assetTotal: number
  engagements: Engagement[]
}

export interface StatCardProps {
  label: string
  value: number | string
  hint: string
  trend?: number
  trendDirection?: 'up' | 'down' | 'neutral'
  tone?: 'muted' | 'brand' | 'critical' | 'high' | 'medium' | 'accent' | 'info'
  severity?: 'success' | 'warning' | 'critical'
  icon: ComponentType<{ className?: string; 'aria-hidden'?: boolean | 'true' | 'false' }>
  className?: string
}

export interface DashboardHookResult {
  data: DashboardData | null
  error: string | null
  fleet: FleetCoverageSummary | null
  fleetError: string | null
  analytics: DashboardSecurityOperations | null
  analyticsError: string | null
  rangeDays: number
  setRangeDays: (days: number) => void
  highRiskAssets: number
  activeEngagements: number
  coverageGaps: number | null
  priorityAssets: BusinessAsset[]
  assessmentQueue: Engagement[]
  assetNames: Record<string, string>
}
