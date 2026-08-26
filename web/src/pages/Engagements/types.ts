import type { Engagement } from '../../lib/types'

export interface EngagementItem extends Engagement {
  repository?: string
  findingsCount?: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
  }
  lastScanDate?: string | null
}

export type EngagementStatusFilter = 'All' | 'Draft' | 'Active' | 'Completed' | 'Archived'
export type EngagementScopeFilter = 'All' | 'repo' | 'domain' | 'host' | 'url' | 'image' | 'cidr'

export type SortField = 'name' | 'repository' | 'status' | 'findings' | 'lastScanDate'
export type SortDirection = 'asc' | 'desc'
