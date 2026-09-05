/**
 * Wire shapes for the two resources the API serializes through explicit view types.
 *
 * SOURCE OF TRUTH: `internal/adapter/httpapi/resource_view.go` (`engagementView`, `projectView`)
 * plus `projectSummaryResponse` in `internal/adapter/httpapi/project_handler.go`, which reuses
 * `projectView`'s field names and adds the two list-only enrichments.
 *
 * Engagements and projects used to answer with Go field names (`ID`, `SourceBinding`) while every
 * other resource answered in snake_case. The view types made them snake_case too. If a json tag
 * there changes, change this file, the mappers that read it, and the mock handlers in
 * `src/mocks/handlers.ts` in the same commit: `src/lib/api.contract.test.ts` pins all three
 * against one fixture and fails otherwise.
 */

export interface ScopeTargetWire {
  kind: string
  value: string
}

export interface BlackoutWire {
  from: string
  to: string
}

export interface RoEWire {
  allowed_tool_classes: string[]
  blackouts: BlackoutWire[]
}

export interface ScopeWire {
  in_scope: ScopeTargetWire[]
  out_of_scope: ScopeTargetWire[]
}

/** `engagementView`. `business_asset_id`, `project_id` and `timezone` are `omitempty`. */
export interface EngagementWire {
  id: string
  tenant_id: string
  project_id?: string
  business_asset_id?: string
  name: string
  client: string
  status: string
  scope: ScopeWire
  roe: RoEWire
  authorized_from: string | null
  authorized_to: string | null
  timezone?: string
  live_recon_enabled: boolean
  created_at: string
  updated_at: string
  /** List-view enrichment. Not part of `engagementView`; present only where the API adds it. */
  findings_count?: { total: number; critical: number; high: number; medium: number; low: number }
  /** List-view enrichment; see `findings_count`. */
  last_scan_date?: string | null
}

export interface SourceBindingWire {
  kind: string
  value: string
  ref?: string
  default_branch?: string
  base_ref?: string
}

/** `projectView`, and the identity half of `projectSummaryResponse`. `gate_id` is `omitempty`. */
export interface ProjectWire {
  id: string
  tenant_id: string
  name: string
  key: string
  source_binding: SourceBindingWire
  default_profile_by_lang: Record<string, string>
  gate_id?: string
  created_at: string
  updated_at: string
  /** List-only enrichment from `projectSummaryResponse`. Null when the project has none. */
  latest_analysis?: unknown
  /** List-only enrichment; see `latest_analysis`. */
  latest_job?: unknown
}

/** Every key `engagementView` serializes, in json-tag form. Ordered as the Go struct declares. */
export const ENGAGEMENT_WIRE_KEYS = [
  'id',
  'tenant_id',
  'project_id',
  'business_asset_id',
  'name',
  'client',
  'status',
  'scope',
  'roe',
  'authorized_from',
  'authorized_to',
  'timezone',
  'live_recon_enabled',
  'created_at',
  'updated_at',
] as const

/** Every key `projectView` serializes, in json-tag form. Ordered as the Go struct declares. */
export const PROJECT_WIRE_KEYS = [
  'id',
  'tenant_id',
  'name',
  'key',
  'source_binding',
  'default_profile_by_lang',
  'gate_id',
  'created_at',
  'updated_at',
] as const
