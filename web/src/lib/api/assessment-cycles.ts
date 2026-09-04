import type {
  AssessmentCycle,
  AssessmentCycleDetail,
  AssessmentCycleListFilters,
  AssessmentCycleMember,
  AssessmentCycleMemberPage,
  AssessmentCyclePage,
  AssessmentLifecycle,
  CreateAssessmentRetestInput,
  CreateAssessmentRetestResponse,
} from '../types'
import { newIdempotencyKey, req } from './client'
import { mapEngagement } from './engagements'

const id = encodeURIComponent

function mapMember(value: any): AssessmentCycleMember {
  return {
    assessmentId: value.assessment_id ?? '',
    assessmentType: value.assessment_type ?? 'initial',
    predecessorAssessmentId: value.predecessor_assessment_id ?? '',
    retestNumber: Number(value.retest_number ?? 0),
    relationshipVersion: Number(value.relationship_version ?? 0),
    createdAt: value.created_at ?? '',
    createdBy: value.created_by ?? '',
    archivedAt: value.archived_at ?? null,
  }
}

function mapCycle(value: any): AssessmentCycle {
  return {
    id: value.id ?? '',
    name: value.name ?? '',
    boundaryKind: value.boundary_kind ?? 'standalone',
    businessAssetId: value.business_asset_id ?? '',
    projectId: value.project_id ?? '',
    status: value.status ?? 'open',
    rootAssessmentId: value.root_assessment_id ?? '',
    selectedHeadAssessmentId: value.selected_head_assessment_id ?? '',
    nextRetestNumber: Number(value.next_retest_number ?? 1),
    version: Number(value.version ?? 0),
    createdAt: value.created_at ?? '',
    updatedAt: value.updated_at ?? '',
    createdBy: value.created_by ?? '',
    updatedBy: value.updated_by ?? '',
  }
}

function mapDetail(value: any): AssessmentCycleDetail {
  return {
    cycle: mapCycle(value.cycle ?? {}),
    members: (value.members ?? []).map(mapMember),
    branchHeads: (value.branch_heads ?? []).map(mapMember),
  }
}

export const assessmentCyclesApi = {
  createRetest: async (assessmentId: string, input: CreateAssessmentRetestInput = {}): Promise<CreateAssessmentRetestResponse> => {
    const value = await req(`/engagements/${id(assessmentId)}/retests`, {
      method: 'POST',
      headers: { 'Idempotency-Key': input.idempotencyKey ?? newIdempotencyKey() },
      body: JSON.stringify({
        name: input.name ?? '',
        predecessor_assessment_id: input.predecessorAssessmentId ?? '',
        scope_strategy: input.scopeStrategy ?? 'copy',
        profile_strategy: input.profileStrategy ?? 'none',
        authorized_from: input.authorizedFrom ?? '',
        authorized_to: input.authorizedTo ?? '',
        timezone: input.timezone ?? '',
        roe: input.roe
          ? { allowed_tool_classes: input.roe.allowedToolClasses, blackouts: input.roe.blackouts }
          : undefined,
      }),
    })
    return {
      engagement: mapEngagement(value.engagement ?? {}),
      cycle: mapCycle(value.cycle ?? {}),
      member: mapMember(value.member ?? {}),
      inheritanceDiff: {
        scope: value.inheritance_diff?.scope ?? 'copy',
        authorization: value.inheritance_diff?.authorization ?? 'explicit_only',
        roe: value.inheritance_diff?.roe ?? 'explicit_only',
        scannerProfile: value.inheritance_diff?.scanner_profile ?? 'none',
      },
      warnings: value.warnings ?? [],
    }
  },

  assessmentLifecycle: async (assessmentId: string): Promise<AssessmentLifecycle> => {
    const value = await req(`/engagements/${id(assessmentId)}/lifecycle`)
    return { assessmentId: value.assessment_id ?? '', ...mapDetail(value) }
  },

  assessmentCycle: async (cycleId: string): Promise<AssessmentCycleDetail> =>
    mapDetail(await req(`/assessment-cycles/${id(cycleId)}`)),

  listAssessmentCycles: async (input: AssessmentCycleListFilters = {}): Promise<AssessmentCyclePage> => {
    const query = new URLSearchParams()
    if (input.status) query.set('status', input.status)
    if (input.boundaryKind) query.set('boundary_kind', input.boundaryKind)
    if (input.assessmentStatus) query.set('assessment_status', input.assessmentStatus)
    if (input.selectedHeadAssessmentId) query.set('selected_head_assessment_id', input.selectedHeadAssessmentId)
    if (input.assessmentType) query.set('assessment_type', input.assessmentType)
    if (input.scanStaleness) query.set('scan_staleness', input.scanStaleness)
    if (input.search) query.set('q', input.search)
    if (input.cursor) query.set('cursor', input.cursor)
    if (input.limit) query.set('limit', String(input.limit))
    const value = await req(`/assessment-cycles${query.size ? `?${query}` : ''}`)
    return {
      items: (value.items ?? []).map((item: any) => ({
        ...mapCycle(item),
        memberCount: Number(item.member_count ?? 0),
        activeBranchCount: Number(item.active_branch_count ?? 0),
        latestAssessmentId: item.latest_assessment_id ?? '',
        latestRetestNumber: Number(item.latest_retest_number ?? 0),
        members: (item.members ?? []).map(mapMember),
        membersNextCursor: item.members_next_cursor ?? '',
        rootSnapshotId: item.root_snapshot_id ?? '',
        currentSnapshotId: item.current_snapshot_id ?? '',
        selectedHeadLastScanAt: item.selected_head_last_scan_at ?? null,
        scanStaleness: item.scan_staleness ?? 'missing',
      })),
      nextCursor: value.next_cursor ?? '',
      migrationPending: (value.migration_pending ?? []).map((item: any) => ({
        assessmentId: item.assessment_id ?? '',
        name: item.name ?? '',
        status: item.status ?? '',
        boundaryKind: item.boundary_kind ?? 'standalone',
        businessAssetId: item.business_asset_id ?? '',
        updatedAt: item.updated_at ?? '',
      })),
      migrationPendingTotal: Number(value.migration_pending_total ?? 0),
    }
  },

  listAssessmentCycleMembers: async (cycleId: string, cursor = '', limit = 25): Promise<AssessmentCycleMemberPage> => {
    const query = new URLSearchParams({ limit: String(limit) })
    if (cursor) query.set('cursor', cursor)
    const value = await req(`/assessment-cycles/${id(cycleId)}/members?${query}`)
    return { items: (value.items ?? []).map(mapMember), nextCursor: value.next_cursor ?? '' }
  },

  archiveAssessmentCycle: async (cycleId: string, version: number): Promise<AssessmentCycleDetail> =>
    mapDetail(await req(`/assessment-cycles/${id(cycleId)}/archive`, {
      method: 'POST',
      headers: { 'Idempotency-Key': newIdempotencyKey(), 'If-Match': String(version) },
      body: '{}',
    })),
}
