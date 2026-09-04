import type {
  AssessmentCycle,
  AssessmentCycleDetail,
  AssessmentCycleMember,
  AssessmentCycleMemberPage,
  AssessmentCycleListFilters,
  AssessmentCyclePage,
  AssessmentClosureBranchState,
  AssessmentClosureCommitResult,
  AssessmentClosureCoverageDecisions,
  AssessmentClosureManifest,
  AssessmentClosurePathMember,
  AssessmentClosurePolicyResult,
  AssessmentClosurePreview,
  AssessmentClosurePreviewInput,
  AssessmentClosureReference,
  AssessmentClosureScopeProfileChange,
  AssessmentLifecycle,
  AssessmentReopenCommitResult,
  AssessmentReopenPreview,
  AssessmentRelationshipChangeRequest,
  AssessmentRelationshipCommitResult,
  AssessmentRelationshipPreview,
  CreateAssessmentRetestInput,
  CreateAssessmentRetestResponse,
} from '../types'
import { blobDownload, newIdempotencyKey, req } from './client'
import { mapEngagement } from './engagements'
import { mapAssessmentComparisonSummary } from './assessment-comparisons'

const id = encodeURIComponent

function mapMember(value: any): AssessmentCycleMember {
  return {
    assessmentId: value.assessment_id ?? '',
    assessmentType: value.assessment_type ?? 'initial',
    predecessorAssessmentId: value.predecessor_assessment_id ?? '',
    retestNumber: value.retest_number ?? 0,
    relationshipVersion: value.relationship_version ?? 0,
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
    activeClosureManifestId: value.active_closure_manifest_id ?? '',
    activeClosureCycleVersion: Number(value.active_closure_cycle_version ?? 0),
    nextRetestNumber: value.next_retest_number ?? 1,
    version: value.version ?? 0,
    createdAt: value.created_at ?? '',
    updatedAt: value.updated_at ?? '',
    createdBy: value.created_by ?? '',
    updatedBy: value.updated_by ?? '',
  }
}

function mapClosurePathMember(value: any): AssessmentClosurePathMember {
  return {
    pathPosition: Number(value.path_position ?? 0), assessmentId: value.assessment_id ?? '', assessmentType: value.assessment_type ?? 'initial',
    retestNumber: Number(value.retest_number ?? 0), relationshipVersion: Number(value.relationship_version ?? 0), snapshotId: value.snapshot_id ?? '',
  }
}

function mapClosureReference(value: any): AssessmentClosureReference {
  return {
    kind: value.kind ?? '', id: value.id ?? '', version: Number(value.version ?? 0), contentHash: value.content_hash ?? '',
    expiresAt: value.expires_at ?? null, metadata: value.metadata ?? null,
  }
}

function mapClosureBranch(value: any): AssessmentClosureBranchState {
  return { assessmentId: value.assessment_id ?? '', relationshipVersion: Number(value.relationship_version ?? 0), archived: Boolean(value.archived) }
}

function mapClosureScopeChange(value: any): AssessmentClosureScopeProfileChange {
  return { assessmentId: value.assessment_id ?? '', kind: value.kind ?? '', summary: value.summary ?? '' }
}

function mapClosureCoverage(value: any): AssessmentClosureCoverageDecisions {
  const mapDecision = (decision: any) => ({
    snapshotId: decision.snapshot_id ?? '', dimensionId: decision.dimension_id ?? '', state: decision.state ?? 'unknown',
    reasonCode: decision.reason_code ?? '', waived: Boolean(decision.waived),
  })
  return { initial: (value?.initial ?? []).map(mapDecision), final: (value?.final ?? []).map(mapDecision) }
}

function mapClosurePolicy(value: any): AssessmentClosurePolicyResult {
  return {
    policyVersion: value?.policy_version ?? '',
    blockers: (value?.blockers ?? []).map((blocker: any) => ({
      id: blocker.id ?? '', code: blocker.code ?? '', message: blocker.message ?? '', overrideable: Boolean(blocker.overrideable), overridden: Boolean(blocker.overridden),
    })),
    warnings: (value?.warnings ?? []).map((warning: any) => ({ code: warning.code ?? '', message: warning.message ?? '' })),
    coverageDecisions: mapClosureCoverage(value?.coverage_decisions), commitAllowed: Boolean(value?.commit_allowed),
  }
}

function mapClosureManifest(value: any): AssessmentClosureManifest {
  return {
    id: value.id ?? '', cycleId: value.cycle_id ?? '', manifestVersion: Number(value.manifest_version ?? 0), lifecycle: value.lifecycle ?? 'building',
    cycleVersion: Number(value.cycle_version ?? 0), rootAssessmentId: value.root_assessment_id ?? '', finalAssessmentId: value.final_assessment_id ?? '',
    initialSnapshotId: value.initial_snapshot_id ?? '', finalSnapshotId: value.final_snapshot_id ?? '', comparisonId: value.comparison_id ?? '',
    initialSnapshotHash: value.initial_snapshot_hash ?? '', finalSnapshotHash: value.final_snapshot_hash ?? '', comparisonHash: value.comparison_hash ?? '',
    canonicalInputHash: value.canonical_input_hash ?? '', contentHash: value.content_hash ?? '', policyVersion: value.policy_version ?? '',
    algorithmVersion: value.algorithm_version ?? '', fingerprintVersion: value.fingerprint_version ?? '', riskVersion: value.risk_version ?? '',
    rendererContractVersion: value.renderer_contract_version ?? '', coverageDecisions: mapClosureCoverage(value.coverage_decisions),
    scopeProfileChanges: (value.scope_profile_changes ?? []).map(mapClosureScopeChange), overrideBlockerIds: value.override_blocker_ids ?? [],
    nonFinalBranches: (value.non_final_branches ?? []).map(mapClosureBranch), path: (value.path ?? []).map(mapClosurePathMember),
    references: (value.references ?? []).map(mapClosureReference), reason: value.reason ?? '', overrideReason: value.override_reason ?? '',
    asOfAt: value.as_of_at ?? '', createdAt: value.created_at ?? '', createdBy: value.created_by ?? '', sealedAt: value.sealed_at ?? null,
    sealedBy: value.sealed_by ?? '', supersededAt: value.superseded_at ?? null,
  }
}

function closureBody(input: AssessmentClosurePreviewInput) {
  return { reason: input.reason, override_blocker_ids: input.overrideBlockerIds, override_reason: input.overrideReason }
}

function mapDetail(value: any): AssessmentCycleDetail {
  return {
    cycle: mapCycle(value.cycle ?? {}),
    members: (value.members ?? []).map(mapMember),
    branchHeads: (value.branch_heads ?? []).map(mapMember),
  }
}

function changeBody(input: AssessmentRelationshipChangeRequest) {
  return {
    command: input.command,
    assessment_id: input.assessmentId ?? '',
    new_predecessor_assessment_id: input.newPredecessorAssessmentId ?? '',
    selected_head_assessment_id: input.selectedHeadAssessmentId ?? '',
  }
}

function mapRelationshipPreview(value: any): AssessmentRelationshipPreview {
  return {
    cycleId: value.cycle_id ?? '', command: value.command ?? 'reparent_within_cycle', assessmentId: value.assessment_id ?? '',
    oldPredecessorAssessmentId: value.old_predecessor_assessment_id ?? '', newPredecessorAssessmentId: value.new_predecessor_assessment_id ?? '',
    oldSelectedHeadAssessmentId: value.old_selected_head_assessment_id ?? '', newSelectedHeadAssessmentId: value.new_selected_head_assessment_id ?? '',
    descendantAssessmentIds: value.descendant_assessment_ids ?? [],
    impact: {
      memberIds: value.impact?.member_ids ?? [], snapshotIds: value.impact?.snapshot_ids ?? [], identityIds: value.impact?.identity_ids ?? [],
      comparisonIds: value.impact?.comparison_ids ?? [], projectionIds: value.impact?.projection_ids ?? [],
    },
    locks: value.locks ?? [], reasonRequired: Boolean(value.reason_required), commitAllowed: Boolean(value.commit_allowed),
    cycleVersion: Number(value.cycle_version ?? 0), expiresAt: value.expires_at ?? '', previewToken: value.preview_token ?? '',
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
    if (input.producer) query.set('producer', input.producer)
    if (input.findingKind) query.set('finding_kind', input.findingKind)
    if (input.reviewState) query.set('review_state', input.reviewState)
    if (input.changePresence) query.set('change_presence', input.changePresence)
    if (input.changeSeverity) query.set('change_severity', input.changeSeverity)
    if (input.scanStaleness) query.set('scan_staleness', input.scanStaleness)
    if (input.search) query.set('q', input.search)
    if (input.cursor) query.set('cursor', input.cursor)
    if (input.limit) query.set('limit', String(input.limit))
    const value = await req(`/assessment-cycles${query.size ? `?${query}` : ''}`)
    return {
      items: (value.items ?? []).map((item: any) => ({
        ...mapCycle(item),
        memberCount: item.member_count ?? 0,
        activeBranchCount: item.active_branch_count ?? 0,
        latestAssessmentId: item.latest_assessment_id ?? '',
        latestRetestNumber: item.latest_retest_number ?? 0,
        members: (item.members ?? []).map(mapMember),
        membersNextCursor: item.members_next_cursor ?? '',
        rootSnapshotId: item.root_snapshot_id ?? '',
        currentSnapshotId: item.current_snapshot_id ?? '',
        comparisonId: item.comparison_id ?? '',
        comparisonStatus: item.comparison_status ?? '',
        comparisonSummary: item.comparison_summary ? mapAssessmentComparisonSummary(item.comparison_summary) : null,
        activeClosureManifestId: item.active_closure_manifest_id ?? '',
        selectedHeadLastScanAt: item.selected_head_last_scan_at ?? null,
        scanStaleness: item.scan_staleness ?? 'missing',
      })),
      nextCursor: value.next_cursor ?? '',
      migrationPending: (value.migration_pending ?? []).map((item: any) => ({
        assessmentId: item.assessment_id ?? '', name: item.name ?? '', status: item.status ?? '',
        boundaryKind: item.boundary_kind ?? 'standalone', businessAssetId: item.business_asset_id ?? '', updatedAt: item.updated_at ?? '',
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

  previewAssessmentRelationshipChange: async (cycleId: string, input: AssessmentRelationshipChangeRequest): Promise<AssessmentRelationshipPreview> =>
    mapRelationshipPreview(await req(`/assessment-cycles/${id(cycleId)}/relationship-previews`, { method: 'POST', body: JSON.stringify(changeBody(input)) })),

  commitAssessmentRelationshipChange: async (cycleId: string, version: number, input: AssessmentRelationshipChangeRequest, previewToken: string, reason: string, idempotencyKey: string): Promise<AssessmentRelationshipCommitResult> => {
    const value = await req(`/assessment-cycles/${id(cycleId)}/relationship-commits`, {
      method: 'POST', headers: { 'If-Match': `"${version}"`, 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ ...changeBody(input), preview_token: previewToken, reason }),
    })
    return { cycle: mapCycle(value.cycle ?? {}), replacedComparisonIds: value.replaced_comparison_ids ?? [], replacementComparisonIds: value.replacement_comparison_ids ?? [] }
  },

  previewAssessmentClosure: async (cycleId: string, input: AssessmentClosurePreviewInput): Promise<AssessmentClosurePreview> => {
    const value = await req(`/assessment-cycles/${id(cycleId)}/closure-previews`, { method: 'POST', body: JSON.stringify(closureBody(input)) })
    return {
      cycleId: value.cycle_id ?? '', cycleVersion: Number(value.cycle_version ?? 0), manifestVersion: Number(value.manifest_version ?? 0),
      finalAssessmentId: value.final_assessment_id ?? '', path: (value.path ?? []).map(mapClosurePathMember), nonFinalBranches: (value.non_final_branches ?? []).map(mapClosureBranch),
      initialSnapshotId: value.initial_snapshot_id ?? '', finalSnapshotId: value.final_snapshot_id ?? '', comparisonId: value.comparison_id ?? '',
      policy: mapClosurePolicy(value.policy), references: (value.references ?? []).map(mapClosureReference),
      scopeProfileChanges: (value.scope_profile_changes ?? []).map(mapClosureScopeChange), rendererContractVersion: value.renderer_contract_version ?? '',
      expiresAt: value.expires_at ?? '', previewToken: value.preview_token ?? '',
    }
  },

  commitAssessmentClosure: async (cycleId: string, version: number, input: AssessmentClosurePreviewInput, previewToken: string, idempotencyKey: string): Promise<AssessmentClosureCommitResult> => {
    const value = await req(`/assessment-cycles/${id(cycleId)}/closure-commits`, {
      method: 'POST', headers: { 'If-Match': `"${version}"`, 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ ...closureBody(input), preview_token: previewToken }),
    })
    return { cycle: mapCycle(value.cycle ?? {}), manifest: mapClosureManifest(value.manifest ?? {}), reportJobId: value.report_job_id ?? '' }
  },

  previewAssessmentReopen: async (cycleId: string): Promise<AssessmentReopenPreview> => {
    const value = await req(`/assessment-cycles/${id(cycleId)}/reopen-previews`, { method: 'POST', body: '{}' })
    return {
      cycleId: value.cycle_id ?? '', cycleVersion: Number(value.cycle_version ?? 0), manifest: mapClosureManifest(value.manifest ?? {}),
      impact: value.impact ?? '', expiresAt: value.expires_at ?? '', previewToken: value.preview_token ?? '',
    }
  },

  commitAssessmentReopen: async (cycleId: string, version: number, previewToken: string, reason: string, idempotencyKey: string): Promise<AssessmentReopenCommitResult> => {
    const value = await req(`/assessment-cycles/${id(cycleId)}/reopen-commits`, {
      method: 'POST', headers: { 'If-Match': `"${version}"`, 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ preview_token: previewToken, reason }),
    })
    return { cycle: mapCycle(value.cycle ?? {}), supersededManifest: mapClosureManifest(value.superseded_manifest ?? {}) }
  },

  listAssessmentClosureManifests: async (cycleId: string): Promise<AssessmentClosureManifest[]> => {
    const value = await req(`/assessment-cycles/${id(cycleId)}/closure-manifests`)
    return (value.items ?? []).map(mapClosureManifest)
  },

  downloadAssessmentClosureReport: (cycleId: string, manifestId: string): Promise<void> =>
    blobDownload(`/api/v1/assessment-cycles/${id(cycleId)}/closure-manifests/${id(manifestId)}/report`, `assessment-cycle-${cycleId}-closure-${manifestId}.json`),
}
