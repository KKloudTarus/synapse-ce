import type {
  AssessmentComparison,
  AssessmentComparisonChangeFlag,
  AssessmentComparisonItem,
  AssessmentComparisonItemPage,
  AssessmentComparisonMode,
  AssessmentComparisonReviewResult,
  AssessmentComparisonStatus,
} from '../types'
import { newIdempotencyKey, req } from './client'

const id = encodeURIComponent

function mapRatio(value: any) {
  return {
    numerator: Number(value?.numerator ?? 0),
    denominator: Number(value?.denominator ?? 0),
    naReason: value?.na_reason ?? '',
  }
}

function mapSeverityCounts(value: any) {
  return {
    critical: Number(value?.critical ?? 0), high: Number(value?.high ?? 0), medium: Number(value?.medium ?? 0),
    low: Number(value?.low ?? 0), info: Number(value?.info ?? 0), unknown: Number(value?.unknown ?? 0),
  }
}

function mapObservation(value: any) {
  if (!value?.observed_at) return null
  return {
    severity: value.severity ?? 'unknown', componentVersion: value.component_version ?? '', location: value.location ?? '',
    reachability: value.reachability ?? '', evidenceDigest: value.evidence_digest ?? '', observedAt: value.observed_at,
    scanner: {
      scanRunId: value.scanner?.scan_run_id ?? '', laneKey: value.scanner?.lane_key ?? '', toolName: value.scanner?.tool_name ?? '',
      toolVersion: value.scanner?.tool_version ?? '', ruleId: value.scanner?.rule_id ?? '',
    },
  }
}

export function mapAssessmentComparisonSummary(value: any) {
  return {
    comparisonId: value?.comparison_id ?? '',
    baselineSnapshotId: value?.baseline_snapshot_id ?? '',
    currentSnapshotId: value?.current_snapshot_id ?? '',
    riskModelVersion: Number(value?.risk_model_version ?? 0),
    fixedRate: mapRatio(value?.fixed_rate),
    countReduction: mapRatio(value?.count_reduction),
    riskReduction: mapRatio(value?.risk_reduction),
    fixedCount: Number(value?.fixed_count ?? 0),
    baselineCount: Number(value?.baseline_count ?? 0),
    currentCount: Number(value?.current_count ?? 0),
    baselineRisk: Number(value?.baseline_risk ?? 0),
    currentRisk: Number(value?.current_risk ?? 0),
    newCount: Number(value?.new_count ?? 0),
    reopenedCount: Number(value?.reopened_count ?? 0),
    stillDetectedCount: Number(value?.still_detected_count ?? 0),
    notEvaluatedCount: Number(value?.not_evaluated_count ?? 0),
    reviewCount: Number(value?.review_count ?? 0),
    newRisk: Number(value?.new_risk ?? 0),
    reopenedRisk: Number(value?.reopened_risk ?? 0),
    baselineSeverity: mapSeverityCounts(value?.baseline_severity),
    currentSeverity: mapSeverityCounts(value?.current_severity),
  }
}

export function mapAssessmentComparison(value: any): AssessmentComparison {
  return {
    id: value?.id ?? '',
    cycleId: value?.cycle_id ?? '',
    baselineSnapshotId: value?.baseline_snapshot_id ?? '',
    currentSnapshotId: value?.current_snapshot_id ?? '',
    mode: value?.mode ?? 'lifecycle',
    inputHash: value?.input_hash ?? '',
    algorithmVersion: Number(value?.algorithm_version ?? 0),
    fingerprintVersion: Number(value?.fingerprint_version ?? 0),
    riskModelVersion: Number(value?.risk_model_version ?? 0),
    coveragePolicyVersion: Number(value?.coverage_policy_version ?? 0),
    status: value?.status ?? 'queued',
    version: Number(value?.version ?? 0),
    attempts: Number(value?.attempts ?? 0),
    failureCode: value?.failure_code ?? '',
    contentHash: value?.content_hash ?? '',
    summary: mapAssessmentComparisonSummary(value?.summary),
    createdAt: value?.created_at ?? '',
    updatedAt: value?.updated_at ?? '',
    completedAt: value?.completed_at ?? null,
    supersededAt: value?.superseded_at ?? null,
    supersededBy: value?.superseded_by ?? '',
  }
}

function mapItem(value: any): AssessmentComparisonItem {
  return {
    id: value?.id ?? '',
    position: Number(value?.position ?? 0),
    identityId: value?.identity_id ?? '',
    producerKind: value?.producer_kind ?? '',
    findingKind: value?.finding_kind ?? '',
    targetCanonical: value?.target_canonical ?? '',
    baselineObservationId: value?.baseline_observation_id ?? '',
    currentObservationId: value?.current_observation_id ?? '',
    baselineObservation: mapObservation(value?.baseline_observation),
    currentObservation: mapObservation(value?.current_observation),
    presence: value?.presence || undefined,
    neutralPresence: value?.neutral_presence || undefined,
    changeFlags: value?.change_flags ?? [],
    coverageDecision: value?.coverage_decision ?? '',
    matchMethods: value?.match_methods ?? [],
    verificationId: value?.verification_id ?? '',
    verificationState: value?.verification_state ?? '',
    fixedBasis: value?.fixed_basis ?? '',
    baselineActionable: Boolean(value?.baseline_actionable),
    currentActionable: Boolean(value?.current_actionable),
    comparableBaseline: Boolean(value?.comparable_baseline),
    baselineRiskMilli: Number(value?.baseline_risk_milli ?? 0),
    currentRiskMilli: Number(value?.current_risk_milli ?? 0),
    reviewCandidateIds: value?.review_candidate_ids ?? [],
    reviewCandidates: (value?.review_candidates ?? []).map((candidate: any) => ({
      id: candidate?.id ?? '',
      sourceObservationIds: candidate?.source_observation_ids ?? [],
    })),
  }
}

export const assessmentComparisonsApi = {
  createAssessmentComparison: async (input: {
    baselineSnapshotId: string
    currentSnapshotId: string
    mode: AssessmentComparisonMode
    idempotencyKey?: string
  }): Promise<{ comparison: AssessmentComparison; created: boolean }> => {
    const value = await req('/assessment-comparisons', {
      method: 'POST',
      headers: { 'Idempotency-Key': input.idempotencyKey ?? newIdempotencyKey() },
      body: JSON.stringify({
        baseline_snapshot_id: input.baselineSnapshotId,
        current_snapshot_id: input.currentSnapshotId,
        mode: input.mode,
      }),
    })
    return { comparison: mapAssessmentComparison(value?.comparison), created: Boolean(value?.created) }
  },

  assessmentComparison: async (comparisonId: string): Promise<AssessmentComparison> =>
    mapAssessmentComparison(await req(`/assessment-comparisons/${id(comparisonId)}`)),

  assessmentComparisonItems: async (comparisonId: string, input: {
    cursor?: string
    limit?: number
    presence?: string
    changeFlag?: AssessmentComparisonChangeFlag
    severity?: string
    producer?: string
    findingKind?: string
    disposition?: string
    reviewState?: string
  } = {}): Promise<AssessmentComparisonItemPage> => {
    const query = new URLSearchParams()
    if (input.cursor) query.set('cursor', input.cursor)
    if (input.limit) query.set('limit', String(input.limit))
    if (input.presence) query.set('presence', input.presence)
    if (input.changeFlag) query.set('change_flag', input.changeFlag)
    if (input.severity) query.set('severity', input.severity)
    if (input.producer) query.set('producer', input.producer)
    if (input.findingKind) query.set('finding_kind', input.findingKind)
    if (input.disposition) query.set('disposition', input.disposition)
    if (input.reviewState) query.set('review_state', input.reviewState)
    const value = await req(`/assessment-comparisons/${id(comparisonId)}/items${query.size ? `?${query}` : ''}`)
    return { items: (value?.items ?? []).map(mapItem), nextCursor: value?.next_cursor ?? '' }
  },

  reviewAssessmentComparisonItem: async (input: {
    comparisonId: string
    itemId: string
    comparisonVersion: number
    action: 'confirm' | 'unlink'
    candidateId: string
    sourceObservationId: string
    targetObservationId?: string
    reason: string
    idempotencyKey?: string
  }): Promise<AssessmentComparisonReviewResult> => {
    const value = await req(`/assessment-comparisons/${id(input.comparisonId)}/items/${id(input.itemId)}/${input.action}`, {
      method: 'POST',
      headers: {
        'Idempotency-Key': input.idempotencyKey ?? newIdempotencyKey(),
        'If-Match': `"${input.comparisonVersion}"`,
      },
      body: JSON.stringify({
        candidate_id: input.candidateId,
        source_observation_id: input.sourceObservationId,
        target_observation_id: input.targetObservationId || undefined,
        reason: input.reason,
      }),
    })
    return {
      overrideEventId: value?.override_event_id ?? '',
      supersededComparisonId: value?.superseded_comparison_id ?? '',
      replacementComparisonId: value?.replacement_comparison_id ?? '',
      replacementStatus: (value?.replacement_status ?? 'queued') as AssessmentComparisonStatus,
    }
  },
}
