import type {
  AssessmentRelationshipCandidate,
  AssessmentRelationshipDecisionAction,
  AssessmentRelationshipSignal,
  AssessmentRelationshipStatus,
} from '../types'
import { req } from './client'

function mapSignal(value: any): AssessmentRelationshipSignal {
  return {
    kind: value.kind,
    evidenceHash: value.evidence_hash ?? '',
    matchCount: Number(value.match_count ?? 0),
    scoreMilli: Number(value.score_milli ?? 0),
    schemaVersion: Number(value.schema_version ?? 0),
  }
}

function mapCandidate(value: any): AssessmentRelationshipCandidate {
  return {
    id: value.id,
    predecessorCycleId: value.predecessor_cycle_id,
    predecessorAssessmentId: value.predecessor_assessment_id,
    predecessorRelationshipVersion: Number(value.predecessor_relationship_version),
    predecessorSnapshotId: value.predecessor_snapshot_id,
    successorCycleId: value.successor_cycle_id,
    successorAssessmentId: value.successor_assessment_id,
    successorRelationshipVersion: Number(value.successor_relationship_version),
    successorSnapshotId: value.successor_snapshot_id,
    boundaryKeyHash: value.boundary_key_hash,
    signals: Array.isArray(value.signals) ? value.signals.map(mapSignal) : [],
    inputHash: value.input_hash,
    confidence: value.confidence,
    status: value.status,
    version: Number(value.version),
    expiresAt: value.expires_at,
    createdBy: value.created_by,
    createdAt: value.created_at,
    decision: value.decision ? {
      id: value.decision.id,
      action: value.decision.action,
      actor: value.decision.actor,
      reason: value.decision.reason,
      version: Number(value.decision.version),
      createdAt: value.decision.created_at,
    } : undefined,
    repairPlan: value.repair_plan ? {
      id: value.repair_plan.id,
      inputHash: value.repair_plan.input_hash,
      planHash: value.repair_plan.plan_hash,
      body: value.repair_plan.body ?? {},
      createdBy: value.repair_plan.created_by,
      createdAt: value.repair_plan.created_at,
    } : undefined,
  }
}

export const assessmentRelationshipsApi = {
  listAssessmentRelationshipCandidates: async (status: AssessmentRelationshipStatus | 'all' = 'open'): Promise<AssessmentRelationshipCandidate[]> => {
    const value = await req(`/assessment-relationship-candidates?status=${encodeURIComponent(status)}`)
    return Array.isArray(value?.items) ? value.items.map(mapCandidate) : []
  },

  generateAssessmentRelationshipCandidate: async (input: {
    predecessorCycleId: string
    successorCycleId: string
    importedReferenceHash?: string
    expiresInDays?: number
  }): Promise<AssessmentRelationshipCandidate> => mapCandidate(await req('/assessment-relationship-candidates/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      predecessor_cycle_id: input.predecessorCycleId,
      successor_cycle_id: input.successorCycleId,
      imported_reference_hash: input.importedReferenceHash || undefined,
      expires_in_days: input.expiresInDays || undefined,
    }),
  })),

  decideAssessmentRelationshipCandidate: async (
    candidate: AssessmentRelationshipCandidate,
    action: AssessmentRelationshipDecisionAction,
    reason: string,
    idempotencyKey = globalThis.crypto.randomUUID(),
  ): Promise<AssessmentRelationshipCandidate> => mapCandidate(await req(`/assessment-relationship-candidates/${encodeURIComponent(candidate.id)}/decisions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'If-Match': `"${candidate.version}"`,
      'Idempotency-Key': idempotencyKey,
    },
    body: JSON.stringify({ action, reason }),
  })),
}
