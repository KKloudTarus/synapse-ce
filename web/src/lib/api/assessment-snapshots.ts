import type {
  AssessmentSnapshot,
  AssessmentSnapshotDimension,
  AssessmentSnapshotListResponse,
  AssessmentSnapshotRunReference,
  AssessmentSnapshotVersion,
  FinalizeAssessmentSnapshotInput,
  FinalizeAssessmentSnapshotResponse,
} from '../types'
import { newIdempotencyKey, req } from './client'

const id = encodeURIComponent

function mapVersion(value: any): AssessmentSnapshotVersion {
  return { kind: value.kind ?? 'tool', name: value.name ?? '', version: value.version ?? '', digest: value.digest ?? '' }
}

function mapRunReference(value: any): AssessmentSnapshotRunReference {
  return {
    runId: value.run_id ?? '',
    manifestHash: value.manifest_hash ?? '',
    laneReferences: (value.lane_refs ?? []).map((lane: any) => ({
      laneKey: lane.lane_key ?? '', manifestHash: lane.manifest_hash ?? '',
    })),
  }
}

function mapDimension(value: any): AssessmentSnapshotDimension {
  return {
    runId: value.run_id ?? '',
    laneKey: value.lane_key ?? '',
    laneManifestHash: value.lane_manifest_hash ?? '',
    producer: value.producer ?? '',
    findingKind: value.finding_kind ?? '',
    target: {
      kind: value.target?.kind ?? 'repository',
      schemaVersion: Number(value.target?.schema_version ?? 0),
      canonical: value.target?.canonical ?? '',
      evaluatedRevision: value.target?.evaluated_revision ?? '',
    },
    state: value.state ?? 'unknown',
    reasonCode: value.reason_code ?? '',
    includedScope: value.included_scope ?? [],
    excludedScope: value.excluded_scope ?? [],
    versions: (value.versions ?? []).map(mapVersion),
  }
}

export function mapAssessmentSnapshot(value: any): AssessmentSnapshot {
  return {
    id: value.id ?? '',
    cycleId: value.cycle_id ?? '',
    assessmentId: value.assessment_id ?? '',
    snapshotNumber: Number(value.snapshot_number ?? 0),
    lifecycle: value.lifecycle ?? 'finalized',
    provenance: value.provenance ?? 'native',
    boundary: {
      boundaryKind: value.boundary?.boundary_kind ?? 'standalone',
      businessAssetId: value.boundary?.business_asset_id ?? '',
      projectId: value.boundary?.project_id ?? '',
    },
    runReferences: (value.run_references ?? []).map(mapRunReference),
    dimensions: (value.dimensions ?? []).map(mapDimension),
    schemaVersion: Number(value.schema_version ?? 0),
    contentHash: value.content_hash ?? '',
    createdAt: value.created_at ?? '',
    createdBy: value.created_by ?? '',
    finalizedAt: value.finalized_at ?? '',
    finalizedBy: value.finalized_by ?? '',
    supersededAt: value.superseded_at ?? null,
    supersededBy: value.superseded_by ?? '',
  }
}

export const assessmentSnapshotsApi = {
  finalizeAssessmentSnapshot: async (assessmentId: string, input: FinalizeAssessmentSnapshotInput): Promise<FinalizeAssessmentSnapshotResponse> => {
    const value = await req(`/engagements/${id(assessmentId)}/snapshots/finalize`, {
      method: 'POST',
      headers: {
        'Idempotency-Key': input.idempotencyKey ?? newIdempotencyKey(),
        'If-Match': String(input.expectedDefaultVersion),
      },
      body: JSON.stringify({
        selected_runs: input.selectedRuns.map((selection) => ({ run_id: selection.runId, lane_keys: selection.laneKeys })),
      }),
    })
    return { snapshot: mapAssessmentSnapshot(value.snapshot ?? {}), defaultVersion: Number(value.default_version ?? 0) }
  },

  assessmentSnapshots: async (assessmentId: string): Promise<AssessmentSnapshotListResponse> => {
    const value = await req(`/engagements/${id(assessmentId)}/snapshots`)
    return {
      items: (value.items ?? []).map(mapAssessmentSnapshot),
      defaultSnapshotId: value.default_snapshot_id ?? '',
      defaultVersion: Number(value.default_version ?? 0),
    }
  },

  assessmentSnapshot: async (snapshotId: string): Promise<AssessmentSnapshot> =>
    mapAssessmentSnapshot(await req(`/assessment-snapshots/${id(snapshotId)}`)),
}
