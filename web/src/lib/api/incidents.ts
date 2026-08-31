import type {
  AgentDetectionRecord,
  CorrelateResult,
  Incident,
  IncidentComment,
  IncidentDisposition,
  IncidentList,
  IncidentResponseRef,
  IncidentRisk,
  IncidentState,
  RiskCoverageVector,
  RiskFactorContribution,
  Severity,
  TimelineEntry,
} from '../types'
import { req } from './client'

// The backend serializes incident.Incident, its RiskAssessment, and endpoint.TimelineEntry with Go
// field names (PascalCase — no json tags), so every mapper below reads PascalCase keys. Keeping the
// mapping in one place means a backend rename surfaces here, not silently as blank cells across the UI.

function mapCoverageVector(raw: any): RiskCoverageVector {
  return {
    process: raw?.Process ?? 0,
    network: raw?.Network ?? 0,
    file: raw?.File ?? 0,
    privilege: raw?.Privilege ?? 0,
    reasons: Array.isArray(raw?.Reasons) ? raw.Reasons : [],
  }
}

function mapFactorContribution(raw: any): RiskFactorContribution {
  return {
    factor: raw?.Factor ?? '',
    points: raw?.Points ?? 0,
    detail: raw?.Detail ?? '',
  }
}

function mapRisk(raw: any): IncidentRisk | null {
  if (!raw) return null
  return {
    assessmentId: raw?.AssessmentID ?? '',
    incidentRevision: raw?.IncidentRevision ?? 0,
    scorerVersion: raw?.ScorerVersion ?? '',
    policyVersion: raw?.PolicyVersion ?? '',
    risk: raw?.Risk ?? 0,
    confidence: raw?.Confidence ?? 0,
    coverage: raw?.Coverage ?? 0,
    coverageVector: mapCoverageVector(raw?.CoverageVector),
    factorContributions: Array.isArray(raw?.FactorContributions)
      ? raw.FactorContributions.map(mapFactorContribution)
      : [],
    reasonCodes: Array.isArray(raw?.ReasonCodes) ? raw.ReasonCodes : [],
    createdAt: raw?.CreatedAt ?? '',
  }
}

function mapComment(raw: any): IncidentComment {
  return { at: raw?.At ?? '', actor: raw?.Actor ?? '', text: raw?.Text ?? '' }
}

function mapResponseRef(raw: any): IncidentResponseRef {
  return { actionId: raw?.ActionID ?? '', verified: Boolean(raw?.Verified) }
}

function mapIncident(raw: any): Incident {
  return {
    id: raw?.ID ?? '',
    assetId: raw?.AssetID ?? '',
    title: raw?.Title ?? '',
    severity: (raw?.Severity ?? 'unknown') as Severity,
    state: (raw?.State ?? 'new') as IncidentState,
    disposition: (raw?.Disposition ?? 'unknown') as IncidentDisposition,
    ownerId: raw?.OwnerID ?? '',
    detectionIds: Array.isArray(raw?.DetectionIDs) ? raw.DetectionIDs : [],
    risk: mapRisk(raw?.Risk),
    mergedInto: raw?.MergedInto ?? '',
    comments: Array.isArray(raw?.Comments) ? raw.Comments.map(mapComment) : [],
    responses: Array.isArray(raw?.Responses) ? raw.Responses.map(mapResponseRef) : [],
    revision: raw?.Revision ?? 0,
    createdAt: raw?.CreatedAt ?? '',
    updatedAt: raw?.UpdatedAt ?? '',
  }
}

function mapTimelineEntry(raw: any): TimelineEntry {
  return {
    occurredAt: raw?.OccurredAt ?? '',
    assetId: raw?.AssetID ?? '',
    entityKind: raw?.EntityKind ?? '',
    entityId: raw?.EntityID ?? '',
    kind: raw?.Kind ?? '',
    eventId: raw?.EventID ?? '',
    summary: raw?.Summary ?? '',
  }
}

export interface ListIncidentsOptions {
  asset?: string
  state?: IncidentState
  limit?: number
}

export const incidentsApi = {
  listIncidents: async (opts: ListIncidentsOptions = {}): Promise<IncidentList> => {
    const q = new URLSearchParams()
    if (opts.asset) q.set('asset', opts.asset)
    if (opts.state) q.set('state', opts.state)
    if (opts.limit) q.set('limit', String(opts.limit))
    const qs = q.toString()
    const res = await req(`/fleet/incidents${qs ? `?${qs}` : ''}`)
    return {
      incidents: Array.isArray(res?.incidents) ? res.incidents.map(mapIncident) : [],
      truncated: Boolean(res?.truncated),
    }
  },

  getIncident: async (id: string): Promise<Incident> =>
    mapIncident(await req(`/fleet/incidents/${encodeURIComponent(id)}`)),

  assignIncidentOwner: async (id: string, owner: string): Promise<Incident> =>
    mapIncident(
      await req(`/fleet/incidents/${encodeURIComponent(id)}/owner`, {
        method: 'POST',
        body: JSON.stringify({ owner }),
      }),
    ),

  commentIncident: async (id: string, text: string): Promise<Incident> =>
    mapIncident(
      await req(`/fleet/incidents/${encodeURIComponent(id)}/comments`, {
        method: 'POST',
        body: JSON.stringify({ text }),
      }),
    ),

  changeIncidentStatus: async (id: string, to: IncidentState): Promise<Incident> =>
    mapIncident(
      await req(`/fleet/incidents/${encodeURIComponent(id)}/status`, {
        method: 'POST',
        body: JSON.stringify({ to }),
      }),
    ),

  setIncidentDisposition: async (id: string, disposition: IncidentDisposition): Promise<Incident> =>
    mapIncident(
      await req(`/fleet/incidents/${encodeURIComponent(id)}/disposition`, {
        method: 'POST',
        body: JSON.stringify({ disposition }),
      }),
    ),

  reassessIncidentRisk: async (id: string): Promise<Incident> =>
    mapIncident(
      await req(`/fleet/incidents/${encodeURIComponent(id)}/risk/reassess`, { method: 'POST' }),
    ),

  assetTimeline: async (
    assetId: string,
    opts: { from?: string; to?: string; limit?: number } = {},
  ): Promise<TimelineEntry[]> => {
    const q = new URLSearchParams()
    if (opts.from) q.set('from', opts.from)
    if (opts.to) q.set('to', opts.to)
    if (opts.limit) q.set('limit', String(opts.limit))
    const qs = q.toString()
    const res = await req(`/fleet/assets/${encodeURIComponent(assetId)}/timeline${qs ? `?${qs}` : ''}`)
    return Array.isArray(res?.entries) ? res.entries.map(mapTimelineEntry) : []
  },

  // Agent security detections for an engagement (GET /engagements/{id}/detections). detection.Record is
  // untagged PascalCase (its evidence events are field-RBAC redacted server-side); field_scope reports
  // how much the caller's role is allowed to see. Answers "does agent security detection show in the UI".
  listEngagementDetections: async (engagementId: string): Promise<{ detections: AgentDetectionRecord[]; fieldScope: string }> => {
    const res = await req(`/engagements/${encodeURIComponent(engagementId)}/detections`)
    return {
      detections: Array.isArray(res?.detections) ? res.detections.map(mapDetectionRecord) : [],
      fieldScope: res?.field_scope ?? '',
    }
  },

  // Correlate an engagement's sealed detections into incidents (POST /fleet/engagements/{id}/correlate).
  correlateEngagement: async (engagementId: string): Promise<CorrelateResult> => {
    const res = await req(`/fleet/engagements/${encodeURIComponent(engagementId)}/correlate`, {
      method: 'POST',
      body: JSON.stringify({}),
    })
    return {
      created: Array.isArray(res?.created) ? res.created.map(mapIncident) : [],
      reassessed: res?.reassessed ?? 0,
      reassessFailed: res?.reassess_failed ?? 0,
    }
  },
}

function mapDetectionRecord(raw: any): AgentDetectionRecord {
  const d = raw?.Detection ?? {}
  return {
    id: raw?.ID ?? '',
    assetId: raw?.AssetID ?? '',
    agentId: raw?.AgentID ?? '',
    recordedAt: raw?.RecordedAt ?? '',
    ruleId: d?.RuleID ?? '',
    ruleVersion: d?.RuleVersion ?? 0,
    class: (d?.Class ?? '') as AgentDetectionRecord['class'],
    severity: (d?.Severity ?? 'unknown') as Severity,
    evidenceCount: Array.isArray(d?.Evidence) ? d.Evidence.length : 0,
    truncated: Boolean(d?.Truncated),
    observedCount: d?.ObservedCount ?? 0,
    observed: d?.Observed ?? '',
  }
}
