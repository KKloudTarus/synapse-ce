import type {
  Finding,
  FindingComment,
  Retest,
  RetestOutcome,
  SLAAssessment,
  SLAEvent,
  SLATransitionInput,
  SLAView,
} from '../types'
import { req } from './client'

export function mapFinding(r: any): Finding {
  return {
    id: r.ID,
    engagementId: r.EngagementID ?? '',
    title: r.Title ?? '',
    description: r.Description ?? '',
    severity: r.Severity ?? 'unknown',
    cvssVector: r.CVSSVector ?? '',
    cwe: r.CWE ?? '',
    status: r.Status ?? 'open',
    dedupKey: r.DedupKey ?? '',
    kev: r.KEV ?? false,
    riskScore: r.RiskScore ?? 0,
    class: r.Class ?? 'third_party',
    scope: r.Scope ?? 'unknown',
    reachability: r.Reachability ?? 'unknown',
    impact: r.Impact ?? '',
    priority: r.Priority ?? 3,
    assignee: r.Assignee ?? '',
    version: r.Version ?? 1,
    kind: r.Kind ?? '',
    evidenceScore: r.EvidenceScore ?? 0,
    proposedBy: r.ProposedBy ?? '',
    complianceControls: (r.compliance_controls ?? []).map((c: any) => ({
      framework: c.Framework ?? '',
      id: c.ID ?? '',
      title: c.Title ?? '',
    })),
  }
}

function mapSLAView(r: any): SLAView {
  const assessment = r?.assessment ?? {}
  const result = assessment.result ?? {}
  const inputs = assessment.inputs ?? {}
  const breakdown = result.breakdown ?? {}
  const lifecycle = r?.lifecycle ?? {}
  return {
    assessment: {
      tenantId: assessment.tenant_id ?? '',
      id: assessment.id ?? '',
      engagementId: assessment.engagement_id ?? '',
      findingId: assessment.finding_id ?? '',
      sourceRiskAssessmentId: assessment.source_risk_assessment_id ?? '',
      inputs: {
        severity: inputs.severity ?? 'unknown',
        cvssScore: inputs.cvss_score ?? 0,
        kev: inputs.kev ?? false,
        epss: inputs.epss ?? 0,
        publicPoC: inputs.public_poc ?? false,
        activeExploitation: inputs.active_exploitation ?? false,
        criticality: inputs.criticality ?? '',
        exposure: inputs.exposure ?? '',
        feasibility: inputs.feasibility ?? '',
      },
      result: {
        tier: result.tier ?? 'low',
        score: result.score ?? 0,
        breakdown: {
          severity: breakdown.severity ?? 0,
          exploitability: breakdown.exploitability ?? 0,
          threatIntel: breakdown.threat_intel ?? 0,
          exposure: breakdown.exposure ?? 0,
          criticality: breakdown.criticality ?? 0,
          feasibility: breakdown.feasibility ?? 0,
          overrides: breakdown.overrides ?? [],
        },
        mitigateBy: result.mitigate_by ?? '',
        remediateBy: result.remediate_by ?? '',
        reason: result.reason ?? '',
        computedAt: result.computed_at ?? '',
        configVersion: result.config_version ?? '',
      },
      inputHash: assessment.input_hash ?? '',
      configHash: assessment.config_hash ?? '',
      previousAssessmentId: assessment.previous_assessment_id ?? '',
      deadlineAnchorAt: assessment.deadline_anchor_at ?? '',
      assessedAt: assessment.assessed_at ?? '',
      createdAt: assessment.created_at ?? '',
    },
    lifecycle: {
      tenantId: lifecycle.tenant_id ?? '',
      engagementId: lifecycle.engagement_id ?? '',
      findingId: lifecycle.finding_id ?? '',
      assessmentId: lifecycle.assessment_id ?? '',
      status: lifecycle.status ?? 'open',
      version: lifecycle.version ?? 1,
      reason: lifecycle.reason ?? '',
      compensatingControl: lifecycle.compensating_control ?? '',
      acceptedBy: lifecycle.accepted_by ?? '',
      acceptedAt: lifecycle.accepted_at ?? null,
      acceptanceExpiresAt: lifecycle.acceptance_expires_at ?? null,
      updatedBy: lifecycle.updated_by ?? '',
      updatedAt: lifecycle.updated_at ?? '',
    },
    effectiveState: r?.effective_state ?? lifecycle.status ?? 'open',
    overdue: r?.overdue ?? false,
    acceptanceExpired: r?.acceptance_expired ?? false,
  }
}

export { mapSLAView }

function mapSLAAssessment(r: any): SLAAssessment {
  return mapSLAView({ assessment: r, lifecycle: {
    tenant_id: r?.tenant_id,
    engagement_id: r?.engagement_id,
    finding_id: r?.finding_id,
    assessment_id: r?.id,
    status: 'open',
    version: 1,
    updated_by: 'history',
    updated_at: r?.assessed_at,
  } }).assessment
}

function mapSLAEvent(r: any): SLAEvent {
  return {
    tenantId: r?.tenant_id ?? '',
    id: r?.id ?? '',
    engagementId: r?.engagement_id ?? '',
    findingId: r?.finding_id ?? '',
    assessmentId: r?.assessment_id ?? '',
    from: r?.from ?? 'open',
    to: r?.to ?? 'open',
    reason: r?.reason ?? '',
    compensatingControl: r?.compensating_control ?? '',
    acceptanceExpiresAt: r?.acceptance_expires_at ?? null,
    actor: r?.actor ?? '',
    beforeVersion: r?.before_version ?? 0,
    afterVersion: r?.after_version ?? 0,
    at: r?.at ?? '',
  }
}

function mapComment(r: any): FindingComment {
  return {
    id: r.ID ?? '',
    findingId: r.FindingID ?? '',
    author: r.Author ?? '',
    body: r.Body ?? '',
    createdAt: r.CreatedAt ?? null,
  }
}

export const findingsApi = {
  findings: async (engagementId: string): Promise<Finding[]> =>
    ((await req(`/engagements/${encodeURIComponent(engagementId)}/findings`)) ?? []).map(mapFinding),

  updateFindingStatus: async (
    engagementId: string,
    findingId: string,
    status: string,
    version: number,
    note?: string,
  ): Promise<Finding> =>
    mapFinding(
      await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}`, {
        method: 'PATCH',
        body: JSON.stringify({ status, note, version }),
      }),
    ),

  verifyFinding: async (
    engagementId: string,
    findingId: string,
    score: number,
    rationale: string,
    version: number,
  ): Promise<Finding> =>
    mapFinding(
      await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/verify`, {
        method: 'POST',
        body: JSON.stringify({ score, rationale, version }),
      }),
    ),

  createFinding: async (
    engagementId: string,
    input: { title: string; description: string; severity: string; cvssVector: string; cwe: string },
  ): Promise<Finding> =>
    mapFinding(
      await req(`/engagements/${encodeURIComponent(engagementId)}/findings`, {
        method: 'POST',
        body: JSON.stringify({
          title: input.title,
          description: input.description,
          severity: input.severity,
          cvss_vector: input.cvssVector,
          cwe: input.cwe,
        }),
      }),
    ),

  setFindingAssignee: async (
    engagementId: string,
    findingId: string,
    assignee: string,
    version: number,
  ): Promise<Finding> =>
    mapFinding(
      await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/assignee`, {
        method: 'PUT',
        body: JSON.stringify({ assignee, version }),
      }),
    ),

  findingComments: async (engagementId: string, findingId: string): Promise<FindingComment[]> =>
    (
      (await req(
        `/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/comments`,
      )) ?? []
    ).map(mapComment),

  addFindingComment: async (engagementId: string, findingId: string, body: string): Promise<FindingComment> =>
    mapComment(
      await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/comments`, {
        method: 'POST',
        body: JSON.stringify({ body }),
      }),
    ),

  cvssScore: async (vector: string): Promise<{ score: number; severity: string }> => {
    const r = await req(`/cvss?vector=${encodeURIComponent(vector)}`)
    return { score: r.score ?? 0, severity: r.severity ?? 'unknown' }
  },

  slas: async (engagementId: string): Promise<SLAView[]> => {
    const response = await req(`/engagements/${encodeURIComponent(engagementId)}/slas`)
    return (response?.slas ?? []).map(mapSLAView)
  },

  findingSLA: async (engagementId: string, findingId: string): Promise<SLAView> =>
    mapSLAView(await req(`/engagements/${encodeURIComponent(engagementId)}/slas/${encodeURIComponent(findingId)}`)),

  transitionSLA: async (engagementId: string, findingId: string, input: SLATransitionInput): Promise<SLAView> =>
    mapSLAView(await req(`/engagements/${encodeURIComponent(engagementId)}/slas/${encodeURIComponent(findingId)}/transition`, {
      method: 'POST',
      body: JSON.stringify({
        to: input.to,
        reason: input.reason,
        compensating_control: input.compensatingControl ?? '',
        acceptance_expires_at: input.acceptanceExpiresAt || null,
        version: input.version,
      }),
    })),

  slaAssessments: async (engagementId: string, findingId: string): Promise<SLAAssessment[]> => {
    const response = await req(`/engagements/${encodeURIComponent(engagementId)}/slas/${encodeURIComponent(findingId)}/assessments`)
    return (response?.assessments ?? []).map(mapSLAAssessment)
  },

  slaEvents: async (engagementId: string, findingId: string): Promise<SLAEvent[]> => {
    const response = await req(`/engagements/${encodeURIComponent(engagementId)}/slas/${encodeURIComponent(findingId)}/events`)
    return (response?.events ?? []).map(mapSLAEvent)
  },

  findingRetests: async (engagementId: string, findingId: string): Promise<Retest[]> =>
    (await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/retests`)) ?? [],

  recordRetest: async (
    engagementId: string,
    findingId: string,
    outcome: RetestOutcome,
    note: string,
    version: number,
  ): Promise<{ retest: Retest; finding: Finding }> => {
    const r = await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/retests`, {
      method: 'POST',
      body: JSON.stringify({ outcome, note, version }),
    })
    return { retest: r.retest as Retest, finding: mapFinding(r.finding) }
  },
}
