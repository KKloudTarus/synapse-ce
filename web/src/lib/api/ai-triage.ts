import type {
  AITriageMetricRow,
  AITriageObservability,
  AITriageReview,
  AITriageReviewFilter,
} from '../types'
import { req } from './client'

function mapAITriageReview(r: any): AITriageReview {
  return {
    id: r.id ?? '', tenantId: r.tenant_id ?? '', engagementId: r.engagement_id ?? '', projectId: r.project_id ?? '',
    findingId: r.finding_id ?? '', dedupKey: r.dedup_key ?? '', title: r.title ?? '', severity: r.severity ?? 'unknown',
    cwe: r.cwe ?? '', owner: r.owner ?? '', state: r.state ?? 'pending', verdict: r.verdict ?? '', driver: r.driver ?? '',
    confidence: r.confidence ?? 0, suspectedFP: r.suspected_fp ?? false, proposerModel: r.proposer_model ?? '',
    proposerProvider: r.proposer_provider ?? '', proposerModelFamily: r.proposer_model_family ?? '',
    verifierModel: r.verifier_model ?? '', verifierProvider: r.verifier_provider ?? '', verifierModelFamily: r.verifier_model_family ?? '',
    independencePolicy: r.independence_policy ?? '', promptVersion: r.prompt_version ?? '', verified: r.verified ?? false, verifierVerdict: r.verifier_verdict ?? '',
    verifierDriver: r.verifier_driver ?? '', verifierConfidence: r.verifier_confidence ?? 0,
    policyVersion: r.policy_version ?? '', policyReason: r.policy_reason ?? '', shadow: r.shadow ?? false,
    wouldGateExempt: r.would_gate_exempt ?? false, gateExempt: r.gate_exempt ?? false,
    reviewRequired: r.review_required ?? false, evidenceRef: r.evidence_ref ?? '', decidedBy: r.decided_by ?? '',
    decisionRationale: r.decision_rationale ?? '', createdAt: r.created_at ?? '', updatedAt: r.updated_at ?? '',
    decidedAt: r.decided_at ?? null, version: r.version ?? 1,
  }
}

function mapAITriageMetricRow(r: any): AITriageMetricRow {
  return {
    value: r?.value ?? '', requestCount: r?.request_count ?? 0, averageLatencyMillis: r?.average_latency_ms ?? 0,
    timeoutCount: r?.timeout_count ?? 0, parseFailureCount: r?.parse_failure_count ?? 0,
    providerFailureCount: r?.provider_failure_count ?? 0, circuitOpenCount: r?.circuit_open_count ?? 0,
    totalTokens: r?.total_tokens ?? 0, estimatedCostMicroUSD: r?.estimated_cost_micro_usd ?? 0,
    comparisons: r?.comparisons ?? 0, disagreements: r?.disagreements ?? 0,
    gateExemptions: r?.gate_exemptions ?? 0, findings: r?.findings ?? 0,
  }
}

function mapAITriageObservability(r: any): AITriageObservability {
  return {
    generatedAt: r?.generated_at ?? '', totals: mapAITriageMetricRow(r?.totals),
    byModel: (r?.by_model ?? []).map(mapAITriageMetricRow),
    byPromptVersion: (r?.by_prompt_version ?? []).map(mapAITriageMetricRow),
    byCWE: (r?.by_cwe ?? []).map(mapAITriageMetricRow),
    byProject: (r?.by_project ?? []).map(mapAITriageMetricRow),
    distribution: {
      schemaVersion: r?.distribution?.schema_version ?? 'synapse-ai-triage-distribution-v1',
      sampleSize: r?.distribution?.sample_size ?? 0,
      languageBasisPoints: r?.distribution?.language_basis_points ?? {},
      cweBasisPoints: r?.distribution?.cwe_basis_points ?? {},
      projectBasisPoints: r?.distribution?.project_basis_points ?? {},
    },
    alerts: (r?.alerts ?? []).map((item: any) => ({
      projectId: item?.project_id ?? '', projectName: item?.project_name ?? '',
      alert: {
        metric: item?.alert?.metric ?? '', observedBasisPoints: item?.alert?.observed_basis_points ?? 0,
        baselineBasisPoints: item?.alert?.baseline_basis_points ?? 0, deviationBasisPoints: item?.alert?.deviation_basis_points ?? 0,
        sampleSize: item?.alert?.sample_size ?? 0, message: item?.alert?.message ?? '',
      },
    })),
  }
}

export const aiTriageApi = {
  aiTriageReviews: async (filter: AITriageReviewFilter = {}): Promise<AITriageReview[]> => {
    const q = new URLSearchParams()
    if (filter.severity) q.set('severity', filter.severity)
    if (filter.cwe) q.set('cwe', filter.cwe)
    if (filter.project) q.set('project', filter.project)
    if (filter.state) q.set('state', filter.state)
    const encoded = q.toString()
    const suffix = encoded ? `?${encoded}` : ''
    const r = await req(`/ai-triage/reviews${suffix}`)
    return (r?.reviews ?? []).map(mapAITriageReview)
  },

  aiTriageObservability: async (): Promise<AITriageObservability> =>
    mapAITriageObservability(await req('/ai-triage/observability')),

  decideAITriageReview: async (reviewId: string, decision: 'accept' | 'reject', rationale: string, version: number): Promise<AITriageReview> =>
    mapAITriageReview(await req(`/ai-triage/reviews/${encodeURIComponent(reviewId)}/decision`, {
      method: 'POST', body: JSON.stringify({ decision, rationale, version }),
    })),

  claimAITriageReview: async (reviewId: string, version: number): Promise<AITriageReview> =>
    mapAITriageReview(await req(`/ai-triage/reviews/${encodeURIComponent(reviewId)}/claim`, {
      method: 'POST', body: JSON.stringify({ version }),
    })),
}
