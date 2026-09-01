import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { AssessmentComparisonTab } from './AssessmentComparisonTab'

vi.mock('../../lib/api', () => ({
  api: {
    assessmentLifecycle: vi.fn(), assessmentSnapshots: vi.fn(), createAssessmentComparison: vi.fn(),
    assessmentComparison: vi.fn(), assessmentComparisonItems: vi.fn(), reviewAssessmentComparisonItem: vi.fn(),
  },
  ApiError: class ApiError extends Error { constructor(public status: number, message: string) { super(message) } },
}))

const snapshot = (id: string, number: number) => ({
  id, cycleId: 'cycle-1', assessmentId: 'assessment-1', snapshotNumber: number, lifecycle: 'finalized' as const, provenance: 'native' as const,
  boundary: { boundaryKind: 'standalone' as const, businessAssetId: '', projectId: '' }, runReferences: [], schemaVersion: 1,
  contentHash: 'a'.repeat(64), createdAt: '2026-08-31T00:00:00Z', createdBy: 'operator', finalizedAt: '2026-08-31T00:00:00Z', finalizedBy: 'operator', supersededAt: null, supersededBy: '',
  dimensions: [{ runId: `run-${number}`, laneKey: 'sca', laneManifestHash: 'b'.repeat(64), producer: 'sca', findingKind: 'vulnerability', target: { kind: 'repository' as const, schemaVersion: 1, canonical: 'repo:example', evaluatedRevision: '' }, state: 'complete' as const, reasonCode: 'complete', includedScope: ['src/**'], excludedScope: [], versions: [] }],
})

const comparison = {
  id: 'comparison-1', cycleId: 'cycle-1', baselineSnapshotId: 'snapshot-1', currentSnapshotId: 'snapshot-2', mode: 'lifecycle' as const,
  inputHash: 'c'.repeat(64), algorithmVersion: 1, fingerprintVersion: 1, riskModelVersion: 1, coveragePolicyVersion: 1,
  status: 'needs_review' as const, version: 3, attempts: 1, failureCode: '', contentHash: 'd'.repeat(64),
  summary: {
    comparisonId: 'comparison-1', baselineSnapshotId: 'snapshot-1', currentSnapshotId: 'snapshot-2', riskModelVersion: 1,
    fixedRate: { numerator: 0, denominator: 0, naReason: 'no_comparable_actionable_baseline' }, countReduction: { numerator: 0, denominator: 0, naReason: 'no_actionable_baseline' }, riskReduction: { numerator: 0, denominator: 0, naReason: 'non_positive_baseline_risk' },
    fixedCount: 0, baselineCount: 0, currentCount: 1, baselineRisk: 0, currentRisk: 5000, newCount: 1, reopenedCount: 0, stillDetectedCount: 0, notEvaluatedCount: 0, reviewCount: 1, newRisk: 5000, reopenedRisk: 0,
    baselineSeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 }, currentSeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0, unknown: 0 },
  },
  createdAt: '2026-08-31T00:00:00Z', updatedAt: '2026-08-31T00:00:00Z', completedAt: '2026-08-31T00:00:00Z', supersededAt: null, supersededBy: '',
}

describe('AssessmentComparisonTab', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.assessmentLifecycle).mockResolvedValue({ assessmentId: 'assessment-1', cycle: { id: 'cycle-1', name: 'Cycle', boundaryKind: 'standalone', businessAssetId: '', projectId: '', status: 'open', rootAssessmentId: 'assessment-1', selectedHeadAssessmentId: 'assessment-1', nextRetestNumber: 1, version: 1, createdAt: '', updatedAt: '', createdBy: '', updatedBy: '' }, members: [{ assessmentId: 'assessment-1', assessmentType: 'initial', predecessorAssessmentId: '', retestNumber: 0, relationshipVersion: 1, createdAt: '', createdBy: '', archivedAt: null }], branchHeads: [] })
    vi.mocked(api.assessmentSnapshots).mockResolvedValue({ items: [snapshot('snapshot-1', 1), snapshot('snapshot-2', 2)], defaultSnapshotId: 'snapshot-2', defaultVersion: 2 })
    vi.mocked(api.createAssessmentComparison).mockResolvedValue({ comparison, created: true })
    vi.mocked(api.assessmentComparison).mockResolvedValue(comparison)
    vi.mocked(api.assessmentComparisonItems).mockResolvedValue({ items: [{ id: 'item-1', position: 0, identityId: 'identity-1', producerKind: 'sca', findingKind: 'vulnerability', targetCanonical: 'repo:example', baselineObservationId: '', currentObservationId: 'observation-1', baselineObservation: null, currentObservation: { severity: 'high', componentVersion: '1.0.0', location: 'go.mod', reachability: 'reachable', evidenceDigest: 'e'.repeat(64), scanner: { scanRunId: 'run-2', laneKey: 'sca', toolName: 'scanner', toolVersion: '1', ruleId: 'rule' }, observedAt: '2026-08-31T00:00:00Z' }, presence: 'needs_review', changeFlags: [], coverageDecision: 'not_comparable', matchMethods: ['matcher'], verificationId: '', verificationState: '', fixedBasis: '', baselineActionable: false, currentActionable: true, comparableBaseline: false, baselineRiskMilli: 0, currentRiskMilli: 5000, reviewCandidateIds: ['candidate-1'], reviewCandidates: [{ id: 'candidate-1', sourceObservationIds: ['source-observation-1'] }] }], nextCursor: 'next' })
  })

  it('persists the pair, renders N/A ratios, and opens immutable item detail', async () => {
    render(<MemoryRouter initialEntries={['/engagements/assessment-1/comparison?comparison_mode=lifecycle&comparison_base_assessment=assessment-1&comparison_baseline=snapshot-1&comparison_current=snapshot-2']}><Routes><Route path="/engagements/:id/comparison" element={<AssessmentComparisonTab assessmentId="assessment-1" />} /></Routes></MemoryRouter>)
    expect(await screen.findByText('Coverage before metrics')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }))
    await waitFor(() => expect(api.createAssessmentComparison).toHaveBeenCalledWith({ baselineSnapshotId: 'snapshot-1', currentSnapshotId: 'snapshot-2', mode: 'lifecycle' }))
    expect((await screen.findAllByText('N/A')).length).toBe(3)
    expect(screen.getByRole('combobox', { name: 'Disposition filter' })).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'Needs Review' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Needs Review' }))
    expect(await screen.findByRole('heading', { name: 'Immutable item detail' })).toBeInTheDocument()
    expect(screen.getByText('none → identity-1 → observation-1')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Review source observation' })).toBeInTheDocument()
    expect(screen.getByText(/completed item is never mutated/i)).toBeInTheDocument()
  })
})
