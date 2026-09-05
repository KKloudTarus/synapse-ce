import { describe, expect, it } from 'vitest'
import type { BusinessAsset, Engagement, FleetCoverageSummary } from '../../../lib/types'
import { ageLabel, buildAttentionQueue, dueLabel } from './attentionQueue'

function asset(overrides: Partial<BusinessAsset>): BusinessAsset {
  return { id: 'a', key: 'a', name: 'Asset', description: '', type: 'system', criticality: 'high', lifecycle: 'active', owner: 'Team', metadata: {}, version: 1, createdAt: null, updatedAt: '2026-09-01T00:00:00Z', posture: 'good', ...overrides }
}

function engagement(overrides: Partial<Engagement>): Engagement {
  return { id: 'e', name: 'Engagement', client: '', status: 'active', inScope: [], outOfScope: [], authorizedFrom: null, authorizedTo: null, roe: { allowedToolClasses: [], blackouts: [] }, liveReconEnabled: false, createdAt: '2026-09-02T00:00:00Z', businessAssetId: '', ...overrides }
}

const fleet: FleetCoverageSummary = { agentsByState: {}, rowsByVerdict: { covered: 5, stale: 2, unauthorized: 0 }, oldestPerCapability: {}, assetsWithoutAgent: 0 }

describe('buildAttentionQueue', () => {
  it('ranks failed scans and critical posture first, then high risk and coverage gaps, then unscanned', () => {
    const queue = buildAttentionQueue({
      assets: [
        asset({ id: 'crit', name: 'Payments', posture: 'critical', criticality: 'critical' }),
        asset({ id: 'hr', name: 'Mobile', posture: 'high_risk' }),
        asset({ id: 'ok', name: 'Portal', posture: 'good' }),
        asset({ id: 'old', name: 'Legacy', posture: 'critical', lifecycle: 'retired' }),
      ],
      engagements: [
        engagement({ id: 'failed', name: 'API review', lastScanDate: '2026-09-03T00:00:00Z', lastScanStatus: 'failed', businessAssetId: 'crit' }),
        engagement({ id: 'fresh', name: 'New service', status: 'active' }),
        engagement({ id: 'done', name: 'Old audit', status: 'completed' }),
        engagement({ id: 'draft', name: 'Draft', status: 'draft' }),
      ],
      fleet,
      assetNames: { crit: 'Payments' },
    })
    expect(queue.map((item) => [item.priority, item.type, item.subject])).toEqual([
      [1, 'Asset posture', 'Payments'],
      [1, 'Scan failed', 'API review'],
      [2, 'Asset posture', 'Mobile'],
      [2, 'Coverage gap', 'Fleet'],
      [3, 'Not scanned', 'New service'],
    ])
    const failed = queue.find((item) => item.type === 'Scan failed')!
    expect(failed.owner).toBe('Payments')
    expect(failed.action).toBe('Rerun scan')
    expect(failed.issue).toBe('Last scan failed; no findings recorded from a previous run')
    expect(failed.to).toBe('/engagements/failed')
    const gap = queue.find((item) => item.type === 'Coverage gap')!
    expect(gap.issue).toBe('2 stale capability checks; the posture of the assets behind them may be out of date')
    expect(queue[0].action).toBe('Open findings')
    expect(queue[0].issue).toBe('Critical security posture on a critical-criticality system')
  })

  it('is empty when nothing needs action and the fleet is unavailable', () => {
    expect(buildAttentionQueue({ assets: [asset({})], engagements: [engagement({ status: 'active', lastScanDate: '2026-09-03T00:00:00Z', lastScanStatus: 'succeeded' })], fleet: null, assetNames: {} })).toEqual([])
  })

  it('labels ages compactly', () => {
    const now = Date.parse('2026-09-05T12:00:00Z')
    expect(ageLabel('2026-09-05T11:30:00Z', now)).toBe('30m')
    expect(ageLabel('2026-09-05T02:00:00Z', now)).toBe('10h')
    expect(ageLabel('2026-09-01T12:00:00Z', now)).toBe('4d')
    expect(ageLabel('2026-07-01T12:00:00Z', now)).toBe('9w')
    expect(ageLabel(null, now)).toBe('')
  })
})

describe('dueLabel and SLA', () => {
  it('sets a priority-based due date and labels overdue vs due-soon vs normal', () => {
    const now = Date.parse('2026-09-05T12:00:00Z')
    // A P1 asset-posture item whose condition began 20h ago: SLA 24h -> due in ~4h (due-soon warning).
    const queue = buildAttentionQueue({
      assets: [{ id: 'a', key: 'a', name: 'Payments', description: '', type: 'system', criticality: 'critical', lifecycle: 'active', owner: 'T', metadata: {}, version: 1, createdAt: null, updatedAt: '2026-09-04T16:00:00Z', posture: 'critical' }],
      engagements: [],
      fleet: null,
      assetNames: {},
    })
    const p1 = queue[0]
    expect(p1.dueAt).not.toBeNull()
    const due = dueLabel(p1.dueAt, now)
    expect(due.text).toMatch(/^Due /)
    expect(due.tone).toBe('warning') // within 12h

    // Overdue: due date in the past.
    const od = dueLabel('2026-09-05T08:00:00Z', now)
    expect(od.text).toMatch(/^Overdue /)
    expect(od.tone).toBe('critical')
    // Far out: neutral.
    const far = dueLabel('2026-09-10T12:00:00Z', now)
    expect(far.tone).toBe('muted')
    // No due date.
    expect(dueLabel(null, now).text).toBe('')
  })
})
