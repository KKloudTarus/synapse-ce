import type { BusinessAsset, Engagement, FleetCoverageSummary } from '../../../lib/types'

export type AttentionPriority = 1 | 2 | 3

export type AttentionType = 'Asset posture' | 'Scan failed' | 'Not scanned' | 'Coverage gap'

/** One row of the dashboard's Needs attention queue: something an operator acts on today. */
export interface AttentionItem {
  key: string
  priority: AttentionPriority
  type: AttentionType
  /** The asset, engagement or fleet the row is about. */
  subject: string
  issue: string
  owner: string
  /** When the condition started (ISO); null when the source does not say. */
  since: string | null
  action: string
  to: string
}

export interface AttentionInput {
  assets: BusinessAsset[]
  engagements: Engagement[]
  fleet: FleetCoverageSummary | null
  assetNames: Record<string, string>
}

const TYPE_RANK: Record<AttentionType, number> = { 'Asset posture': 0, 'Scan failed': 1, 'Coverage gap': 2, 'Not scanned': 3 }

const VERDICT_LABEL: Record<string, string> = {
  stale: 'stale',
  unauthorized: 'unauthorized',
  missing: 'uncovered',
  degraded: 'degraded',
}

/**
 * buildAttentionQueue derives the queue from data the dashboard already loads: no extra request.
 * Priority 1 is a critical-posture asset or a failed scan, 2 a high-risk asset or a fleet coverage
 * gap, 3 an active engagement that has never been scanned. Within a priority the oldest condition
 * comes first. O(assets + engagements + verdicts).
 */
export function buildAttentionQueue({ assets, engagements, fleet, assetNames }: AttentionInput): AttentionItem[] {
  const items: AttentionItem[] = []
  for (const asset of assets) {
    if (asset.lifecycle === 'retired') continue
    const posture = asset.posture ?? 'unknown'
    if (posture !== 'critical' && posture !== 'high_risk') continue
    items.push({
      key: `asset:${asset.id}`,
      priority: posture === 'critical' ? 1 : 2,
      type: 'Asset posture',
      subject: asset.name,
      issue: `${posture === 'critical' ? 'Critical' : 'High-risk'} security posture on a ${asset.criticality}-criticality ${asset.type.replaceAll('_', ' ')}${asset.postureExplanation ? `: ${asset.postureExplanation}` : ''}`,
      owner: asset.owner || 'Owner not set',
      since: asset.updatedAt,
      action: 'Open findings',
      to: `/assets/${encodeURIComponent(asset.id)}`,
    })
  }
  for (const engagement of engagements) {
    const status = engagement.status.toLowerCase()
    if (status === 'archived' || status === 'completed') continue
    const owner = (engagement.businessAssetId && assetNames[engagement.businessAssetId]) || engagement.client || 'Unassigned'
    if (engagement.lastScanStatus === 'failed') {
      items.push({
        key: `scan-failed:${engagement.id}`,
        priority: 1,
        type: 'Scan failed',
        subject: engagement.name,
        issue: `Last scan failed${engagement.findingsCount ? `; ${engagement.findingsCount.total} open ${engagement.findingsCount.total === 1 ? 'finding is' : 'findings are'} from the previous run` : '; no findings recorded from a previous run'}`,
        owner,
        since: engagement.lastScanDate ?? null,
        action: 'Rerun scan',
        to: `/engagements/${encodeURIComponent(engagement.id)}`,
      })
    } else if (status === 'active' && !engagement.lastScanDate) {
      items.push({
        key: `not-scanned:${engagement.id}`,
        priority: 3,
        type: 'Not scanned',
        subject: engagement.name,
        issue: 'Active engagement with no scan yet; its findings and gate state are unknown',
        owner,
        since: engagement.createdAt,
        action: 'Start scan',
        to: `/engagements/${encodeURIComponent(engagement.id)}`,
      })
    }
  }
  if (fleet) {
    for (const [verdict, count] of Object.entries(fleet.rowsByVerdict)) {
      if (verdict === 'covered' || count <= 0) continue
      const label = VERDICT_LABEL[verdict] ?? verdict.replaceAll('_', ' ')
      items.push({
        key: `coverage:${verdict}`,
        priority: 2,
        type: 'Coverage gap',
        subject: 'Fleet',
        issue: `${count} ${label} capability ${count === 1 ? 'check' : 'checks'}; the posture of the assets behind ${count === 1 ? 'it' : 'them'} may be out of date`,
        owner: 'Fleet',
        since: null,
        action: 'Open fleet coverage',
        to: '/fleet',
      })
    }
  }
  // Within a priority: exposure that already exists (posture) before a lost view of it (failed
  // scan), then coverage, then unscanned; ties by how long the condition has stood.
  return items.sort(
    (left, right) =>
      left.priority - right.priority ||
      TYPE_RANK[left.type] - TYPE_RANK[right.type] ||
      sinceMillis(left.since) - sinceMillis(right.since) ||
      left.subject.localeCompare(right.subject),
  )
}

function sinceMillis(iso: string | null): number {
  const ms = iso ? Date.parse(iso) : NaN
  return Number.isNaN(ms) ? Number.MAX_SAFE_INTEGER : ms
}

/** Age of a condition as a short label: "3h", "2d", "5w". Empty when the start is unknown. */
export function ageLabel(iso: string | null, now = Date.now()): string {
  const ms = iso ? Date.parse(iso) : NaN
  if (Number.isNaN(ms)) return ''
  const minutes = Math.max(0, Math.floor((now - ms) / 60_000))
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  if (hours < 48) return `${hours}h`
  const days = Math.floor(hours / 24)
  if (days < 14) return `${days}d`
  return `${Math.floor(days / 7)}w`
}
