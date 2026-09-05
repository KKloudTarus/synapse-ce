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
  /** When this condition is due for action, derived from `since` plus a priority SLA window. Null when
   *  the start is unknown (e.g. a fleet coverage gap with no recorded onset). */
  dueAt: string | null
  action: string
  to: string
}

// slaWindowMs is the time an operator has to act on a condition, by priority: P1 within a day, P2 within
// three days, P3 within a week. A default operational SLA, not a per-tenant policy; it turns "how long has
// this stood" (age) into "how long until it must be handled" (due), which is what orders the work.
const slaWindowMs: Record<AttentionPriority, number> = {
  1: 24 * 60 * 60 * 1000,
  2: 72 * 60 * 60 * 1000,
  3: 7 * 24 * 60 * 60 * 1000,
}

function dueAtFrom(since: string | null, priority: AttentionPriority): string | null {
  if (!since) return null
  const ms = Date.parse(since)
  if (Number.isNaN(ms)) return null
  return new Date(ms + slaWindowMs[priority]).toISOString()
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
      dueAt: null,
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
        dueAt: null,
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
        dueAt: null,
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
        dueAt: null,
        action: 'Open fleet coverage',
        to: '/fleet',
      })
    }
  }
  // Within a priority: exposure that already exists (posture) before a lost view of it (failed
  // scan), then coverage, then unscanned; ties by how long the condition has stood.
  for (const item of items) {
    item.dueAt = dueAtFrom(item.since, item.priority)
  }
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

/** dueLabel renders the operational urgency: "Overdue 4h", "Due 6h", "Due 2d", or "" when there is no
 *  due date. tone drives colour: overdue is critical, due within 12h is warning, otherwise neutral. */
export function dueLabel(dueAt: string | null, now = Date.now()): { text: string; tone: 'critical' | 'warning' | 'muted' } {
  if (!dueAt) return { text: '', tone: 'muted' }
  const ms = Date.parse(dueAt)
  if (Number.isNaN(ms)) return { text: '', tone: 'muted' }
  const diff = ms - now
  const span = (abs: number): string => {
    const h = Math.floor(abs / (60 * 60 * 1000))
    if (h < 1) return `${Math.max(1, Math.floor(abs / (60 * 1000)))}m`
    if (h < 48) return `${h}h`
    return `${Math.floor(h / 24)}d`
  }
  if (diff < 0) return { text: `Overdue ${span(-diff)}`, tone: 'critical' }
  return { text: `Due ${span(diff)}`, tone: diff < 12 * 60 * 60 * 1000 ? 'warning' : 'muted' }
}
