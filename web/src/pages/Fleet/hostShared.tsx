import { SCAN_STATE_LABEL, ScanStatusPill, type ScanState } from '../../components/synapse/ScanStatusPill'
import type { HostFinding, HostRow, HostScan } from '../../lib/types'

/** Package and installed version of an SCA finding. The pipeline titles them "<advisory> in <pkg>@<version>";
 *  the dedup key ("vuln:<advisory>:<pkg>:<version>") is the fallback for a renamed title. */
export function hostFindingPackage(f: Pick<HostFinding, 'title' | 'dedupKey'>): { name: string; version: string } {
  const m = / in (.+)@([^@\s]+)$/.exec(f.title)
  if (m) return { name: m[1], version: m[2] }
  const parts = f.dedupKey.split(':')
  if (parts[0] === 'vuln' && parts.length >= 4) return { name: parts[2], version: parts.slice(3).join(':') }
  return { name: '', version: '' }
}

/** The advisory identifier shown as the row title: the advisory id when the pipeline recorded one, else the
 *  leading token of the title (a CVE or GHSA id). */
export function hostFindingAdvisory(f: Pick<HostFinding, 'title' | 'advisoryId'>): string {
  if (f.advisoryId) return f.advisoryId
  const i = f.title.indexOf(' in ')
  return i > 0 ? f.title.slice(0, i) : f.title
}

export function hostOS(row: Pick<HostRow, 'asset'>): string {
  const a = row.asset.attributes
  const os = a.os ?? ''
  const version = a.os_version ?? ''
  if (!os && !version) return '—'
  return [os, version].filter(Boolean).join(' ')
}

export function hostDegraded(row: Pick<HostRow, 'asset'>): boolean {
  return row.asset.attributes.degraded === 'true'
}

/**
 * Recorded scan status for a host, derived from what the server actually holds:
 * - `none`: the agent has never sent a package list (the asset records zero packages).
 * - `unrecorded`: the agent reported packages but no set is recorded (the recorder refused or failed;
 *   the inventory response and audit log carry the reason). This is the state a bare "no packages"
 *   badge used to hide behind while the host card said 427.
 * - `pending`: a set is recorded and no scan job exists yet.
 * - `running` | `succeeded` | `failed`: the latest scan job.
 */
export type HostScanState = ScanState

export function hostScanState(row: Pick<HostRow, 'engagementId' | 'lastScan' | 'packages' | 'asset'>): HostScanState {
  if (row.lastScan) return row.lastScan.status
  if (row.engagementId && row.packages > 0) return 'pending'
  const reported = Number(row.asset.attributes.packages ?? '0') || 0
  return reported > 0 ? 'unrecorded' : 'none'
}

export function HostScanBadge({ row }: { row: Pick<HostRow, 'engagementId' | 'lastScan' | 'packages' | 'asset'> }) {
  const state = hostScanState(row)
  const title = row.lastScan?.error || (row.lastScan ? `Stage: ${row.lastScan.stage}` : undefined)
  return <ScanStatusPill state={state} title={title} />
}

export function scanLabel(scan: HostScan | null): string {
  if (!scan) return SCAN_STATE_LABEL.none
  return SCAN_STATE_LABEL[scan.status]
}

export function scanStateLabel(state: HostScanState): string {
  return SCAN_STATE_LABEL[state]
}

/** The packages the host reported on its last inventory, whether or not a set was recorded. */
export function reportedPackages(row: Pick<HostRow, 'packages' | 'asset'>): number {
  return row.packages || (Number(row.asset.attributes.packages ?? '0') || 0)
}

/** A short display name for a host: the hostname up to its first dot, or the full name when short. */
export function hostShortName(name: string, key: string): string {
  const n = name || key
  if (n.length <= 32) return n
  const first = n.split('.')[0]
  return first.length <= 32 ? first : n.slice(0, 29) + '…'
}

export function formatCount(n: number): string {
  return n.toLocaleString()
}

/** Compact severity count cell: a number in the severity's colour, dimmed when zero. */
export { SeverityCount } from '../../components/synapse/SeverityCount'
