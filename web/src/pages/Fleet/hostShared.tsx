import { Pill, cn } from '../../components/ui'
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

/** Recorded scan status for a host. `none` is a host that never reported packages. */
export type HostScanState = 'none' | 'running' | 'succeeded' | 'failed'

export function hostScanState(row: Pick<HostRow, 'engagementId' | 'lastScan'>): HostScanState {
  if (!row.engagementId || !row.lastScan) return 'none'
  return row.lastScan.status
}

const SCAN_LABEL: Record<HostScanState, string> = {
  none: 'No packages reported',
  running: 'Scanning',
  succeeded: 'Scanned',
  failed: 'Scan failed',
}

const SCAN_CLASS: Record<HostScanState, string> = {
  none: 'bg-secondary text-tertiary',
  running: 'bg-brand-primary text-brand-secondary',
  succeeded: 'bg-success-primary text-success-primary',
  failed: 'bg-error-primary text-error-primary',
}

export function HostScanBadge({ row }: { row: Pick<HostRow, 'engagementId' | 'lastScan'> }) {
  const state = hostScanState(row)
  const title = row.lastScan?.error || (row.lastScan ? `Stage: ${row.lastScan.stage}` : undefined)
  return <Pill className={cn(SCAN_CLASS[state])}><span title={title}>{SCAN_LABEL[state]}</span></Pill>
}

export function scanLabel(scan: HostScan | null): string {
  if (!scan) return SCAN_LABEL.none
  return SCAN_LABEL[scan.status]
}

/** Compact severity count cell: a number in the severity's colour, dimmed when zero. */
export function SeverityCount({ count, tone }: { count: number; tone: 'critical' | 'high' | 'medium' | 'low' }) {
  const color = { critical: 'text-critical', high: 'text-high', medium: 'text-medium', low: 'text-low' }[tone]
  return (
    <span className={cn('font-mono text-sm tabular-nums', count > 0 ? cn(color, 'font-semibold') : 'text-quaternary')}>
      {count}
    </span>
  )
}
