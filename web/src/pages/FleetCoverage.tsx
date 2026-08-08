import { useEffect, useState } from 'react'
import { Download, ShieldAlert } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import type { FleetCoverageRow, FleetCoverageSummary, FleetVerdict } from '../lib/types'
import { Button, Card, EmptyState, ErrorState, Spinner } from '../components/ui'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { FLEET_VERDICT_ORDER, FleetVerdictBadge, formatFleetTime, verdictLabel } from './fleetShared'

const COLUMNS: Column<FleetCoverageRow>[] = [
  {
    header: 'Asset',
    className: 'w-52',
    cell: (r) => (
      <span className="font-mono text-[12px] text-foreground" title={r.assetId}>
        {r.assetId}
      </span>
    ),
  },
  {
    header: 'Capability',
    className: 'w-40',
    cell: (r) => (
      <span className="font-mono text-[12px] text-mutedfg" title={r.capability || undefined}>
        {r.capability || '—'}
      </span>
    ),
  },
  {
    header: 'Verdict',
    className: 'w-36',
    cell: (r) => <FleetVerdictBadge verdict={r.verdict} />,
  },
  {
    header: 'Detail',
    className: 'flex-1',
    cell: (r) => <span className="text-mutedfg">{r.detail || '—'}</span>,
  },
  {
    header: 'Last run',
    className: 'w-44 tabular-nums',
    cell: (r) => (
      <span className="text-mutedfg" title={r.lastRun || undefined}>
        {formatFleetTime(r.lastRun)}
      </span>
    ),
  },
  {
    header: 'Agent',
    className: 'w-40',
    cell: (r) => (
      <span className="font-mono text-[12px] text-mutedfg" title={r.agentId || undefined}>
        {r.agentId || '—'}
      </span>
    ),
  },
]

function Stat({ label, value, tone }: { label: string; value: number; tone?: 'warn' }) {
  return (
    <div className="rounded-lg border border-border bg-elevated px-4 py-3">
      <div className={tone === 'warn' && value > 0 ? 'text-2xl font-bold tabular-nums text-critical' : 'text-2xl font-bold tabular-nums text-foreground'}>
        {value.toLocaleString()}
      </div>
      <div className="mt-0.5 text-xs text-mutedfg">{label}</div>
    </div>
  )
}

function SummaryCard({ summary }: { summary: FleetCoverageSummary }) {
  const total = Object.values(summary.rowsByVerdict).reduce((a, b) => a + b, 0)
  const covered = summary.rowsByVerdict['covered'] ?? 0
  const notCovered = total - covered
  const oldest = Object.entries(summary.oldestPerCapability).sort((a, b) => a[0].localeCompare(b[0]))
  return (
    <Card title="Coverage summary" className="mb-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Assessed pairs" value={total} />
        <Stat label="Covered" value={covered} />
        <Stat label="Not covered" value={notCovered} tone="warn" />
        <Stat label="Assets without an agent" value={summary.assetsWithoutAgent} tone="warn" />
      </div>

      <div className="mt-4">
        <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-subtlefg">By verdict</div>
        <div className="flex flex-wrap gap-2">
          {FLEET_VERDICT_ORDER.filter((v) => (summary.rowsByVerdict[v] ?? 0) > 0).map((v) => (
            <span key={v} className="inline-flex items-center gap-1.5">
              <FleetVerdictBadge verdict={v as FleetVerdict} />
              <span className="text-xs tabular-nums text-mutedfg">{summary.rowsByVerdict[v]}</span>
            </span>
          ))}
          {total === 0 && <span className="text-xs text-mutedfg">No coverage rows.</span>}
        </div>
      </div>

      {oldest.length > 0 && (
        <div className="mt-4">
          <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-subtlefg">Oldest assessment per capability</div>
          <ul className="space-y-1">
            {oldest.map(([cap, ts]) => (
              <li key={cap} className="flex items-center justify-between gap-3 text-xs">
                <span className="font-mono text-mutedfg">{cap}</span>
                <span className="tabular-nums text-subtlefg">{formatFleetTime(ts)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  )
}

export function FleetCoverage() {
  const [rows, setRows] = useState<FleetCoverageRow[] | null>(null)
  const [summary, setSummary] = useState<FleetCoverageSummary | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  function load() {
    setError(null)
    setRows(null)
    setSummary(null)
    Promise.all([api.listFleetCoverage(), api.fleetCoverageSummary()])
      .then(([r, s]) => {
        setRows(r)
        setSummary(s)
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : 'Failed to load fleet coverage'))
  }
  useEffect(load, [])

  async function onExport() {
    setExportError(null)
    setExporting(true)
    try {
      await api.exportFleetCoverage()
    } catch (e) {
      setExportError(e instanceof ApiError ? e.message : 'Export failed')
    } finally {
      setExporting(false)
    }
  }

  if (error) {
    return (
      <div className="space-y-3">
        <ErrorState message={error} />
        <Button variant="secondary" onClick={load}>
          Retry
        </Button>
      </div>
    )
  }
  if (!rows || !summary) return <Spinner label="Loading fleet coverage…" />

  return (
    <div>
      <SummaryCard summary={summary} />

      {rows.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="No coverage rows"
          hint="No assets are in scope for this tenant yet, or the fleet is not enabled. Enrol an agent and register assets to see per-capability coverage."
        />
      ) : (
        <Card
          title="Per-asset coverage"
          bodyClass="p-0"
          actions={
            <Button variant="secondary" onClick={onExport} loading={exporting}>
              <Download className="size-4" /> Export CSV
            </Button>
          }
        >
          {exportError && (
            <div className="px-6 pt-4">
              <ErrorState message={exportError} />
            </div>
          )}
          <VirtualTable
            items={rows}
            columns={COLUMNS}
            rowKey={(r, i) => `${r.assetId}:${r.capability}:${i}`}
            maxHeightClass="max-h-[65vh]"
            tableMinWidthClass="min-w-[64rem]"
          />
        </Card>
      )}

      <p className="mt-4 text-xs text-mutedfg">
        Every state except <span className="font-semibold">{verdictLabel('covered')}</span> is a gap that is surfaced,
        not hidden. Unknown, stale, refused and unauthorized are never counted as covered.
      </p>
    </div>
  )
}
