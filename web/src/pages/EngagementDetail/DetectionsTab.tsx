import { useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, GitBranch01, RefreshCw01 } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { AgentDetectionClass, AgentDetectionRecord, CorrelateResult, CurrentUser } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Pill, SevBadge, Spinner, cn } from '../../components/ui'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { useFetch, useMutation } from '../../hooks'

const OPERATE_ROLES = ['admin', 'consultant', 'member']

const CLASS_STYLE: Record<Exclude<AgentDetectionClass, ''>, string> = {
  process: 'bg-info/10 text-info ring-info/30',
  network: 'bg-medium/10 text-medium ring-medium/30',
  file: 'bg-accent/10 text-accent ring-accent/30',
  privilege: 'bg-critical/10 text-critical ring-critical/30',
}

function ClassBadge({ cls }: { cls: AgentDetectionClass }) {
  if (!cls) return <span className="text-quaternary">—</span>
  return (
    <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset', CLASS_STYLE[cls])}>
      {cls}
    </span>
  )
}

function fmtTime(iso: string): string {
  if (!iso) return '—'
  const t = new Date(iso)
  if (Number.isNaN(t.getTime()) || t.getUTCFullYear() <= 1) return '—'
  return t.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

const COLUMNS: Column<AgentDetectionRecord>[] = [
  {
    header: 'Rule',
    className: 'flex-1 min-w-0',
    cell: (d) => (
      <div className="min-w-0">
        <div className="truncate font-mono text-[12px] text-primary" title={d.ruleId}>{d.ruleId || d.id}</div>
        <div className="truncate font-mono text-[10px] text-quaternary">v{d.ruleVersion} · {d.id}</div>
      </div>
    ),
  },
  { header: 'Class', className: 'w-28', cell: (d) => <ClassBadge cls={d.class} /> },
  { header: 'Severity', className: 'w-28', cell: (d) => <SevBadge sev={d.severity} /> },
  {
    header: 'Agent',
    className: 'w-36',
    cell: (d) => <span className="font-mono text-[12px] text-tertiary" title={d.agentId}>{d.agentId || '—'}</span>,
  },
  {
    header: 'Evidence',
    className: 'w-28 tabular-nums',
    cell: (d) => (
      <span className="text-tertiary" title={d.truncated ? `window truncated; ${d.observedCount} observed` : undefined}>
        {d.evidenceCount}
        {d.truncated && <span className="ml-1 text-medium" title="evidence window truncated">⋯</span>}
      </span>
    ),
  },
  {
    header: 'Observed',
    className: 'w-44 tabular-nums',
    cell: (d) => <span className="text-tertiary" title={d.observed}>{fmtTime(d.observed)}</span>,
  },
]

export function DetectionsTab({ engagementId }: { engagementId: string }) {
  const { data: me } = useFetch<CurrentUser | null>(() => api.me().catch(() => null), { deps: [] })
  const canOperate = OPERATE_ROLES.includes(me?.role ?? '')

  const { data, loading, error, refetch } = useFetch(() => api.listEngagementDetections(engagementId), { deps: [engagementId] })
  const [result, setResult] = useState<CorrelateResult | null>(null)

  const correlate = useMutation(() => api.correlateEngagement(engagementId), {
    onSuccess: (r) => { setResult(r); refetch() },
  })

  const detections = data?.detections ?? null
  const scope = data?.fieldScope ?? ''

  return (
    <div className="space-y-5">
      <Card
        title={`Agent security detections${detections ? ` (${detections.length})` : ''}`}
        actions={
          canOperate ? (
            <Button variant="secondary" className="px-2.5 py-1 text-xs" loading={correlate.loading} onClick={() => correlate.mutate(undefined)}>
              <GitBranch01 className="size-4" /> Correlate → incidents
            </Button>
          ) : undefined
        }
        bodyClass="p-0"
      >
        {scope && scope !== 'full' && (
          <div className="border-b border-secondary px-4 py-2 text-xs text-tertiary">
            Field scope: <span className="font-mono text-secondary">{scope}</span> — some evidence fields are redacted for your role.
          </div>
        )}
        {correlate.error && <div className="px-4 pt-3"><ErrorState message={correlate.error} /></div>}
        {result && (
          <div className="flex flex-wrap items-center gap-2 border-b border-secondary bg-secondary/30 px-4 py-2 text-sm">
            <Pill>{result.created.length} incident{result.created.length === 1 ? '' : 's'} created</Pill>
            <span className="text-xs text-tertiary">· {result.reassessed} reassessed{result.reassessFailed ? ` · ${result.reassessFailed} failed` : ''}</span>
            <Link to="/fleet/incidents" className="ml-auto text-xs font-semibold text-brand-solid hover:underline">View incidents →</Link>
          </div>
        )}

        {loading && !detections ? (
          <div className="px-4 py-6"><Spinner label="Loading detections…" /></div>
        ) : error ? (
          <div className="p-4 space-y-3">
            <ErrorState message={error} />
            <Button variant="secondary" onClick={refetch}>Retry</Button>
          </div>
        ) : detections && detections.length > 0 ? (
          <VirtualTable
            items={detections}
            columns={COLUMNS}
            rowKey={(d) => d.id}
            maxHeightClass="max-h-[60vh]"
            tableMinWidthClass="min-w-[60rem]"
          />
        ) : (
          <div className="p-6">
            <EmptyState
              icon={AlertTriangle}
              title="No detections"
              hint="Agent security detections for this engagement appear here once an enrolled agent ships a signed detection batch. Correlate folds them into incidents."
            />
          </div>
        )}
      </Card>

      <p className="flex items-center gap-1.5 text-xs text-quaternary">
        <RefreshCw01 className="size-3.5" />
        Correlation is operator-triggered over a stable window (it never auto-runs, to avoid duplicate incidents). Requires operate permission.
      </p>
    </div>
  )
}

export default DetectionsTab
