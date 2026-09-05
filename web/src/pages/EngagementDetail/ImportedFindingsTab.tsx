import { FileCode02, Tool02 } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { ImportedFinding } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, SevBadge, Spinner } from '../../components/ui'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { useFetch } from '../../hooks'

function fmtTime(iso: string): string {
  if (!iso) return '—'
  const t = new Date(iso)
  if (Number.isNaN(t.getTime()) || t.getUTCFullYear() <= 1) return '—'
  return t.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

const COLUMNS: Column<ImportedFinding>[] = [
  {
    header: 'Finding',
    className: 'flex-1 min-w-0',
    cell: (f) => (
      <div className="min-w-0">
        <div className="truncate text-sm font-medium text-primary" title={f.title}>{f.title || f.rule}</div>
        <div className="truncate font-mono text-[11px] text-quaternary" title={f.rule}>{f.rule}</div>
      </div>
    ),
  },
  { header: 'Severity', className: 'w-28', cell: (f) => <SevBadge sev={f.severity} /> },
  {
    header: 'Location',
    className: 'w-72 min-w-0',
    cell: (f) =>
      f.path ? (
        <span className="inline-flex min-w-0 items-center gap-1 font-mono text-[12px] text-secondary" title={f.path}>
          <FileCode02 className="size-3.5 shrink-0 text-fg-tertiary" aria-hidden="true" />
          <span className="truncate">{f.path}</span>
          {f.startLine > 0 && <span className="shrink-0 text-tertiary">:{f.startLine}</span>}
        </span>
      ) : (
        <span className="text-quaternary">{f.logicalName || '—'}</span>
      ),
  },
  {
    header: 'Tool',
    className: 'w-44 min-w-0',
    cell: (f) => (
      <span className="inline-flex min-w-0 items-center gap-1 text-[12px] text-tertiary" title={`${f.tool} ${f.toolVersion}`}>
        <Tool02 className="size-3.5 shrink-0 text-fg-tertiary" aria-hidden="true" />
        <span className="truncate">{f.tool}</span>
        {f.toolVersion && <span className="shrink-0 font-mono text-quaternary">{f.toolVersion}</span>}
      </span>
    ),
  },
  {
    header: 'Imported',
    className: 'w-44 tabular-nums',
    cell: (f) => <span className="text-tertiary" title={`${f.ingestedBy} · ${f.ingestedAt}`}>{fmtTime(f.ingestedAt)}</span>,
  },
]

/**
 * Third-party findings a pipeline imported through the SARIF route. They are kept apart from
 * first-party findings on purpose: each entered under governance, cannot promote itself, and carries
 * the provenance a reviewer needs before trusting it. Until this tab existed the route wrote rows no
 * page rendered, so a successful CI import looked to the reader exactly like nothing having happened.
 */
export function ImportedFindingsTab({ engagementId }: { engagementId: string }) {
  const { data, loading, error, refetch } = useFetch(() => api.listImportedFindings(engagementId), { deps: [engagementId] })

  if (loading && !data) return <Spinner label="Loading imported findings" />
  if (error) {
    return (
      <div className="space-y-3">
        <ErrorState message={error} />
        <Button variant="secondary" onClick={refetch}>Retry</Button>
      </div>
    )
  }

  const findings = data ?? []
  const tools = new Map<string, number>()
  for (const f of findings) tools.set(f.tool || 'unknown tool', (tools.get(f.tool || 'unknown tool') ?? 0) + 1)
  const suppressed = findings.filter((f) => f.suppressedByTool).length

  return (
    <div className="space-y-4">
      <Card title={`Imported findings${findings.length ? ` (${findings.length})` : ''}`}>
        <p className="mb-3 text-sm text-tertiary">
          Results a pipeline or an external scanner sent through the SARIF import route. They are reviewed like any other
          finding and cannot promote themselves.
        </p>
        {findings.length === 0 ? (
          <EmptyState
            icon={Tool02}
            title="Nothing imported yet"
            hint="Send a SARIF 2.1.0 report to POST /api/v1/engagements/{id}/sarif, for example the output of synapse-cli scan --sarif from CI, and it appears here with its tool and provenance."
          />
        ) : (
          <>
            <div className="mb-3 flex flex-wrap items-center gap-2 text-[12px] text-tertiary" aria-label="Import summary">
              <span className="rounded-md border border-secondary bg-primary px-2 py-0.5 font-medium text-secondary">
                {findings.length} finding{findings.length === 1 ? '' : 's'}
              </span>
              {[...tools.entries()].map(([tool, n]) => (
                <span key={tool} className="rounded-md border border-secondary bg-primary px-2 py-0.5">
                  {tool} · {n}
                </span>
              ))}
              {suppressed > 0 && (
                <span className="rounded-md border border-secondary bg-primary px-2 py-0.5" title="Suppressed by the producing tool, kept for the record">
                  {suppressed} suppressed by tool
                </span>
              )}
            </div>
            <VirtualTable
              items={findings}
              columns={COLUMNS}
              rowKey={(f) => f.id}
              maxHeightClass="max-h-[60vh]"
              tableMinWidthClass="min-w-[60rem]"
            />
          </>
        )}
      </Card>
    </div>
  )
}
