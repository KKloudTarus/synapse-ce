import { useState } from 'react'
import { FileCode02, Tool02 } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { ImportedFinding } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, InfoNote, SevBadge, Spinner } from '../../components/ui'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { ApproveBindingDialog } from './ApproveBindingDialog'
import { useFetch } from '../../hooks'

function fmtTime(iso: string): string {
  if (!iso) return '—'
  const t = new Date(iso)
  if (Number.isNaN(t.getTime()) || t.getUTCFullYear() <= 1) return '—'
  return t.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function columns(onDecide: (finding: ImportedFinding) => void): Column<ImportedFinding>[] {
  return [
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
    // The state and the action on it sit in one cell. A separate column pushed the import timestamp off
    // a laptop screen, and a reader deciding whether to approve is looking at the state while they do it.
    header: 'Link',
    className: 'w-48',
    cell: (f) => (
      <span className="inline-flex items-center gap-2">
        <BindingBadge finding={f} />
        <Button
          variant="secondary"
          className="shrink-0 px-2 py-0.5 text-[11px]"
          onClick={() => onDecide(f)}
          aria-label={f.binding === 'approved' ? `Change the approved finding for ${f.title || f.rule}` : `Approve ${f.title || f.rule} onto a finding`}
        >
          {f.binding === 'approved' ? 'Change' : 'Approve'}
        </Button>
      </span>
    ),
  },
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
    className: 'w-40 min-w-0',
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
}

/**
 * How this row's link to a first-party finding should be read.
 *
 * The deduplicator sets findingId when an external result lands on the same file and line as a
 * first-party finding. That is evidence, and the table says so: it reads "Candidate" until someone
 * records the decision that the two describe one issue, and only then "Approved". Rendering both the
 * same way is what let a coincidence of line number merge two remediation workflows.
 */
function BindingBadge({ finding }: { finding: ImportedFinding }) {
  if (finding.binding === 'approved') {
    return (
      <span className="inline-flex items-center gap-1">
        <span className="rounded-md border border-utility-green-300 bg-success-primary px-2 py-0.5 text-[11px] font-medium text-success-primary">
          Approved
        </span>
        <InfoNote label="What approved means">
          A person recorded that this observation and finding {finding.approvedFindingId} describe one issue
          {finding.bindingVersion > 1 ? `, most recently at version ${finding.bindingVersion}` : ''}. The decision carries
          who made it and why, and replacing it keeps the version it replaced.
        </InfoNote>
      </span>
    )
  }
  if (finding.binding === 'candidate') {
    return (
      <span className="inline-flex items-center gap-1">
        <span className="rounded-md border border-secondary bg-primary px-2 py-0.5 text-[11px] font-medium text-tertiary">
          Candidate
        </span>
        <InfoNote label="What candidate means">
          This result landed on the same file and line as finding {finding.findingId}. That is evidence the two may be
          the same issue, not a decision that they are. Nothing merges until someone approves it.
        </InfoNote>
      </span>
    )
  }
  return <span className="text-[11px] text-quaternary">Not linked</span>
}

/**
 * Third-party findings a pipeline imported through the SARIF route. They are kept apart from
 * first-party findings on purpose: each entered under governance, cannot promote itself, and carries
 * the provenance a reviewer needs before trusting it. Until this tab existed the route wrote rows no
 * page rendered, so a successful CI import looked to the reader exactly like nothing having happened.
 */
export function ImportedFindingsTab({ engagementId }: { engagementId: string }) {
  const { data, loading, error, refetch } = useFetch(() => api.listImportedFindings(engagementId), { deps: [engagementId] })
  const [deciding, setDeciding] = useState<ImportedFinding | null>(null)

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
              columns={columns(setDeciding)}
              rowKey={(f) => f.id}
              maxHeightClass="max-h-[60vh]"
              tableMinWidthClass="min-w-[72rem]"
            />
          </>
        )}
      </Card>
      {deciding ? (
        <ApproveBindingDialog
          engagementId={engagementId}
          observation={deciding}
          onClose={() => setDeciding(null)}
          onDecided={() => {
            setDeciding(null)
            refetch()
          }}
        />
      ) : null}
    </div>
  )
}
