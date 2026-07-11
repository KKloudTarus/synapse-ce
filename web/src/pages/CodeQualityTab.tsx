import { useEffect, useMemo, useState } from 'react'
import { Copy, Gauge, ShieldCheck, Wrench } from 'lucide-react'
import { api } from '../lib/api'
import type { CodeQualityView, Finding, Grade, LanguageInventory } from '../lib/types'
import { Card, EmptyState, ErrorState, Pill, SevBadge, Spinner, cn } from '../components/ui'
import { VirtualTable, type Column } from '../components/VirtualTable'

// gradeTone maps an A-E grade to a severity-token color (A/B good, C caution, D/E bad).
function gradeTone(g: Grade): string {
  switch (g) {
    case 'A':
    case 'B':
      return 'text-low ring-low/30 bg-low/10'
    case 'C':
      return 'text-medium ring-medium/30 bg-medium/10'
    default: // D, E
      return 'text-critical ring-critical/30 bg-critical/10'
  }
}

function GradeBadge({ label, grade, icon: Icon }: { label: string; grade: Grade; icon: typeof Gauge }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-border bg-card p-3">
      <span className={cn('inline-flex size-9 items-center justify-center rounded-md text-lg font-semibold ring-1 tabular-nums', gradeTone(grade))} aria-hidden>
        {grade}
      </span>
      <div className="min-w-0">
        <div className="flex items-center gap-1.5 text-sm font-medium text-foreground">
          <Icon className="size-3.5 text-mutedfg" />
          {label}
        </div>
        <div className="text-xs text-mutedfg">
          rating <span className="font-medium">{grade}</span>
        </div>
      </div>
    </div>
  )
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-border bg-card p-3">
      <div className="text-xs text-mutedfg">{label}</div>
      <div className="font-mono text-lg tabular-nums text-foreground">{value}</div>
      {hint && <div className="text-xs text-mutedfg">{hint}</div>}
    </div>
  )
}

const findingCols: Column<Finding>[] = [
  { header: 'Severity', className: 'w-24', cell: (f) => <SevBadge sev={f.severity} /> },
  { header: 'Kind', className: 'w-28', cell: (f) => <Pill>{f.kind}</Pill> },
  { header: 'Issue', className: 'flex-1', cell: (f) => <span className="text-sm text-foreground">{f.title}</span> },
]

// CodeQualityTab renders the engagement's code-quality dashboard: A-E health ratings + technical debt,
// the per-language size inventory, the duplication summary, and the maintainability/reliability findings.
// Read-only; computed server-side over the in-scope local source directory (pure-Go, memory-safe).
export function CodeQualityTab({ engagementId }: { engagementId: string }) {
  const [view, setView] = useState<CodeQualityView | undefined>(undefined) // undefined = loading
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    setView(undefined)
    setErr(null)
    api
      .codeQuality(engagementId)
      .then(setView)
      .catch((e) => setErr(e instanceof Error ? e.message : 'Failed to load code quality'))
  }, [engagementId])

  const findings = view?.report?.findings ?? []
  const kindCounts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const f of findings) c[f.kind] = (c[f.kind] ?? 0) + 1
    return c
  }, [findings])

  if (err) return <ErrorState message={err} />
  if (view === undefined) return <Spinner label="Analyzing code quality…" />
  if (!view.available || !view.report) {
    return (
      <EmptyState
        icon={Gauge}
        title="Code quality unavailable"
        hint={view.reason || 'Code quality is computed over an in-scope local source directory; this engagement has none.'}
      />
    )
  }

  const r = view.report
  const total = r.inventory.reduce(
    (acc, l) => ({ files: acc.files + l.files, code: acc.code + l.codeLines }),
    { files: 0, code: 0 },
  )
  const dupDensity = r.duplication.totalLines > 0 ? (100 * r.duplication.duplicatedLines) / r.duplication.totalLines : 0
  const debtH = Math.floor(r.rating.techDebtMinutes / 60)
  const debtM = r.rating.techDebtMinutes % 60
  const langs = [...r.inventory].sort((a, b) => b.codeLines - a.codeLines)

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <GradeBadge label="Security" grade={r.rating.security} icon={ShieldCheck} />
        <GradeBadge label="Reliability" grade={r.rating.reliability} icon={Gauge} />
        <GradeBadge label="Maintainability" grade={r.rating.maintainability} icon={Wrench} />
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Technical debt" value={`${debtH}h ${debtM}m`} hint={`ratio ${r.rating.debtRatioPct.toFixed(1)}%`} />
        <Stat label="Code lines" value={total.code.toLocaleString()} hint={`${total.files} files`} />
        <Stat label="Duplication" value={`${dupDensity.toFixed(1)}%`} hint={`${r.duplication.blocks.length} blocks`} />
        <Stat label="Issues" value={String(findings.length)} hint={`${kindCounts['quality'] ?? 0} quality · ${kindCounts['reliability'] ?? 0} reliability`} />
      </div>

      <Card title="Languages">
        {langs.length === 0 ? (
          <p className="text-sm text-mutedfg">No source files detected.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-mutedfg">
                  <th className="py-1 pr-4 font-medium">Language</th>
                  <th className="py-1 pr-4 text-right font-medium">Files</th>
                  <th className="py-1 pr-4 text-right font-medium">Code</th>
                  <th className="py-1 pr-4 text-right font-medium">Comments</th>
                  <th className="py-1 text-right font-medium">Functions</th>
                </tr>
              </thead>
              <tbody className="font-mono tabular-nums">
                {langs.map((l: LanguageInventory) => (
                  <tr key={l.language} className="border-t border-border">
                    <td className="py-1 pr-4 font-sans text-foreground">{l.language}</td>
                    <td className="py-1 pr-4 text-right text-mutedfg">{l.files}</td>
                    <td className="py-1 pr-4 text-right text-foreground">{l.codeLines.toLocaleString()}</td>
                    <td className="py-1 pr-4 text-right text-mutedfg">{l.commentLines.toLocaleString()}</td>
                    <td className="py-1 text-right text-mutedfg">{l.functionsKnown ? l.functions : 'n/a'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {r.duplication.blocks.length > 0 && (
        <Card title="Duplicated blocks">
          <p className="mb-2 text-xs text-mutedfg">
            {dupDensity.toFixed(1)}% of {r.duplication.totalLines.toLocaleString()} code lines
          </p>
          <ul className="space-y-2">
            {[...r.duplication.blocks]
              .sort((a, b) => b.tokens - a.tokens)
              .slice(0, 20)
              .map((b, i) => (
                <li key={i} className="rounded-md border border-border bg-muted/30 p-2 text-sm">
                  <div className="flex items-center gap-1.5 text-mutedfg">
                    <Copy className="size-3.5" />
                    <span className="font-mono tabular-nums text-foreground">{b.tokens}</span> tokens, {b.occurrences.length} places
                  </div>
                  <div className="mt-1 space-y-0.5 font-mono text-xs text-mutedfg">
                    {b.occurrences.map((o, j) => (
                      <div key={j}>
                        {o.file}:{o.startLine}-{o.endLine}
                      </div>
                    ))}
                  </div>
                </li>
              ))}
          </ul>
        </Card>
      )}

      <Card title="Maintainability & reliability issues">
        {findings.length === 0 ? (
          <p className="text-sm text-mutedfg">No code-quality issues found.</p>
        ) : (
          <VirtualTable
            columns={findingCols}
            items={findings}
            rowKey={(f, i) => f.id || `${f.dedupKey}-${i}`}
          />
        )}
      </Card>
    </div>
  )
}
