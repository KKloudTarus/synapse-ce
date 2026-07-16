import { useMemo, type ReactNode } from 'react'
import { Braces, Copy, FileCode2, Gauge, ShieldCheck, Wrench } from 'lucide-react'
import type { CodeQualityReport, Finding, Grade, LanguageInventory } from '../../lib/types'
import { Card, Pill, SevBadge, cn } from '../ui'
import { VirtualTable, type Column } from '../VirtualTable'

function gradeTone(grade: Grade): string {
  switch (grade) {
    case 'A':
    case 'B':
      return 'border-low/25 bg-low/10 text-low'
    case 'C':
      return 'border-medium/25 bg-medium/10 text-medium'
    default:
      return 'border-critical/25 bg-critical/10 text-critical'
  }
}

function GradeCard({ label, grade, detail, icon: Icon }: { label: string; grade: Grade; detail: string; icon: typeof Gauge }) {
  return (
    <div className="flex min-h-28 items-center gap-4 rounded-lg border border-border bg-bg px-4 py-4">
      <span
        className={cn('inline-flex size-14 shrink-0 items-center justify-center rounded-lg border font-mono text-3xl font-semibold tabular-nums', gradeTone(grade))}
        aria-label={`${label} rating ${grade}`}
      >
        {grade}
      </span>
      <div className="min-w-0">
        <div className="mb-1 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-mutedfg">
          <Icon className="size-4" aria-hidden="true" />
          {label}
        </div>
        <p className="text-sm text-foreground">Grade {grade}</p>
        <p className="mt-0.5 text-xs text-subtlefg">{detail}</p>
      </div>
    </div>
  )
}

function Metric({ label, value, hint, icon: Icon }: { label: string; value: string; hint: string; icon: typeof Gauge }) {
  return (
    <div className="bg-card px-5 py-4">
      <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.12em] text-mutedfg">
        <Icon className="size-3.5" aria-hidden="true" />
        {label}
      </div>
      <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-foreground">{value}</div>
      <div className="mt-0.5 text-xs text-subtlefg">{hint}</div>
    </div>
  )
}

const findingCols: Column<Finding>[] = [
  { header: 'Severity', className: 'w-24 shrink-0', cell: (finding) => <SevBadge sev={finding.severity} /> },
  { header: 'Kind', className: 'w-28 shrink-0', cell: (finding) => <Pill>{finding.kind}</Pill> },
  { header: 'Issue', className: 'min-w-64 flex-1', cell: (finding) => <span className="text-sm text-foreground">{finding.title}</span> },
]

const languageCols: Column<LanguageInventory>[] = [
  { header: 'Language', className: 'min-w-40 flex-1', cell: (language) => <span className="font-medium text-foreground">{language.language}</span> },
  { header: 'Files', className: 'w-20 shrink-0 text-right', cell: (language) => <span className="font-mono tabular-nums text-mutedfg">{language.files.toLocaleString()}</span> },
  { header: 'Code', className: 'w-24 shrink-0 text-right', cell: (language) => <span className="font-mono tabular-nums text-foreground">{language.codeLines.toLocaleString()}</span> },
  { header: 'Comments', className: 'w-24 shrink-0 text-right', cell: (language) => <span className="font-mono tabular-nums text-mutedfg">{language.commentLines.toLocaleString()}</span> },
  { header: 'Functions', className: 'w-24 shrink-0 text-right', cell: (language) => <span className="font-mono tabular-nums text-mutedfg">{language.functionsKnown ? language.functions.toLocaleString() : 'n/a'}</span> },
]

export function CodeQualityReportView({ report, empty }: { report?: CodeQualityReport; empty: ReactNode }) {
  const findings = report?.findings ?? []
  const kindCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const finding of findings) counts[finding.kind] = (counts[finding.kind] ?? 0) + 1
    return counts
  }, [findings])

  if (!report) return <>{empty}</>

  const total = report.inventory.reduce(
    (acc, language) => ({ files: acc.files + language.files, code: acc.code + language.codeLines }),
    { files: 0, code: 0 },
  )
  const dupDensity = report.duplication.totalLines > 0 ? (100 * report.duplication.duplicatedLines) / report.duplication.totalLines : 0
  const debtH = Math.floor(report.rating.techDebtMinutes / 60)
  const debtM = report.rating.techDebtMinutes % 60
  const languages = [...report.inventory].sort((a, b) => b.codeLines - a.codeLines)
  const duplicateBlocks = [...report.duplication.blocks].sort((a, b) => b.tokens - a.tokens).slice(0, 20)

  return (
    <div className="space-y-6">
      <Card title="Quality ratings">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <GradeCard label="Security" grade={report.rating.security} detail="Worst security issue severity" icon={ShieldCheck} />
          <GradeCard label="Reliability" grade={report.rating.reliability} detail="Worst reliability issue severity" icon={Gauge} />
          <GradeCard label="Maintainability" grade={report.rating.maintainability} detail={`${report.rating.debtRatioPct.toFixed(2)}% technical-debt ratio`} icon={Wrench} />
        </div>
      </Card>

      <Card
        title="Measures"
        actions={
          <span className="text-xs text-subtlefg" title="Technical debt is estimated from maintainability issue severity: info 5m, low 10m, medium 20m, high 60m, critical 120m. The ratio compares that debt with 30 minutes per line of code.">
            Estimated remediation effort
          </span>
        }
        bodyClass="p-0"
      >
        <div className="grid grid-cols-1 gap-px bg-border sm:grid-cols-2 lg:grid-cols-4">
          <Metric label="Technical debt" value={`${debtH}h ${debtM}m`} hint={`${report.rating.debtRatioPct.toFixed(2)}% of estimated development cost`} icon={Wrench} />
          <Metric label="Code lines" value={total.code.toLocaleString()} hint={`${total.files.toLocaleString()} source files`} icon={FileCode2} />
          <Metric label="Duplication" value={`${dupDensity.toFixed(1)}%`} hint={`${report.duplication.blocks.length.toLocaleString()} duplicate blocks`} icon={Copy} />
          <Metric label="Issues" value={findings.length.toLocaleString()} hint={`${kindCounts.quality ?? 0} quality · ${kindCounts.reliability ?? 0} reliability`} icon={Gauge} />
        </div>
      </Card>

      <Card title="Languages" actions={<Pill>{languages.length.toLocaleString()} detected</Pill>} bodyClass="p-0">
        {languages.length === 0 ? (
          <p className="px-6 py-5 text-sm text-mutedfg">No source files detected in this analysis.</p>
        ) : (
          <VirtualTable
            columns={languageCols}
            items={languages}
            rowKey={(language) => language.language}
            rowHeight={44}
            maxHeightClass="max-h-96"
            tableMinWidthClass="min-w-[640px]"
          />
        )}
      </Card>

      <Card
        title="Duplicated blocks"
        actions={<div className="flex items-center gap-2"><Pill>{dupDensity.toFixed(1)}% density</Pill>{report.duplication.blocks.length > duplicateBlocks.length && <span className="text-xs text-subtlefg">Showing {duplicateBlocks.length.toLocaleString()} of {report.duplication.blocks.length.toLocaleString()}</span>}</div>}
        bodyClass={duplicateBlocks.length === 0 ? undefined : 'p-0'}
      >
        {duplicateBlocks.length === 0 ? (
          <p className="text-sm text-mutedfg">No duplicated code blocks were detected.</p>
        ) : (
          <ol className="max-h-[32rem] divide-y divide-border overflow-y-auto overscroll-contain">
            {duplicateBlocks.map((block, index) => (
              <li key={index} className="px-5 py-4">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                  <span className="inline-flex items-center gap-1.5 font-medium text-foreground">
                    <Copy className="size-3.5 text-mutedfg" aria-hidden="true" />
                    Duplicate group {index + 1}
                  </span>
                  <span className="font-mono text-xs tabular-nums text-mutedfg">{block.tokens.toLocaleString()} tokens · {block.occurrences.length.toLocaleString()} locations</span>
                </div>
                <div className="mt-2 space-y-1 rounded-md border border-border bg-elevated px-3 py-2 font-mono text-xs text-mutedfg">
                  {block.occurrences.map((occurrence, occurrenceIndex) => (
                    <div key={occurrenceIndex} className="flex min-w-0 items-center gap-2">
                      <Braces className="size-3 shrink-0 text-subtlefg" aria-hidden="true" />
                      <span className="truncate text-foreground">{occurrence.file}</span>
                      <span className="ml-auto shrink-0 tabular-nums">lines {occurrence.startLine}–{occurrence.endLine}</span>
                    </div>
                  ))}
                </div>
              </li>
            ))}
          </ol>
        )}
      </Card>

      <Card title="Maintainability & reliability issues" actions={<Pill>{findings.length.toLocaleString()} issues</Pill>} bodyClass={findings.length === 0 ? undefined : 'p-0'}>
        {findings.length === 0 ? (
          <p className="text-sm text-mutedfg">No code-quality issues were detected in this analysis.</p>
        ) : (
          <VirtualTable
            columns={findingCols}
            items={findings}
            rowKey={(finding, index) => finding.id || `${finding.dedupKey}-${index}`}
            tableMinWidthClass="min-w-[640px]"
          />
        )}
      </Card>
    </div>
  )
}
