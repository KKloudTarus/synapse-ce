import {
  AlertCircle,
  Clock,
  CpuChip01,
  File01,
  FileCode01,
  FolderClosed,
  Percent01,
  ShieldTick,
  Star01,
  Tool01,
  Virus,
  Zap,
} from '@untitledui/icons'
import { Pill, cn } from '../../../components/ui'
import type { Column } from '../../../components/synapse/VirtualTable'
import type {
  MeasureCountMetric,
  MeasureDecimalMetric,
  MeasureGradeMetric,
  MeasureNode,
} from '../../../lib/projectMeasures'

export function GradeBadge({ grade }: { grade: string }) {
  const g = grade.toUpperCase()
  const colorMap: Record<string, string> = {
    A: 'bg-success-primary/15 text-success-primary border-success-primary/35',
    B: 'bg-utility-green-500/15 text-utility-green-600 dark:text-utility-green-400 border-utility-green-500/35',
    C: 'bg-warning-primary/15 text-warning-primary border-warning-primary/35',
    D: 'bg-utility-orange-500/15 text-utility-orange-600 dark:text-utility-orange-400 border-utility-orange-500/35',
    E: 'bg-error-primary/15 text-error-primary border-error-primary/35',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center justify-center size-6 rounded-md font-mono font-black text-xs border shadow-2xs',
        colorMap[g] || 'bg-secondary text-primary border-secondary',
      )}
    >
      {g}
    </span>
  )
}

export function MetricValue({
  m,
  suffix = '',
  showProgressBar = false,
}: {
  m: MeasureCountMetric | MeasureDecimalMetric | MeasureGradeMetric | undefined
  suffix?: string
  showProgressBar?: boolean
}) {
  if (!m) return <span className="text-tertiary font-mono" title="Omitted">—</span>
  if (m.availability === 'not_applicable') {
    return <span className="text-quaternary font-mono text-xs" title="Not applicable">N/A</span>
  }
  if (m.availability === 'unavailable') {
    return (
      <span className="text-tertiary flex items-center gap-1 font-mono" title={m.reason ?? 'Unavailable'}>
        —
        {m.reason && <AlertCircle className="size-3 text-brand-secondary" aria-hidden="true" />}
      </span>
    )
  }

  if ('grade' in m) {
    return <GradeBadge grade={m.grade ?? ''} />
  }

  if (m.value === null) return <span className="text-tertiary font-mono">—</span>

  const num = m.value
  const formatted = num.toLocaleString(undefined, { maximumFractionDigits: 2 })

  if (showProgressBar) {
    const clamped = Math.max(0, Math.min(100, num))
    return (
      <div className="flex items-center gap-2">
        <span className="tabular-nums font-mono font-medium">{formatted}{suffix}</span>
        <div className="w-16 h-1.5 rounded-full bg-secondary overflow-hidden hidden sm:block">
          <div
            className={cn(
              'h-full rounded-full transition-all',
              clamped >= 80 ? 'bg-success-primary' : clamped >= 50 ? 'bg-warning-primary' : 'bg-error-primary',
            )}
            style={{ width: `${clamped}%` }}
          />
        </div>
      </div>
    )
  }

  return (
    <span className="tabular-nums font-mono font-medium">
      {formatted}
      {suffix}
    </span>
  )
}

export function getDomainColumns(
  domain: string,
  totalLinesInNode?: number,
): (setPath: (p: string) => void) => Column<MeasureNode>[] {
  const baseColumns: (setPath: (p: string) => void) => Column<MeasureNode>[] = (setPath) => [
    {
      header: 'Name',
      className: 'w-[38%] min-w-[220px]',
      cell: (item) => {
        const navigable = item.kind === 'directory' || item.kind === 'file'
        const isDir = item.kind === 'directory'

        return (
          <div className="flex items-center gap-2.5 min-w-0">
            {isDir ? (
              <div className="p-1 rounded-md bg-brand-primary/10 text-brand-secondary shrink-0 border border-brand/20">
                <FolderClosed className="size-4" aria-hidden="true" />
              </div>
            ) : (
              <div className="p-1 rounded-md bg-secondary text-tertiary shrink-0 border border-secondary">
                <File01 className="size-4" aria-hidden="true" />
              </div>
            )}
            {navigable ? (
              <button
                onClick={() => setPath(item.path)}
                className="rounded-sm font-semibold hover:underline hover:text-brand-secondary text-left truncate text-primary text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                title={item.name}
              >
                {item.name}
              </button>
            ) : (
              <span className="font-semibold truncate text-primary text-xs" title={item.name}>
                {item.name}
              </span>
            )}
          </div>
        )
      },
    },
    {
      header: 'Kind',
      className: 'w-[12%] min-w-[90px]',
      cell: (item) => (
        <span className={cn('text-xs capitalize font-medium', item.kind === 'directory' ? 'text-brand-secondary font-semibold' : 'text-tertiary')}>
          {item.kind}
        </span>
      ),
    },
    {
      header: 'Language',
      className: 'w-[12%] min-w-[90px]',
      cell: (item) => (item.language ? <Pill className="text-[10px] py-0.2">{item.language}</Pill> : <span className="text-quaternary font-mono text-xs">—</span>),
    },
  ]

  return (setPath) => {
    const base = baseColumns(setPath)
    switch (domain) {
      case 'size':
        return [
          ...base,
          {
            header: 'Files',
            cell: (i) => <MetricValue m={i.size?.files} />,
          },
          {
            header: 'Code Lines (Relative)',
            className: 'w-[25%] min-w-[160px]',
            cell: (i) => {
              const lines = i.size?.ncloc?.value
              if (lines == null) return <MetricValue m={i.size?.ncloc} />
              const pct = totalLinesInNode && totalLinesInNode > 0 ? (lines / totalLinesInNode) * 100 : 0

              return (
                <div className="flex items-center gap-2.5">
                  <span className="tabular-nums font-mono font-bold text-primary min-w-[4rem]">
                    {lines.toLocaleString()}
                  </span>
                  {totalLinesInNode && totalLinesInNode > 0 ? (
                    <div className="flex items-center gap-1.5 flex-1 max-w-[100px]">
                      <div className="h-1.5 flex-1 rounded-full bg-secondary overflow-hidden">
                        <div
                          className="h-full rounded-full bg-brand-secondary transition-all"
                          style={{ width: `${Math.min(100, Math.max(2, pct))}%` }}
                        />
                      </div>
                      <span className="text-[10px] text-tertiary font-mono tabular-nums">
                        {pct.toFixed(1)}%
                      </span>
                    </div>
                  ) : null}
                </div>
              )
            },
          },
          {
            header: 'Functions',
            cell: (i) => <MetricValue m={i.size?.functions} />,
          },
        ]
      case 'complexity':
        return [
          ...base,
          {
            header: 'Cyclomatic Complexity',
            cell: (i) => <MetricValue m={i.complexity?.cyclomatic} />,
          },
          {
            header: 'Cognitive Complexity',
            cell: (i) => <MetricValue m={i.complexity?.cognitive} />,
          },
        ]
      case 'coverage':
        return [
          ...base,
          {
            header: 'Coverage %',
            cell: (i) => <MetricValue m={i.coverage?.coverage} suffix="%" showProgressBar />,
          },
          {
            header: 'New Code %',
            cell: (i) => <MetricValue m={i.coverage?.newCodeCoverage} suffix="%" />,
          },
          {
            header: 'Covered Lines',
            cell: (i) => <MetricValue m={i.coverage?.coveredLines} />,
          },
        ]
      case 'duplication':
        return [
          ...base,
          {
            header: 'Duplication %',
            cell: (i) => <MetricValue m={i.duplication?.duplicationDensity} suffix="%" showProgressBar />,
          },
          {
            header: 'Duplicated Lines',
            cell: (i) => <MetricValue m={i.duplication?.duplicatedLines} />,
          },
          {
            header: 'Blocks',
            cell: (i) => <MetricValue m={i.duplication?.duplicationBlocks} />,
          },
        ]
      case 'issues':
        return [
          ...base,
          {
            header: '🐞 Bugs',
            cell: (i) => {
              const count = i.issues?.byType['bug']?.value
              return count && count > 0 ? (
                <span className="inline-flex items-center gap-1 rounded bg-warning-primary/10 text-warning-primary px-1.5 py-0.5 font-mono font-bold text-xs border border-warning-primary/25">
                  {count}
                </span>
              ) : (
                <span className="text-tertiary font-mono text-xs">0</span>
              )
            },
          },
          {
            header: '🛡️ Vulnerabilities',
            cell: (i) => {
              const count = i.issues?.byType['vulnerability']?.value
              return count && count > 0 ? (
                <span className="inline-flex items-center gap-1 rounded bg-error-primary/10 text-error-primary px-1.5 py-0.5 font-mono font-bold text-xs border border-error-primary/25">
                  {count}
                </span>
              ) : (
                <span className="text-tertiary font-mono text-xs">0</span>
              )
            },
          },
          {
            header: '🔧 Code Smells',
            cell: (i) => {
              const count = i.issues?.byType['code_smell']?.value
              return count && count > 0 ? (
                <span className="inline-flex items-center gap-1 rounded bg-utility-blue-500/10 text-utility-blue-600 dark:text-utility-blue-400 px-1.5 py-0.5 font-mono font-bold text-xs border border-utility-blue-500/25">
                  {count}
                </span>
              ) : (
                <span className="text-tertiary font-mono text-xs">0</span>
              )
            },
          },
          {
            header: '🔥 Hotspots',
            cell: (i) => {
              const count = i.issues?.byType['security_hotspot']?.value
              return count && count > 0 ? (
                <span className="inline-flex items-center gap-1 rounded bg-warning-primary/10 text-warning-primary px-1.5 py-0.5 font-mono font-bold text-xs border border-warning-primary/25">
                  {count}
                </span>
              ) : (
                <span className="text-tertiary font-mono text-xs">0</span>
              )
            },
          },
        ]
      case 'debt':
        return [
          ...base,
          {
            header: 'Remediation Effort',
            cell: (i) => {
              const mins = i.debt?.remediationEffortMinutes?.value
              if (mins == null) return <MetricValue m={i.debt?.remediationEffortMinutes} />
              const hrs = Math.floor(mins / 60)
              const remMins = mins % 60
              return (
                <span className="font-mono text-xs font-semibold text-primary">
                  {hrs > 0 ? `${hrs}h ` : ''}{remMins}m
                </span>
              )
            },
          },
        ]
      case 'ratings':
        return [
          ...base,
          {
            header: 'Security',
            cell: (i) => <MetricValue m={i.ratings?.security} />,
          },
          {
            header: 'Reliability',
            cell: (i) => <MetricValue m={i.ratings?.reliability} />,
          },
          {
            header: 'Maintainability',
            cell: (i) => <MetricValue m={i.ratings?.maintainability} />,
          },
        ]
      default:
        return base
    }
  }
}

export function CurrentNodeMeasures({
  node,
  domain,
}: {
  node: MeasureNode
  domain: string
}) {
  const items: {
    label: string
    icon: typeof File01
    m: MeasureCountMetric | MeasureDecimalMetric | MeasureGradeMetric | undefined
    suffix?: string
    showProgress?: boolean
  }[] = []

  if (domain === 'size') {
    items.push(
      { label: 'Files', icon: File01, m: node.size?.files },
      { label: 'Lines of Code', icon: FileCode01, m: node.size?.ncloc },
      { label: 'Functions', icon: CpuChip01, m: node.size?.functions },
      { label: 'Comment Lines', icon: Tool01, m: node.size?.commentLines },
      { label: 'Blank Lines', icon: File01, m: node.size?.blankLines },
      { label: 'Comment Density', icon: Percent01, m: node.size?.commentDensity, suffix: '%', showProgress: true },
    )
  } else if (domain === 'complexity') {
    items.push(
      { label: 'Cyclomatic Complexity', icon: CpuChip01, m: node.complexity?.cyclomatic },
      { label: 'Cognitive Complexity', icon: CpuChip01, m: node.complexity?.cognitive },
    )
  } else if (domain === 'coverage') {
    items.push(
      { label: 'Overall Coverage', icon: ShieldTick, m: node.coverage?.coverage, suffix: '%', showProgress: true },
      { label: 'New Code Coverage', icon: ShieldTick, m: node.coverage?.newCodeCoverage, suffix: '%', showProgress: true },
      { label: 'Covered Lines', icon: FileCode01, m: node.coverage?.coveredLines },
      { label: 'Coverable Lines', icon: FileCode01, m: node.coverage?.coverableLines },
    )
  } else if (domain === 'duplication') {
    items.push(
      { label: 'Duplication Density', icon: Percent01, m: node.duplication?.duplicationDensity, suffix: '%', showProgress: true },
      { label: 'Duplicated Lines', icon: FileCode01, m: node.duplication?.duplicatedLines },
      { label: 'Duplicated Blocks', icon: File01, m: node.duplication?.duplicationBlocks },
    )
  } else if (domain === 'issues') {
    items.push(
      { label: 'Bugs', icon: Virus, m: node.issues?.byType['bug'] },
      { label: 'Vulnerabilities', icon: ShieldTick, m: node.issues?.byType['vulnerability'] },
      { label: 'Code Smells', icon: Tool01, m: node.issues?.byType['code_smell'] },
      { label: 'Security Hotspots', icon: Zap, m: node.issues?.byType['security_hotspot'] },
      { label: 'Critical Issues', icon: Virus, m: node.issues?.bySeverity['critical'] },
      { label: 'High Issues', icon: Virus, m: node.issues?.bySeverity['high'] },
    )
  } else if (domain === 'debt') {
    items.push(
      { label: 'Remediation Effort (mins)', icon: Clock, m: node.debt?.remediationEffortMinutes },
    )
  } else if (domain === 'ratings') {
    items.push(
      { label: 'Security Rating', icon: Star01, m: node.ratings?.security },
      { label: 'Reliability Rating', icon: Star01, m: node.ratings?.reliability },
      { label: 'Maintainability Rating', icon: Star01, m: node.ratings?.maintainability },
    )
  }

  return (
    <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
      <div className="flex items-center justify-between gap-3 mb-3.5">
        <h3 className="text-xs font-bold uppercase tracking-wider text-tertiary">
          Current Node Metrics ({node.name})
        </h3>
        <span className="text-[11px] font-mono text-tertiary">
          Type: <strong className="capitalize text-primary">{node.kind}</strong>
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {items.map((item) => {
          const Icon = item.icon
          return (
            <div
              key={item.label}
              className="flex flex-col justify-between rounded-lg border border-secondary/70 bg-secondary/20 p-3 hover:bg-secondary/40 transition-colors shadow-2xs"
            >
              <div className="flex items-center justify-between gap-1.5 text-tertiary mb-2">
                <span className="text-[11px] font-medium leading-tight truncate" title={item.label}>
                  {item.label}
                </span>
                <Icon className="size-3.5 shrink-0 text-brand-secondary" aria-hidden="true" />
              </div>
              <div className="text-base font-bold tabular-nums text-primary">
                <MetricValue m={item.m} suffix={item.suffix} showProgressBar={item.showProgress} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
