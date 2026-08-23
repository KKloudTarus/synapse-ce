import { AlertCircle, File01, Folder } from '@untitledui/icons'
import { Pill } from '../../../components/ui'
import type { Column } from '../../../components/synapse/VirtualTable'
import type { MeasureNode, MeasureCountMetric, MeasureDecimalMetric, MeasureGradeMetric } from '../../../lib/projectMeasures'

export function MetricValue({ m }: { m: MeasureCountMetric | MeasureDecimalMetric | MeasureGradeMetric | undefined }) {
  if (!m) return <span className="text-tertiary" title="Omitted">-</span>
  if (m.availability === 'not_applicable') {
    return <span className="text-quaternary" title="Not applicable">N/A</span>
  }
  if (m.availability === 'unavailable') {
    return (
      <span className="text-tertiary flex items-center gap-1" title={m.reason ?? 'Unavailable'}>
        -
        {m.reason && <AlertCircle className="size-3 text-brand-secondary" aria-hidden="true" />}
      </span>
    )
  }
  
  if ('grade' in m) {
    return <span className="font-medium font-mono">{m.grade}</span>
  }
  
  if (m.value === null) return <span className="text-tertiary">-</span>

  return <span className="tabular-nums font-mono">{m.value.toLocaleString(undefined, { maximumFractionDigits: 2 })}</span>
}

export function getDomainColumns(domain: string): (setPath: (p: string) => void) => Column<MeasureNode>[] {
  const baseColumns: (setPath: (p: string) => void) => Column<MeasureNode>[] = (setPath) => [
    {
      header: 'Name',
      className: 'w-[40%]',
      cell: (item) => {
        const navigable = item.kind === 'directory' || item.kind === 'file'
        return (
          <div className="flex items-center gap-2">
            {item.kind === 'directory' ? <Folder className="size-4 text-brand-secondary shrink-0" aria-hidden="true" /> : <File01 className="size-4 text-tertiary shrink-0" aria-hidden="true" />}
            {navigable ? (
              <button
                onClick={() => setPath(item.path)}
                className="rounded-sm font-medium hover:underline hover:text-brand-secondary text-left truncate focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                title={item.name}
              >
                {item.name}
              </button>
            ) : (
              <span className="font-medium truncate" title={item.name}>{item.name}</span>
            )}
          </div>
        )
      }
    },
    {
      header: 'Kind',
      className: 'w-[15%]',
      cell: (item) => <span className="capitalize">{item.kind}</span>
    },
    {
      header: 'Language',
      className: 'w-[15%]',
      cell: (item) => item.language ? <Pill>{item.language}</Pill> : null
    },
  ]

  return (setPath) => {
    const base = baseColumns(setPath)
    switch (domain) {
      case 'size':
        return [
          ...base,
          { header: 'Files', cell: (i) => <MetricValue m={i.size?.files} /> },
          { header: 'Code Lines', cell: (i) => <MetricValue m={i.size?.ncloc} /> },
          { header: 'Functions', cell: (i) => <MetricValue m={i.size?.functions} /> },
        ]
      case 'complexity':
        return [
          ...base,
          { header: 'Cyclomatic', cell: (i) => <MetricValue m={i.complexity?.cyclomatic} /> },
          { header: 'Cognitive', cell: (i) => <MetricValue m={i.complexity?.cognitive} /> },
        ]
      case 'coverage':
        return [
          ...base,
          { header: 'Coverage %', cell: (i) => <MetricValue m={i.coverage?.coverage} /> },
          { header: 'New Code %', cell: (i) => <MetricValue m={i.coverage?.newCodeCoverage} /> },
          { header: 'Covered Lines', cell: (i) => <MetricValue m={i.coverage?.coveredLines} /> },
        ]
      case 'duplication':
        return [
          ...base,
          { header: 'Duplication %', cell: (i) => <MetricValue m={i.duplication?.duplicationDensity} /> },
          { header: 'Duplicated Lines', cell: (i) => <MetricValue m={i.duplication?.duplicatedLines} /> },
          { header: 'Blocks', cell: (i) => <MetricValue m={i.duplication?.duplicationBlocks} /> },
        ]
      case 'issues':
        return [
          ...base,
          { header: 'Bugs', cell: (i) => <MetricValue m={i.issues?.byType['bug']} /> },
          { header: 'Vulnerabilities', cell: (i) => <MetricValue m={i.issues?.byType['vulnerability']} /> },
          { header: 'Code Smells', cell: (i) => <MetricValue m={i.issues?.byType['code_smell']} /> },
          { header: 'Hotspots', cell: (i) => <MetricValue m={i.issues?.byType['security_hotspot']} /> },
        ]
      case 'debt':
        return [
          ...base,
          { header: 'Remediation Effort', cell: (i) => <MetricValue m={i.debt?.remediationEffortMinutes} /> },
        ]
      case 'ratings':
        return [
          ...base,
          { header: 'Security', cell: (i) => <MetricValue m={i.ratings?.security} /> },
          { header: 'Reliability', cell: (i) => <MetricValue m={i.ratings?.reliability} /> },
          { header: 'Maintainability', cell: (i) => <MetricValue m={i.ratings?.maintainability} /> },
        ]
      default:
        return base
    }
  }
}

export function CurrentNodeMeasures({ node, domain }: { node: MeasureNode, domain: string }) {
  const metrics: { label: string, m: MeasureCountMetric | MeasureDecimalMetric | MeasureGradeMetric | undefined }[] = []
  
  if (domain === 'size') {
    metrics.push(
      { label: 'Files', m: node.size?.files },
      { label: 'Lines of Code', m: node.size?.ncloc },
      { label: 'Functions', m: node.size?.functions },
      { label: 'Comment Lines', m: node.size?.commentLines },
      { label: 'Blank Lines', m: node.size?.blankLines },
      { label: 'Comment Density', m: node.size?.commentDensity }
    )
  } else if (domain === 'complexity') {
    metrics.push(
      { label: 'Cyclomatic', m: node.complexity?.cyclomatic },
      { label: 'Cognitive', m: node.complexity?.cognitive }
    )
  } else if (domain === 'coverage') {
    metrics.push(
      { label: 'Coverage', m: node.coverage?.coverage },
      { label: 'New Code Coverage', m: node.coverage?.newCodeCoverage },
      { label: 'Covered Lines', m: node.coverage?.coveredLines },
      { label: 'Coverable Lines', m: node.coverage?.coverableLines }
    )
  } else if (domain === 'duplication') {
    metrics.push(
      { label: 'Duplication Density', m: node.duplication?.duplicationDensity },
      { label: 'Duplicated Lines', m: node.duplication?.duplicatedLines },
      { label: 'Duplication Blocks', m: node.duplication?.duplicationBlocks }
    )
  } else if (domain === 'issues') {
    metrics.push(
      { label: 'Bugs', m: node.issues?.byType['bug'] },
      { label: 'Vulnerabilities', m: node.issues?.byType['vulnerability'] },
      { label: 'Code Smells', m: node.issues?.byType['code_smell'] },
      { label: 'Security Hotspots', m: node.issues?.byType['security_hotspot'] },
      { label: 'Critical', m: node.issues?.bySeverity['critical'] },
      { label: 'High', m: node.issues?.bySeverity['high'] },
      { label: 'Medium', m: node.issues?.bySeverity['medium'] },
      { label: 'Low', m: node.issues?.bySeverity['low'] },
      { label: 'Info', m: node.issues?.bySeverity['info'] }
    )
  } else if (domain === 'debt') {
    metrics.push(
      { label: 'Remediation Effort (mins)', m: node.debt?.remediationEffortMinutes }
    )
  } else if (domain === 'ratings') {
    metrics.push(
      { label: 'Security', m: node.ratings?.security },
      { label: 'Reliability', m: node.ratings?.reliability },
      { label: 'Maintainability', m: node.ratings?.maintainability }
    )
  }

  return (
    <div className="bg-primary border border-secondary rounded-xl p-4 shadow-xs">
      <h3 className="text-sm font-semibold mb-3 text-primary">Current Node Metrics</h3>
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-4">
        {metrics.map((item) => (
          <div key={item.label} className="flex flex-col gap-1">
            <span className="text-xs font-medium text-tertiary">{item.label}</span>
            <div className="text-lg font-bold tabular-nums text-primary"><MetricValue m={item.m} /></div>
          </div>
        ))}
      </div>
    </div>
  )
}
