import { useState } from 'react'
import { Activity, AlertTriangle, BarChart01, Coins01, RefreshCw01 } from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Spinner, cn } from '../../components/ui'
import { api } from '../../lib/api'
import type { AITriageMetricRow, AITriageObservability as Observability } from '../../lib/types'
import { useFetch } from '../../hooks'

export function AITriageObservability() {
  const [revision, setRevision] = useState(0)
  const { data, loading, error } = useFetch<Observability>(
    () => api.aiTriageObservability(),
    { deps: [revision] },
  )

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">
            Automation Observability
          </h1>
        </div>
        <Button
          variant="secondary"
          onClick={() => setRevision((v) => v + 1)}
        >
          <RefreshCw01 className="size-4" />Refresh
        </Button>
      </header>
      {error ? <ErrorState message={error} /> : loading || data === null ? <Spinner label="Loading AI triage metrics…" /> : <Dashboard data={data} />}
    </div>
  )
}

function Dashboard({ data }: { data: Observability }) {
  if (data.totals.requestCount === 0 && data.totals.findings === 0) {
    return <EmptyState icon={Activity} title="No AI triage telemetry yet" hint="Metrics appear after an AI-triaged scan completes." />
  }
  const disagreementRate = rate(data.totals.disagreements, data.totals.comparisons)
  const exemptionRate = rate(data.totals.gateExemptions, data.totals.findings)

  return (
    <div className="space-y-6">
      {/* Alert banner (inline, no card) */}
      {data.alerts.length > 0 && (
        <div className="flex items-start gap-2 rounded-lg border border-utility-orange-200 bg-utility-orange-50 px-4 py-2.5 dark:border-utility-orange-800 dark:bg-utility-orange-950">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-utility-orange-600 dark:text-utility-orange-400" />
          <div className="space-y-1">
            {data.alerts.map((item, i) => (
              <p key={i} className="text-sm text-primary">
                <span className="font-medium">{item.projectName || item.projectId}</span>
                <span className="text-tertiary"> — </span>
                <span className="text-tertiary">{item.alert.message}</span>
              </p>
            ))}
          </div>
        </div>
      )}

      {/* Stat cards row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4">
        <Metric
          icon={Activity}
          label="Provider requests"
          value={data.totals.requestCount.toLocaleString()}
          iconColor="text-fg-brand-primary"
        />
        <Metric
          icon={BarChart01}
          label="Disagreement rate"
          value={disagreementRate}
          iconColor="text-utility-blue-600 dark:text-utility-blue-400"
        />
        <Metric
          icon={AlertTriangle}
          label="Gate exemption rate"
          value={exemptionRate}
          iconColor="text-utility-orange-600 dark:text-utility-orange-400"
        />
        <Metric
          icon={Coins01}
          label="Estimated cost"
          value={formatCost(data.totals.estimatedCostMicroUSD)}
          iconColor="text-utility-green-600 dark:text-utility-green-400"
        />
      </div>

      {/* Distribution with donut charts */}
      <Card title="Drift input distribution">
        <div className="flex flex-col items-start gap-8 sm:flex-row sm:justify-around overflow-hidden pt-2">
          <DistributionDonut title="Language" values={data.distribution.languageBasisPoints} />
          <DistributionDonut title="CWE" values={data.distribution.cweBasisPoints} />
          <DistributionDonut title="Project" values={data.distribution.projectBasisPoints} />
        </div>
      </Card>

      {/* Model + Prompt merged (2-col with CWE on desktop) */}
      <div className="grid gap-5 xl:grid-cols-2 [&>*]:min-w-0">
        <ModelAndPromptSection models={data.byModel} prompts={data.byPromptVersion} />
        <CWESection rows={data.byCWE} />
      </div>

      {/* Project (full width) */}
      <ProjectSection rows={data.byProject} />
    </div>
  )
}

function Metric({
  icon: Icon,
  label,
  value,
  iconColor,
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  value: string
  iconColor?: string
}) {
  return (
    <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <span className="block truncate text-sm font-semibold text-secondary">{label}</span>
          <div className="mt-2 font-mono text-3xl font-bold tabular-nums text-primary sm:text-4xl">
            {value}
          </div>
        </div>
        <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary shadow-2xs">
          <Icon className={cn('size-5', iconColor ?? 'text-fg-brand-primary')} aria-hidden="true" />
        </span>
      </div>
    </div>
  )
}

function DistributionDonut({ title, values }: { title: string; values: Record<string, number> }) {
  const rows = Object.entries(values)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 6)
  const total = rows.reduce((a, [, v]) => a + v, 0) || 1

  // SVG donut params
  const size = 140
  const strokeWidth = 24
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius

  // Color palette — a descending brand-shade ramp, all driven from theme tokens.
  const colors = [
    'var(--color-brand-600)',
    'var(--color-brand-500)',
    'var(--color-brand-400)',
    'var(--color-brand-300)',
    'var(--color-brand-200)',
    'var(--color-brand-100)',
  ]

  let offset = 0

  return (
    <div className="flex flex-col items-center gap-4 flex-1 min-w-[160px] max-w-[220px]">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-tertiary">{title}</h3>
      <div className="relative">
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
          {rows.map(([label, basisPoints], i) => {
            const pct = basisPoints / total
            const dash = pct * circumference
            const gap = circumference - dash
            const currentOffset = offset
            offset += dash
            return (
              <circle
                key={label}
                cx={size / 2}
                cy={size / 2}
                r={radius}
                fill="none"
                stroke={colors[i % colors.length]}
                strokeWidth={strokeWidth}
                strokeDasharray={`${dash} ${gap}`}
                strokeDashoffset={-currentOffset}
                className="transition-all duration-500"
              />
            )
          })}
        </svg>
        {/* Center label */}
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="font-mono text-2xl font-bold text-primary tabular-nums">{rows.length}</span>
        </div>
      </div>
      {/* Legend — horizontal wrap below donut */}
      <div className="flex flex-wrap justify-center gap-x-3 gap-y-1 w-full">
        {rows.map(([label, basisPoints], i) => (
          <span key={label} className="inline-flex items-center gap-1 text-[11px] max-w-full">
            <span className="size-2 rounded-full shrink-0" style={{ backgroundColor: colors[i % colors.length] }} />
            <span className="text-primary truncate max-w-[80px]" title={label}>{label}</span>
            <span className="tabular-nums text-tertiary shrink-0">{(basisPoints / 100).toFixed(1)}%</span>
          </span>
        ))}
      </div>
    </div>
  )
}

function ModelAndPromptSection({ models, prompts }: { models: AITriageMetricRow[]; prompts: AITriageMetricRow[] }) {
  const totalModelReq = models.reduce((a, r) => a + r.requestCount, 0) || 1
  return (
    <Card title="Models & prompts">
      <div className="space-y-3">
        {models.map((row) => {
          const failures = row.timeoutCount + row.parseFailureCount + row.providerFailureCount + row.circuitOpenCount
          return (
            <div key={row.value} className="flex items-center gap-3 text-sm">
              <span className="font-mono text-xs font-medium text-primary truncate max-w-[250px]" title={row.value}>
                {row.value}
              </span>
              <div className="flex-1 h-1.5 rounded-full bg-secondary">
                <div
                  className="h-1.5 rounded-full bg-brand-solid transition-all"
                  style={{ width: `${(row.requestCount / totalModelReq) * 100}%` }}
                />
              </div>
              <span className="text-xs tabular-nums text-tertiary whitespace-nowrap">{row.requestCount} req</span>
              <span className="text-xs tabular-nums text-tertiary whitespace-nowrap">{row.totalTokens.toLocaleString()} tok</span>
              {failures > 0 && (
                <span className="text-xs tabular-nums text-critical whitespace-nowrap">
                  {failures} fail
                </span>
              )}
            </div>
          )
        })}
        {/* Prompt version inline */}
        {prompts.length > 0 && (
          <div className="border-t border-secondary pt-3 mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-tertiary">
            <span className="font-medium text-secondary">Prompt:</span>
            {prompts.map((p) => {
              const failures = p.timeoutCount + p.parseFailureCount + p.providerFailureCount + p.circuitOpenCount
              return (
                <span key={p.value} className="inline-flex items-center gap-2">
                  <span className="font-mono text-primary">{p.value}</span>
                  <span className="tabular-nums">{p.requestCount} req</span>
                  <span className="tabular-nums">{p.totalTokens.toLocaleString()} tok</span>
                  {failures > 0 && (
                    <span className="text-critical">{failures} fail</span>
                  )}
                </span>
              )
            })}
          </div>
        )}
      </div>
    </Card>
  )
}

function CWESection({ rows }: { rows: AITriageMetricRow[] }) {
  const max = rows[0]?.requestCount ?? 1
  return (
    <Card title="By CWE">
      <div className="space-y-2.5 min-w-0">
        {rows.map((row) => (
          <div key={row.value} className="min-w-0">
            <div className="flex items-center justify-between gap-2 text-xs mb-0.5">
              <span className="font-mono font-medium text-primary truncate">{row.value}</span>
              <span className="flex items-center gap-3 tabular-nums text-tertiary shrink-0">
                <span>{row.requestCount} req</span>
                {row.gateExemptions > 0 && (
                  <span className="text-utility-orange-600 dark:text-utility-orange-400">
                    {row.gateExemptions} exempt
                  </span>
                )}
              </span>
            </div>
            <div className="h-1.5 w-full rounded-full bg-secondary">
              <div
                className="h-1.5 rounded-full bg-brand-solid transition-all"
                style={{ width: `${(row.requestCount / max) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}

function ProjectSection({ rows }: { rows: AITriageMetricRow[] }) {
  const totalReq = rows.reduce((a, r) => a + r.requestCount, 0) || 1
  return (
    <Card title="By project">
      <div className="space-y-3 min-w-0">
        {rows.map((row) => {
          const failures = row.timeoutCount + row.parseFailureCount + row.providerFailureCount + row.circuitOpenCount
          return (
            <div key={row.value} className="min-w-0">
              <div className="flex items-center justify-between gap-2 text-sm mb-1">
                <span className="font-medium text-primary truncate" title={row.value}>{row.value}</span>
                <span className="flex items-center gap-3 text-xs tabular-nums text-tertiary shrink-0">
                  <span>{row.requestCount} req</span>
                  {failures > 0 && <span className="text-critical">{failures} fail</span>}
                  <span>{row.gateExemptions} exempt</span>
                </span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-secondary">
                <div
                  className="h-1.5 rounded-full bg-brand-solid transition-all"
                  style={{ width: `${(row.requestCount / totalReq) * 100}%` }}
                />
              </div>
            </div>
          )
        })}
      </div>
    </Card>
  )
}

function rate(numerator: number, denominator: number) {
  return denominator > 0 ? `${((numerator * 100) / denominator).toFixed(1)}%` : '0.0%'
}

function formatCost(microUSD: number) {
  return `$${(microUSD / 1_000_000).toFixed(4)}`
}

export default AITriageObservability
