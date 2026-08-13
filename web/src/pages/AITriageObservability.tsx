import { useEffect, useState } from 'react'
import { Activity, AlertTriangle, Coins, Gauge, RefreshCw } from 'lucide-react'
import { Button, Card, EmptyState, ErrorState, Spinner } from '../components/ui'
import { api, ApiError } from '../lib/api'
import type { AITriageMetricRow, AITriageObservability as Observability } from '../lib/types'

export function AITriageObservability() {
  const [data, setData] = useState<Observability | null>(null)
  const [error, setError] = useState('')
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    let active = true
    setData(null); setError('')
    api.aiTriageObservability()
      .then((value) => { if (active) setData(value) })
      .catch((e) => { if (active) setError(e instanceof ApiError ? e.message : 'Failed to load AI triage observability') })
    return () => { active = false }
  }, [refresh])

  return <div className="space-y-5">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h1 className="text-3xl font-bold tracking-tight">AI triage observability</h1><p className="mt-1 text-sm text-mutedfg">Evidence-sealed safety, reliability, token and cost signals from each project's latest scan.</p></div>
      <Button variant="secondary" onClick={() => setRefresh((value) => value + 1)}><RefreshCw className="size-4" />Refresh</Button>
    </div>
    {error ? <ErrorState message={error} /> : data === null ? <Spinner label="Loading AI triage metrics…" /> : <Dashboard data={data} />}
  </div>
}

function Dashboard({ data }: { data: Observability }) {
  if (data.totals.requestCount === 0 && data.totals.findings === 0) return <EmptyState icon={Activity} title="No AI triage telemetry yet" hint="Metrics appear after an AI-triaged scan completes." />
  const disagreementRate = rate(data.totals.disagreements, data.totals.comparisons)
  const exemptionRate = rate(data.totals.gateExemptions, data.totals.findings)
  return <>
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <Metric icon={Activity} label="Provider requests" value={data.totals.requestCount.toLocaleString()} hint={`${data.totals.averageLatencyMillis.toLocaleString()} ms average`} />
      <Metric icon={Gauge} label="Disagreement rate" value={disagreementRate} hint={`${data.totals.comparisons} verified comparisons`} />
      <Metric icon={AlertTriangle} label="Gate exemption rate" value={exemptionRate} hint={`${data.totals.gateExemptions} retained findings exempted`} />
      <Metric icon={Coins} label="Estimated cost" value={formatCost(data.totals.estimatedCostMicroUSD)} hint={`${data.totals.totalTokens.toLocaleString()} tokens`} />
    </div>
    {data.alerts.length > 0 && <Card title="Safety alerts"><ul className="divide-y divide-border">{data.alerts.map((item, index) => <li className="px-6 py-4" key={`${item.projectId}-${item.alert.metric}-${index}`}><div className="flex gap-3"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-high" /><div><div className="text-sm font-medium">{item.projectName || item.projectId}</div><p className="mt-1 text-sm text-mutedfg">{item.alert.message}</p></div></div></li>)}</ul></Card>}
    <Card title="Drift input distribution" bodyClass="p-0">
      <div className="border-b border-border px-6 py-3 text-xs text-mutedfg">Normalized from {data.distribution.sampleSize.toLocaleString()} AI-triaged findings; export this snapshot for deterministic drift checks.</div>
      <div className="grid divide-y divide-border lg:grid-cols-3 lg:divide-x lg:divide-y-0">
        <DistributionList title="Language" values={data.distribution.languageBasisPoints} />
        <DistributionList title="CWE" values={data.distribution.cweBasisPoints} />
        <DistributionList title="Project" values={data.distribution.projectBasisPoints} />
      </div>
    </Card>
    <MetricTable title="By model" rows={data.byModel} />
    <div className="grid gap-5 xl:grid-cols-2"><MetricTable title="By prompt version" rows={data.byPromptVersion} /><MetricTable title="By CWE" rows={data.byCWE} /></div>
    <MetricTable title="By project" rows={data.byProject} />
  </>
}

function Metric({ icon: Icon, label, value, hint }: { icon: typeof Activity; label: string; value: string; hint: string }) {
  return <Card bodyClass="p-5"><div className="flex items-start justify-between"><div><div className="text-xs font-medium uppercase tracking-wide text-mutedfg">{label}</div><div className="mt-2 text-2xl font-bold tabular-nums">{value}</div><div className="mt-1 text-xs text-mutedfg">{hint}</div></div><Icon className="size-5 text-brand" /></div></Card>
}

function MetricTable({ title, rows }: { title: string; rows: AITriageMetricRow[] }) {
  return <Card title={title} bodyClass="p-0"><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="border-b border-border bg-elevated/40 text-xs uppercase tracking-wide text-mutedfg"><tr><th className="px-5 py-3">Dimension</th><th className="px-3 py-3 text-right">Requests</th><th className="px-3 py-3 text-right">Latency</th><th className="px-3 py-3 text-right">Failures</th><th className="px-3 py-3 text-right">Tokens</th><th className="px-3 py-3 text-right">Cost</th><th className="px-5 py-3 text-right">Exemptions</th></tr></thead><tbody className="divide-y divide-border">{rows.map((row) => <tr key={row.value}><td className="max-w-xs truncate px-5 py-3 font-medium" title={row.value}>{row.value}</td><td className="px-3 py-3 text-right tabular-nums">{row.requestCount}</td><td className="px-3 py-3 text-right tabular-nums">{row.averageLatencyMillis} ms</td><td className="px-3 py-3 text-right tabular-nums">{row.timeoutCount + row.parseFailureCount + row.providerFailureCount + row.circuitOpenCount}</td><td className="px-3 py-3 text-right tabular-nums">{row.totalTokens.toLocaleString()}</td><td className="px-3 py-3 text-right tabular-nums">{formatCost(row.estimatedCostMicroUSD)}</td><td className="px-5 py-3 text-right tabular-nums">{row.gateExemptions}</td></tr>)}</tbody></table></div></Card>
}

function DistributionList({ title, values }: { title: string; values: Record<string, number> }) {
  const rows = Object.entries(values).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 8)
  return <section className="p-5"><h3 className="text-xs font-semibold uppercase tracking-wide text-mutedfg">{title}</h3><ul className="mt-3 space-y-2">{rows.map(([value, basisPoints]) => <li className="flex items-center justify-between gap-3 text-sm" key={value}><span className="truncate font-medium" title={value}>{value}</span><span className="tabular-nums text-mutedfg">{(basisPoints / 100).toFixed(2)}%</span></li>)}</ul></section>
}

function rate(numerator: number, denominator: number) { return denominator > 0 ? `${(numerator * 100 / denominator).toFixed(1)}%` : '—' }
function formatCost(microUSD: number) { return `$${(microUSD / 1_000_000).toFixed(4)}` }
