import { useMemo, useState } from 'react'
import { CheckCircle, ShieldZap, SlashCircle01, XCircle } from '@untitledui/icons'
import { Card, EmptyState, ErrorState, Pill, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { OffensivePolicy as OffensivePolicyDTO, OffensiveTechnique } from '../../lib/api'

const RISK_TONE: Record<string, string> = {
  prohibited: 'text-error-primary bg-error-primary/10 border-error-primary/25',
  high: 'text-error-primary bg-error-primary/10 border-error-primary/25',
  medium: 'text-warning-primary bg-warning-primary/10 border-warning-primary/25',
  low: 'text-success-primary bg-success-primary/10 border-success-primary/25',
}

function riskTone(risk: string): string {
  return RISK_TONE[risk.toLowerCase()] ?? 'text-tertiary bg-secondary border-secondary'
}

function humanize(v: string): string {
  return v ? v.replace(/[_-]+/g, ' ') : '—'
}

function LegalReviewCard({ policy }: { policy: OffensivePolicyDTO }) {
  const lr = policy.legalReview
  return (
    <Card title="Legal review" titleClassName="flex items-center gap-2">
      <div className="flex flex-wrap items-center gap-3">
        <StatusPill ok={lr.reviewed} label="Policy reviewed" off="Not reviewed" />
        <StatusPill ok={lr.counselReviewed} label="Counsel signed off" off="Counsel pending" />
      </div>
      <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
        <div>
          <dt className="text-xs text-tertiary">Owner</dt>
          <dd className="text-primary">{lr.owner || '—'}</dd>
        </div>
        <div>
          <dt className="text-xs text-tertiary">Reviewed</dt>
          <dd className="text-primary">{lr.date || '—'}</dd>
        </div>
        <div>
          <dt className="text-xs text-tertiary">Counsel date</dt>
          <dd className="text-primary">{lr.counselDate || '—'}</dd>
        </div>
      </dl>
    </Card>
  )
}

function StatusPill({ ok, label, off }: { ok: boolean; label: string; off: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold',
        ok ? 'border-success-primary/25 bg-success-primary/10 text-success-primary' : 'border-warning-primary/25 bg-warning-primary/10 text-warning-primary',
      )}
    >
      {ok ? <CheckCircle className="size-3.5" aria-hidden /> : <SlashCircle01 className="size-3.5" aria-hidden />}
      {ok ? label : off}
    </span>
  )
}

function StatTile({ value, label, tone }: { value: number; label: string; tone: string }) {
  return (
    <div className="flex items-baseline gap-2 rounded-lg border border-secondary bg-primary px-3 py-2">
      <span className={cn('text-lg font-bold tabular-nums', tone)}>{value}</span>
      <span className="text-xs text-tertiary">{label}</span>
    </div>
  )
}

function TechniqueRow({ t }: { t: OffensiveTechnique }) {
  return (
    <tr className="border-t border-secondary align-top">
      <td className="py-2 pr-3">
        <div className="font-mono text-sm font-semibold text-primary">{t.technique}</div>
        {t.taxonomyRef && <div className="font-mono text-xs text-quaternary">{t.taxonomyRef}</div>}
      </td>
      <td className="py-2 pr-3">
        <span className={cn('inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-bold capitalize', riskTone(t.riskClass))}>
          {t.riskClass || '—'}
        </span>
      </td>
      <td className="py-2 pr-3 text-sm capitalize text-secondary">{humanize(t.disruption)}</td>
      <td className="py-2 pr-3 text-sm capitalize text-secondary">{humanize(t.reversibility)}</td>
      <td className="py-2 pr-3 text-sm capitalize text-secondary">{humanize(t.blastRadius)}</td>
      <td className="py-2 pr-3 text-sm capitalize text-secondary">{t.approval ? humanize(t.approval) : '—'}</td>
      <td className="py-2 text-right">
        {t.prohibited ? (
          <Pill className="text-error-primary"><XCircle className="mr-1 inline size-3.5" aria-hidden />Prohibited</Pill>
        ) : t.productionSafe ? (
          <Pill className="text-success-primary"><CheckCircle className="mr-1 inline size-3.5" aria-hidden />Prod-safe</Pill>
        ) : (
          <Pill>Lab only</Pill>
        )}
      </td>
    </tr>
  )
}

export function OffensivePolicy() {
  const { data, loading, error } = useFetch<OffensivePolicyDTO | null>(() => api.offensivePolicy(), { deps: [] })
  const [risk, setRisk] = useState('all')

  const risks = useMemo(() => {
    const set = new Set<string>()
    for (const t of data?.techniques ?? []) if (t.riskClass) set.add(t.riskClass.toLowerCase())
    return ['all', ...[...set].sort()]
  }, [data])

  const visible = useMemo(
    () => (data?.techniques ?? []).filter((t) => risk === 'all' || t.riskClass.toLowerCase() === risk),
    [data, risk],
  )

  if (loading) return <Spinner label="Loading offensive policy…" />
  if (error) return <ErrorState message={error} />
  if (data === null)
    return (
      <EmptyState
        icon={ShieldZap}
        title="Offensive policy is not enabled"
        hint="This deployment did not load an offensive technique register. The register is what the running binary enforces before any offensive step is admitted."
      />
    )

  return (
    <div className="space-y-6">
      <p className="text-sm text-tertiary">
        The technique register the running binary enforces before any offensive step runs. Read-only; it ships with the binary.
      </p>

      <LegalReviewCard policy={data} />

      <div className="flex flex-wrap gap-2">
        <StatTile value={data.techniques.length} label="classified techniques" tone="text-primary" />
        <StatTile value={data.productionSafe} label="production-safe" tone="text-success-primary" />
        <StatTile value={data.prohibited} label="prohibited" tone="text-error-primary" />
      </div>

      <Card
        title="Technique register"
        actions={
          risks.length > 2 ? (
            <div className="flex flex-wrap gap-1">
              {risks.map((r) => (
                <button
                  key={r}
                  type="button"
                  onClick={() => setRisk(r)}
                  className={cn(
                    'rounded-md px-2 py-1 text-xs font-semibold capitalize transition-colors',
                    risk === r ? 'bg-brand-primary/10 text-brand-secondary' : 'text-tertiary hover:bg-secondary hover:text-primary',
                  )}
                >
                  {r}
                </button>
              ))}
            </div>
          ) : undefined
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full min-w-[44rem] text-left">
            <thead>
              <tr className="text-xs font-medium text-tertiary">
                <th className="pb-2 pr-3">Technique</th>
                <th className="pb-2 pr-3">Risk</th>
                <th className="pb-2 pr-3">Disruption</th>
                <th className="pb-2 pr-3">Reversibility</th>
                <th className="pb-2 pr-3">Blast radius</th>
                <th className="pb-2 pr-3">Approval</th>
                <th className="pb-2 text-right">Deployment</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((t) => (
                <TechniqueRow key={t.technique} t={t} />
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

export default OffensivePolicy
