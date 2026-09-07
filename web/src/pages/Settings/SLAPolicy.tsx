import { useMemo, useState } from 'react'
import { AlertTriangle, CheckCircle, Scales02, Save01 } from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Field, InfoNote, Input, Pill, Spinner, cn } from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { SLAConfig, SLADueTier, SLAPoliciesView, SLAPolicy } from '../../lib/api'

const DUE_TIERS: SLADueTier[] = ['emergency', 'critical', 'high', 'medium', 'low', 'exception']

// Mirrors sla.DefaultConfig() in internal/domain/sla/config.go, the reproducible floor when no policy is
// active. Used to seed the editor so an admin starts from the shipped defaults, not an empty form.
const DEFAULT_CONFIG: SLAConfig = {
  version: 'sla-v1',
  weights: { severity: 35, exploitability: 25, threatIntel: 10, exposure: 15, criticality: 15, feasibilityRelief: 15 },
  thresholds: { emergency: 85, critical: 70, high: 50, medium: 30 },
  dueRanges: {
    emergency: { mitigateDays: 1, remediateDays: 7 },
    critical: { mitigateDays: 3, remediateDays: 15 },
    high: { mitigateDays: 7, remediateDays: 30 },
    medium: { mitigateDays: 30, remediateDays: 90 },
    low: { mitigateDays: 90, remediateDays: 180 },
    exception: { mitigateDays: 30, remediateDays: 180 },
  },
}

const WEIGHT_FIELDS: { key: keyof SLAConfig['weights']; label: string }[] = [
  { key: 'severity', label: 'Severity' },
  { key: 'exploitability', label: 'Exploitability' },
  { key: 'threatIntel', label: 'Threat intel' },
  { key: 'exposure', label: 'Exposure' },
  { key: 'criticality', label: 'Criticality' },
  { key: 'feasibilityRelief', label: 'Feasibility relief' },
]

const THRESHOLD_FIELDS: { key: keyof SLAConfig['thresholds']; label: string }[] = [
  { key: 'emergency', label: 'Emergency' },
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
]

function validateConfig(c: SLAConfig): string | null {
  if (!c.version.trim()) return 'A version label is required.'
  for (const f of WEIGHT_FIELDS) if (c.weights[f.key] < 0) return `${f.label} weight cannot be negative.`
  const t = c.thresholds
  if (!(t.emergency > t.critical && t.critical > t.high && t.high > t.medium && t.medium > 0))
    return 'Thresholds must be strictly descending and positive: emergency > critical > high > medium > 0.'
  for (const tier of DUE_TIERS) {
    const r = c.dueRanges[tier]
    if (r.mitigateDays < 0 || r.remediateDays < 0) return `${tier} due range cannot be negative.`
    if (r.mitigateDays > r.remediateDays) return `${tier}: mitigate window must be ≤ remediate window.`
  }
  return null
}

function shortHash(h: string): string {
  return h ? `${h.slice(0, 10)}…` : '—'
}

function formatWhen(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function ActivePolicyCard({ policy }: { policy: SLAPolicy }) {
  const c = policy.config
  const positiveSum = WEIGHT_FIELDS.filter((f) => f.key !== 'feasibilityRelief').reduce((n, f) => n + c.weights[f.key], 0)
  return (
    <Card title="Active policy" titleClassName="flex items-center gap-2" actions={<Pill className="font-mono text-brand-secondary">{c.version}</Pill>}>
      <dl className="mb-5 grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
        <div>
          <dt className="text-xs text-tertiary">Digest</dt>
          <dd className="font-mono text-primary" title={policy.sha256}>{shortHash(policy.sha256)}</dd>
        </div>
        <div>
          <dt className="text-xs text-tertiary">Activated by</dt>
          <dd className="text-primary">{policy.createdBy || '—'}</dd>
        </div>
        <div>
          <dt className="text-xs text-tertiary">Activated at</dt>
          <dd className="text-primary">{formatWhen(policy.createdAt)}</dd>
        </div>
        <div>
          <dt className="text-xs text-tertiary">Positive weight sum</dt>
          <dd className={cn('font-semibold tabular-nums', positiveSum === 100 ? 'text-success-primary' : 'text-warning-primary')}>{positiveSum}</dd>
        </div>
      </dl>

      <div className="grid gap-5 lg:grid-cols-2">
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-tertiary">Factor weights (max points)</h3>
          <ul className="space-y-1.5">
            {WEIGHT_FIELDS.map((f) => {
              const v = c.weights[f.key]
              return (
                <li key={f.key} className="flex items-center gap-3">
                  <span className="w-32 shrink-0 text-sm text-secondary">{f.label}</span>
                  <span className="h-2 flex-1 overflow-hidden rounded-full bg-secondary">
                    <span className="block h-full rounded-full bg-brand-solid" style={{ width: `${Math.min(100, v)}%` }} />
                  </span>
                  <span className="w-8 shrink-0 text-right text-sm font-semibold tabular-nums text-primary">{v}</span>
                </li>
              )
            })}
          </ul>
        </div>
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-tertiary">Tier thresholds & due windows</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-tertiary">
                  <th className="pb-1 font-medium">Tier</th>
                  <th className="pb-1 text-right font-medium">Score ≥</th>
                  <th className="pb-1 text-right font-medium">Mitigate</th>
                  <th className="pb-1 text-right font-medium">Remediate</th>
                </tr>
              </thead>
              <tbody>
                {DUE_TIERS.map((tier) => {
                  const score =
                    tier === 'emergency' || tier === 'critical' || tier === 'high' || tier === 'medium'
                      ? c.thresholds[tier]
                      : undefined
                  const r = c.dueRanges[tier]
                  return (
                    <tr key={tier} className="border-t border-secondary">
                      <td className="py-1 capitalize text-primary">{tier}</td>
                      <td className="py-1 text-right tabular-nums text-secondary">{score ?? '—'}</td>
                      <td className="py-1 text-right tabular-nums text-secondary">{r.mitigateDays}d</td>
                      <td className="py-1 text-right tabular-nums text-secondary">{r.remediateDays}d</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Card>
  )
}

function num(v: string): number {
  const n = Number(v)
  return Number.isFinite(n) ? n : 0
}

function ActivateForm({ seed, canAdmin, onDone }: { seed: SLAConfig; canAdmin: boolean; onDone: () => void }) {
  const { notify } = useToast()
  const [config, setConfig] = useState<SLAConfig>(seed)
  const [submitting, setSubmitting] = useState(false)
  const invalid = useMemo(() => validateConfig(config), [config])
  const positiveSum = WEIGHT_FIELDS.filter((f) => f.key !== 'feasibilityRelief').reduce((n, f) => n + config.weights[f.key], 0)

  function setWeight(k: keyof SLAConfig['weights'], v: number) {
    setConfig((c) => ({ ...c, weights: { ...c.weights, [k]: v } }))
  }
  function setThreshold(k: keyof SLAConfig['thresholds'], v: number) {
    setConfig((c) => ({ ...c, thresholds: { ...c.thresholds, [k]: v } }))
  }
  function setDue(tier: SLADueTier, field: 'mitigateDays' | 'remediateDays', v: number) {
    setConfig((c) => ({ ...c, dueRanges: { ...c.dueRanges, [tier]: { ...c.dueRanges[tier], [field]: v } } }))
  }

  async function submit() {
    if (invalid || !canAdmin) return
    setSubmitting(true)
    try {
      const res = await api.activateSLAPolicy(config)
      notify(res.created ? `Activated policy ${config.version}.` : `Policy ${config.version} is already active.`, 'success')
      onDone()
    } catch (e) {
      notify(e instanceof Error ? e.message : 'Failed to activate policy.', 'error')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Card
      title="Activate a policy version"
      titleClassName="flex items-center gap-2"
      actions={
        <Button variant="primary" loading={submitting} disabled={!!invalid || !canAdmin} onClick={submit}>
          <Save01 className="size-4" aria-hidden />
          Activate
        </Button>
      }
    >
      {!canAdmin && (
        <p className="mb-4 rounded-lg border border-secondary bg-secondary/40 px-3 py-2 text-sm text-tertiary">
          Activating a policy needs the administer permission. You can review the values but not apply them.
        </p>
      )}
      <fieldset disabled={!canAdmin} className="space-y-6">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Version label" htmlFor="sla-version" hint="Recorded on every assessment scored under this policy.">
            <Input id="sla-version" value={config.version} onChange={(e) => setConfig((c) => ({ ...c, version: e.target.value }))} />
          </Field>
          <div className="flex items-end">
            <p className={cn('text-sm', positiveSum === 100 ? 'text-success-primary' : 'text-warning-primary')}>
              Positive weights sum to <span className="font-semibold tabular-nums">{positiveSum}</span> (100 recommended so a maxed finding scores 100).
            </p>
          </div>
        </div>

        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-tertiary">Factor weights</h3>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {WEIGHT_FIELDS.map((f) => (
              <Field key={f.key} label={f.label} htmlFor={`w-${f.key}`}>
                <Input id={`w-${f.key}`} type="number" min={0} value={config.weights[f.key]} onChange={(e) => setWeight(f.key, num(e.target.value))} />
              </Field>
            ))}
          </div>
        </div>

        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-tertiary">Tier thresholds (score ≥)</h3>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {THRESHOLD_FIELDS.map((f) => (
              <Field key={f.key} label={f.label} htmlFor={`t-${f.key}`}>
                <Input id={`t-${f.key}`} type="number" min={0} value={config.thresholds[f.key]} onChange={(e) => setThreshold(f.key, num(e.target.value))} />
              </Field>
            ))}
          </div>
        </div>

        <div>
          <h3 className="mb-2 inline-flex items-center gap-1 text-xs font-semibold uppercase tracking-wide text-tertiary">
            Due windows (days)
            <InfoNote label="Due windows">Windows are edited in whole or fractional days; a policy set out-of-band with sub-day precision is rounded to the day view here.</InfoNote>
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[24rem] text-sm">
              <thead>
                <tr className="text-left text-xs text-tertiary">
                  <th className="pb-1 font-medium">Tier</th>
                  <th className="pb-1 font-medium">Mitigate within</th>
                  <th className="pb-1 font-medium">Remediate within</th>
                </tr>
              </thead>
              <tbody>
                {DUE_TIERS.map((tier) => (
                  <tr key={tier} className="border-t border-secondary">
                    <td className="py-1.5 pr-3 capitalize text-primary">{tier}</td>
                    <td className="py-1.5 pr-3">
                      <Input aria-label={`${tier} mitigate days`} type="number" min={0} value={config.dueRanges[tier].mitigateDays} onChange={(e) => setDue(tier, 'mitigateDays', num(e.target.value))} />
                    </td>
                    <td className="py-1.5">
                      <Input aria-label={`${tier} remediate days`} type="number" min={0} value={config.dueRanges[tier].remediateDays} onChange={(e) => setDue(tier, 'remediateDays', num(e.target.value))} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {invalid && (
          <div className="flex items-start gap-2 rounded-lg border border-warning-primary/30 bg-warning-primary/10 px-3 py-2 text-sm text-warning-primary">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span>{invalid}</span>
          </div>
        )}
      </fieldset>
    </Card>
  )
}

export function SLAPolicy() {
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  const canAdmin = me?.role === 'admin' || me?.role === 'owner'
  const { data, loading, error, refetch } = useFetch<SLAPoliciesView | null>(() => api.slaPolicies(), { deps: [] })

  if (loading) return <Spinner label="Loading SLA policy…" />
  if (error) return <ErrorState message={error} />
  if (data === null)
    return (
      <EmptyState
        icon={Scales02}
        title="SLA governance is not enabled"
        hint="This deployment does not expose risk-based remediation SLAs. Enable the SLA use case to score findings into due-date tiers."
      />
    )

  const seed = data.active?.config ?? DEFAULT_CONFIG
  const history = data.policies.filter((p) => p.sha256 !== data.active?.sha256)

  return (
    <div className="space-y-6">
      {data.active ? (
        <ActivePolicyCard policy={data.active} />
      ) : (
        <div className="flex items-center gap-2 rounded-xl border border-dashed border-secondary bg-secondary/20 px-4 py-3 text-sm text-tertiary">
          <CheckCircle className="size-4 text-brand-secondary" aria-hidden />
          No stored policy is active. Findings are scored against the built-in default (<span className="font-mono">{DEFAULT_CONFIG.version}</span>) until you activate one.
        </div>
      )}

      <ActivateForm seed={seed} canAdmin={canAdmin} onDone={refetch} />

      {history.length > 0 && (
        <Card title="Previous versions">
          <ul className="divide-y divide-secondary">
            {history.map((p) => (
              <li key={p.sha256} className="flex flex-wrap items-center gap-x-4 gap-y-1 py-2 text-sm">
                <Pill className="font-mono text-secondary">{p.config.version}</Pill>
                <span className="font-mono text-xs text-quaternary" title={p.sha256}>{shortHash(p.sha256)}</span>
                <span className="text-tertiary">by {p.createdBy || '—'}</span>
                <span className="ml-auto text-xs text-quaternary">{formatWhen(p.createdAt)}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  )
}

export default SLAPolicy
