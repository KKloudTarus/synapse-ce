import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, CheckCircle, Save01, Shield01 } from '@untitledui/icons'
import { Button, Card, ErrorState, Pill, Spinner, cn } from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { useFetch } from '../../hooks'
import { api, SLA_TIERS } from '../../lib/api'
import type { SlaConfig, SlaPolicy, SlaTier } from '../../lib/api'

const WEIGHT_FIELDS: { key: keyof SlaConfig['weights']; label: string }[] = [
  { key: 'severity', label: 'Severity' },
  { key: 'exploitability', label: 'Exploitability' },
  { key: 'threatIntel', label: 'Threat intel' },
  { key: 'exposure', label: 'Exposure' },
  { key: 'criticality', label: 'Asset criticality' },
]

const THRESHOLD_FIELDS: { key: keyof SlaConfig['thresholds']; label: string }[] = [
  { key: 'emergency', label: 'Emergency' },
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
]

const TIER_LABEL: Record<SlaTier, string> = {
  emergency: 'Emergency',
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  exception: 'Exception',
}

function shortDigest(sha: string): string {
  return sha ? sha.slice(0, 12) : '—'
}

function formatWhen(iso: string | null): string {
  if (!iso) return 'unknown'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function NumberInput({
  value,
  onChange,
  ariaLabel,
  min = 0,
  step = 1,
  suffix,
}: {
  value: number
  onChange: (n: number) => void
  ariaLabel: string
  min?: number
  step?: number
  suffix?: string
}) {
  return (
    <div className="flex items-center gap-1.5">
      <input
        type="number"
        inputMode="decimal"
        value={Number.isFinite(value) ? value : 0}
        min={min}
        step={step}
        aria-label={ariaLabel}
        onChange={(e) => onChange(e.target.value === '' ? 0 : Number(e.target.value))}
        className="input-inset w-20 rounded-lg border border-secondary bg-secondary px-2.5 py-1.5 text-right text-sm tabular-nums text-primary outline-none transition-colors focus:border-brand focus:ring-2 focus:ring-brand/40"
      />
      {suffix && <span className="text-xs text-tertiary">{suffix}</span>}
    </div>
  )
}

function WeightsEditor({ cfg, set }: { cfg: SlaConfig; set: (c: SlaConfig) => void }) {
  const sum = WEIGHT_FIELDS.reduce((acc, f) => acc + (cfg.weights[f.key] || 0), 0)
  const balanced = Math.round(sum) === 100
  return (
    <Card
      title="Scoring weights"
      titleClassName="flex items-center gap-2"
      actions={
        <Pill
          className={cn(
            'tabular-nums',
            balanced ? 'bg-success-primary/10 text-success-primary ring-1 ring-inset ring-success-primary/25' : 'bg-warning-primary/10 text-warning-primary ring-1 ring-inset ring-warning-primary/25',
          )}
        >
          {balanced ? <CheckCircle className="mr-1 inline size-3.5" /> : <AlertTriangle className="mr-1 inline size-3.5" />}
          sums to {Math.round(sum)}
        </Pill>
      }
    >
      <p className="text-xs text-tertiary">
        Each factor's maximum point contribution. The five scoring factors sum to 100, so a maxed finding
        scores 100 before feasibility relief.
      </p>
      <div className="mt-4 space-y-2.5">
        {WEIGHT_FIELDS.map((f) => {
          const v = cfg.weights[f.key] || 0
          return (
            <div key={f.key} className="flex items-center gap-3">
              <span className="w-36 shrink-0 text-sm text-secondary">{f.label}</span>
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-secondary">
                <div className="h-full rounded-full bg-brand-solid" style={{ width: `${Math.min(100, v)}%` }} />
              </div>
              <NumberInput
                value={v}
                ariaLabel={`Weight ${f.label}`}
                onChange={(n) => set({ ...cfg, weights: { ...cfg.weights, [f.key]: n } })}
              />
            </div>
          )
        })}
        <div className="flex items-center gap-3 border-t border-secondary pt-2.5">
          <span className="w-36 shrink-0 text-sm text-tertiary">Feasibility relief</span>
          <span className="flex-1 text-xs text-quaternary">Maximum urgency reduction for a hard-to-fix finding</span>
          <NumberInput
            value={cfg.weights.feasibilityRelief || 0}
            ariaLabel="Weight feasibility relief"
            onChange={(n) => set({ ...cfg, weights: { ...cfg.weights, feasibilityRelief: n } })}
          />
        </div>
      </div>
    </Card>
  )
}

function ThresholdsEditor({ cfg, set }: { cfg: SlaConfig; set: (c: SlaConfig) => void }) {
  const t = cfg.thresholds
  const descending = t.emergency >= t.critical && t.critical >= t.high && t.high >= t.medium
  return (
    <Card
      title="Tier thresholds"
      titleClassName="flex items-center gap-2"
      actions={
        !descending ? (
          <Pill className="bg-error-primary/10 text-error-primary ring-1 ring-inset ring-error-primary/25">
            <AlertTriangle className="mr-1 inline size-3.5" /> must descend
          </Pill>
        ) : undefined
      }
    >
      <p className="text-xs text-tertiary">
        Inclusive lower score bound for each tier, strictly descending. A score below Medium is Low.
      </p>
      <div className="mt-4 space-y-2">
        {THRESHOLD_FIELDS.map((f) => (
          <div key={f.key} className="flex items-center gap-3">
            <span className="w-28 shrink-0 text-sm text-secondary">{f.label}</span>
            <span className="flex-1 text-xs text-quaternary">score &ge;</span>
            <NumberInput
              value={t[f.key] || 0}
              ariaLabel={`Threshold ${f.label}`}
              onChange={(n) => set({ ...cfg, thresholds: { ...t, [f.key]: n } })}
            />
          </div>
        ))}
      </div>
    </Card>
  )
}

function DueRangesEditor({ cfg, set }: { cfg: SlaConfig; set: (c: SlaConfig) => void }) {
  return (
    <Card title="Due ranges">
      <p className="text-xs text-tertiary">
        How long each tier has to mitigate (a compensating step) and to fully remediate, in days.
      </p>
      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[420px] text-sm">
          <thead>
            <tr className="text-left text-[11px] uppercase tracking-wider text-tertiary">
              <th className="pb-2 font-semibold">Tier</th>
              <th className="pb-2 text-right font-semibold">Mitigate (days)</th>
              <th className="pb-2 text-right font-semibold">Remediate (days)</th>
            </tr>
          </thead>
          <tbody>
            {SLA_TIERS.map((tier) => {
              const dr = cfg.dueRanges[tier]
              const bad = dr.mitigateDays > dr.remediateDays
              return (
                <tr key={tier} className="border-t border-secondary">
                  <td className="py-2 text-secondary">{TIER_LABEL[tier]}</td>
                  <td className="py-2">
                    <div className="flex justify-end">
                      <NumberInput
                        value={dr.mitigateDays}
                        step={0.5}
                        ariaLabel={`${TIER_LABEL[tier]} mitigate days`}
                        onChange={(n) => set({ ...cfg, dueRanges: { ...cfg.dueRanges, [tier]: { ...dr, mitigateDays: n } } })}
                      />
                    </div>
                  </td>
                  <td className="py-2">
                    <div className="flex items-center justify-end gap-2">
                      {bad && <AlertTriangle className="size-3.5 text-error-primary" aria-label="mitigate exceeds remediate" />}
                      <NumberInput
                        value={dr.remediateDays}
                        step={0.5}
                        ariaLabel={`${TIER_LABEL[tier]} remediate days`}
                        onChange={(n) => set({ ...cfg, dueRanges: { ...cfg.dueRanges, [tier]: { ...dr, remediateDays: n } } })}
                      />
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function PolicyHistory({ policies, activeSha }: { policies: SlaPolicy[]; activeSha: string }) {
  if (policies.length === 0) return null
  return (
    <Card title="Version history">
      <ul className="divide-y divide-secondary">
        {policies.map((p) => (
          <li key={p.sha256} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5">
            <span className="font-mono text-xs text-secondary">{shortDigest(p.sha256)}</span>
            {p.sha256 === activeSha && (
              <Pill className="bg-brand-primary/10 text-brand-secondary ring-1 ring-inset ring-brand/25">active</Pill>
            )}
            <span className="text-xs text-tertiary">{p.config.version}</span>
            <span className="ml-auto text-xs text-quaternary">
              {p.createdBy} · {formatWhen(p.createdAt)}
            </span>
          </li>
        ))}
      </ul>
    </Card>
  )
}

export function SLAPolicy() {
  const { data, loading, error, refetch } = useFetch(() => api.slaPolicies(), { deps: [] })
  const active = data?.active ?? null
  const [draft, setDraft] = useState<SlaConfig | null>(null)
  const [busy, setBusy] = useState(false)
  const { notify } = useToast()

  // Seed the editable draft from the active policy the first time it loads (and when it changes).
  useEffect(() => {
    if (active) setDraft(structuredClone(active.config))
  }, [active])

  const dirty = useMemo(
    () => (active && draft ? JSON.stringify(draft) !== JSON.stringify(active.config) : false),
    [active, draft],
  )

  // Mirror the server's validity rules so an invalid config is refused here with a clear reason rather
  // than a 400. The block is empty only when the draft would be accepted.
  const invalidReason = useMemo(() => {
    if (!draft) return ''
    const w = draft.weights
    const sum = w.severity + w.exploitability + w.threatIntel + w.exposure + w.criticality
    if (Math.round(sum) !== 100) return 'the five scoring factors must sum to 100'
    const t = draft.thresholds
    if (!(t.emergency >= t.critical && t.critical >= t.high && t.high >= t.medium)) return 'tier thresholds must descend'
    for (const tier of SLA_TIERS) {
      const dr = draft.dueRanges[tier]
      if (dr.mitigateDays > dr.remediateDays) return `${tier} mitigate must not exceed remediate`
    }
    return ''
  }, [draft])

  async function activate() {
    if (!draft) return
    setBusy(true)
    try {
      const { created } = await api.activateSLAPolicy(draft)
      notify(created ? 'New SLA policy version activated.' : 'Policy re-activated (identical to the active version).', 'success')
      refetch()
    } catch (e) {
      notify(e instanceof Error ? e.message : 'Failed to activate policy', 'error')
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <Spinner label="Loading SLA policy…" />
  if (error) return <ErrorState message={error} />
  if (!active || !draft)
    return <ErrorState message="No SLA policy is available. The remediation-governance feature may be disabled." />

  return (
    <div className="space-y-4">
      <Card title="Active policy" titleClassName="flex items-center gap-2">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <div className="flex items-center gap-2">
            <Shield01 className="size-4 text-brand-secondary" aria-hidden />
            <span className="text-sm font-semibold text-primary">{active.config.version}</span>
          </div>
          <div className="text-xs text-tertiary">
            digest <span className="font-mono text-secondary">{shortDigest(active.sha256)}</span>
          </div>
          <div className="text-xs text-tertiary">
            activated by <span className="text-secondary">{active.createdBy || 'system'}</span> · {formatWhen(active.createdAt)}
          </div>
          <div className="ml-auto flex items-center gap-3">
            {dirty && !invalidReason && <span className="text-xs text-warning-primary">Unsaved edits</span>}
            <Button loading={busy} disabled={!dirty || invalidReason !== ''} onClick={activate} variant="primary" className="px-3 py-1.5">
              <Save01 className="size-4" /> Activate new version
            </Button>
          </div>
        </div>
        {dirty && invalidReason ? (
          <p className="mt-3 flex items-center gap-1.5 text-xs text-error-primary">
            <AlertTriangle className="size-3.5 shrink-0" aria-hidden /> Cannot activate: {invalidReason}.
          </p>
        ) : (
          <p className="mt-3 text-xs text-quaternary">
            {dirty
              ? 'Editing appends a new immutable version and makes it active; previous versions stay in the history below. Activation requires administrator permission.'
              : 'Edit the weights, thresholds, or due ranges below to stage a new version. Activation requires administrator permission.'}
          </p>
        )}
      </Card>

      <WeightsEditor cfg={draft} set={setDraft} />
      <ThresholdsEditor cfg={draft} set={setDraft} />
      <DueRangesEditor cfg={draft} set={setDraft} />
      <PolicyHistory policies={data?.policies ?? []} activeSha={active.sha256} />
    </div>
  )
}

export default SLAPolicy
