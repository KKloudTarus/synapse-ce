import { useMemo, useState } from 'react'
import { AlertTriangle, Plus, ShieldOff, Target04, Trash01 } from '@untitledui/icons'
import { Button, Card, Field, Input, Pill, Select, cn } from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { TechnicalAsset } from '../../lib/types'

interface StepDraft {
  technique: string
  target: string
  blastRadius: 'read_only' | 'state_changing'
  cleanup: string
}

const RADII = [
  { value: 'read_only', label: 'Read-only' },
  { value: 'state_changing', label: 'State-changing (needs cleanup)' },
]

function emptyStep(): StepDraft {
  return { technique: '', target: '', blastRadius: 'read_only', cleanup: '' }
}

// ChainRehearsalTab drives a governed exploitation chain as a no-host simulation. The operator declares the
// steps; each is admitted through the engagement's rules of engagement, sealed, and verified. It proves the
// chain is policy-admissible and its custody chain is sound without touching a host.
export function ChainRehearsalTab({ engagementId }: { engagementId: string }) {
  const { data: assets } = useFetch<TechnicalAsset[]>(() => api.listTechnicalAssets(), { deps: [] })
  const [steps, setSteps] = useState<StepDraft[]>([emptyStep()])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [result, setResult] = useState<{ state: string; steps: number } | null>(null)
  const { notify } = useToast()

  const assetOptions = useMemo(
    () => [
      { value: '', label: assets && assets.length > 0 ? 'Select an asset…' : 'No assets enrolled' },
      ...(assets ?? []).map((a) => ({ value: a.id, label: `${a.name} (${a.kind})` })),
    ],
    [assets],
  )

  const ready = steps.length > 0 && steps.every((s) => s.technique.trim() !== '' && s.target !== '')

  function update(i: number, patch: Partial<StepDraft>) {
    setSteps((xs) => xs.map((s, j) => (j === i ? { ...s, ...patch } : s)))
  }

  async function rehearse() {
    if (!ready) return
    setBusy(true)
    setErr('')
    setResult(null)
    try {
      const res = await api.rehearseChain(
        engagementId,
        steps.map((s) => ({
          technique: s.technique.trim(),
          target: s.target,
          blastRadius: s.blastRadius,
          cleanup: s.blastRadius === 'state_changing' && s.cleanup.trim() ? [s.cleanup.trim()] : [],
          cleanupVerification: s.blastRadius === 'state_changing' ? 'confirm the target is restored' : '',
        })),
      )
      setResult({ state: res.state, steps: res.steps })
      notify(`Rehearsal complete (simulation): chain ${res.state}.`, res.state === 'succeeded' ? 'success' : 'error')
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to rehearse the chain')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start gap-2 rounded-xl border border-warning-primary/40 bg-warning-primary/10 p-3">
        <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning-primary" aria-hidden="true" />
        <p className="text-xs text-secondary">
          <span className="font-semibold text-warning-primary">Simulation, not real exploitation.</span> A
          rehearsal admits each step through this engagement's rules of engagement, seals per-step evidence,
          and has a distinct verifier confirm it, but executes with a no-host simulation. It proves the chain
          is permitted and its chain of custody is sound; it never touches a host. A running rehearsal is
          haltable by the offensive kill switch.
        </p>
      </div>

      <Card
        title="Exploitation chain rehearsal"
        actions={
          <div className="flex items-center gap-2">
            <Pill className="text-tertiary">
              <ShieldOff className="size-3.5 text-warning-primary" aria-hidden /> No host contact
            </Pill>
            {result && (
              <Pill className={result.state === 'succeeded' ? 'text-success-primary' : 'text-error-primary'}>
                {result.state}
              </Pill>
            )}
            <Button loading={busy} disabled={!ready} onClick={rehearse} variant="primary" className="px-3 py-1.5">
              <Target04 className="size-4" /> Run no-host rehearsal
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          {steps.map((s, i) => (
            <div key={i} className="flex flex-wrap items-end gap-3 rounded-lg border border-secondary bg-primary p-3">
              <span className="pb-2 font-mono text-xs text-quaternary">#{i + 1}</span>
              <Field label="Technique">
                <Input
                  value={s.technique}
                  onChange={(e) => update(i, { technique: e.target.value })}
                  placeholder="recon.service_banner"
                  aria-label={`Step ${i + 1} technique`}
                  className="w-56"
                />
              </Field>
              <div className="space-y-1.5">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Target</div>
                <Select
                  value={s.target}
                  onValueChange={(v) => update(i, { target: v })}
                  size="sm"
                  aria-label={`Step ${i + 1} target`}
                  className="w-56"
                  options={assetOptions}
                />
              </div>
              <div className="space-y-1.5">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Blast radius</div>
                <Select
                  value={s.blastRadius}
                  onValueChange={(v) => update(i, { blastRadius: v as StepDraft['blastRadius'] })}
                  size="sm"
                  aria-label={`Step ${i + 1} blast radius`}
                  className="w-56"
                  options={RADII}
                />
              </div>
              {s.blastRadius === 'state_changing' && (
                <Field label="Cleanup">
                  <Input
                    value={s.cleanup}
                    onChange={(e) => update(i, { cleanup: e.target.value })}
                    placeholder="restore the changed state"
                    aria-label={`Step ${i + 1} cleanup`}
                    className="w-56"
                  />
                </Field>
              )}
              {steps.length > 1 && (
                <button
                  type="button"
                  onClick={() => setSteps((xs) => xs.filter((_, j) => j !== i))}
                  aria-label={`Remove step ${i + 1}`}
                  className="pb-2 text-quaternary hover:text-error-primary"
                >
                  <Trash01 className="size-4" />
                </button>
              )}
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={() => setSteps((xs) => [...xs, emptyStep()])}
          className={cn('mt-3 inline-flex items-center gap-1.5 text-xs font-medium text-brand-secondary hover:text-brand-primary')}
        >
          <Plus className="size-3.5" /> Add step
        </button>
        {result && (
          <p className="mt-3 text-xs text-tertiary">
            The rehearsal reached <span className="font-semibold text-primary">{result.state}</span> across{' '}
            {result.steps} step{result.steps === 1 ? '' : 's'}. A refused step (outside the rules of engagement)
            halts the chain and runs cleanup, exactly as a real chain would.
          </p>
        )}
        {err && <p className="mt-2 text-xs text-error-primary">{err}</p>}
      </Card>
    </div>
  )
}
