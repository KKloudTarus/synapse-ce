import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Cloud01, Play, Plus, Trash01 } from '@untitledui/icons'
import { Button, Card, ErrorState, Field, Input, Select, cn } from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { api } from '../../lib/api'
import type { CSPMRun, CloudProvider, CloudTarget } from '../../lib/api'

const PROVIDERS: { value: CloudProvider; label: string }[] = [
  { value: 'aws', label: 'AWS' },
  { value: 'azure', label: 'Azure' },
  { value: 'gcp', label: 'GCP' },
]

const ROOT_HINT: Record<CloudProvider, string> = {
  aws: 'account id, e.g. 123456789012',
  azure: 'subscription id',
  gcp: 'project id',
}

const ROOT_LABEL: Record<CloudProvider, string> = {
  aws: 'AWS account',
  azure: 'Azure subscription',
  gcp: 'GCP project',
}

function statusTone(status: CSPMRun['status']): string {
  switch (status) {
    case 'succeeded':
      return 'bg-success-primary/10 text-success-primary ring-1 ring-inset ring-success-primary/25'
    case 'partial':
      return 'bg-warning-primary/10 text-warning-primary ring-1 ring-inset ring-warning-primary/25'
    case 'failed':
    case 'cancelled':
      return 'bg-error-primary/10 text-error-primary ring-1 ring-inset ring-error-primary/25'
    default:
      return 'bg-brand-primary/10 text-brand-secondary ring-1 ring-inset ring-brand/25'
  }
}

function formatWhen(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex flex-col">
      <span className="text-lg font-semibold tabular-nums text-primary">{value.toLocaleString()}</span>
      <span className="text-[11px] uppercase tracking-wide text-quaternary">{label}</span>
    </div>
  )
}

function RunStatus({ run, targets }: { run: CSPMRun; targets: CloudTarget[] }) {
  return (
    <Card title="Latest run" titleClassName="flex items-center gap-2">
      {targets.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1.5">
          {targets.map((t, i) => (
            <span key={i} className="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-0.5 font-mono text-[11px] text-secondary ring-1 ring-inset ring-secondary">
              <span className="uppercase text-brand-secondary">{t.provider}</span> {t.root}
            </span>
          ))}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium capitalize', statusTone(run.status))}>
          {run.status}
          {!run.complete && run.status !== 'failed' && <span className="ml-1.5 size-1.5 animate-pulse rounded-full bg-current" aria-hidden />}
        </span>
        <Stat label="Assets" value={run.assets} />
        <Stat label="Findings" value={run.findings} />
        <Stat label="Coverage issues" value={run.coverageIssues.length} />
        <Stat label="Evidence" value={run.evidenceRefs.length} />
        <div className="ml-auto text-right text-xs text-tertiary">
          <div>started {formatWhen(run.startedAt)}</div>
          <div>{run.finishedAt ? `finished ${formatWhen(run.finishedAt)}` : 'in progress'}</div>
        </div>
      </div>
      {run.errorCode && (
        <p className="mt-3 flex items-center gap-1.5 text-xs text-error-primary">
          <AlertTriangle className="size-3.5 shrink-0" aria-hidden /> {run.errorCode}
        </p>
      )}
      <p className="mt-3 font-mono text-[11px] text-quaternary">run {run.id}</p>
    </Card>
  )
}

export function CloudPostureTab({ engagementId }: { engagementId: string }) {
  const [targets, setTargets] = useState<CloudTarget[]>([{ provider: 'aws', root: '', credentialRef: '' }])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [run, setRun] = useState<CSPMRun | null>(null)
  const [submitted, setSubmitted] = useState<CloudTarget[]>([])
  const { notify } = useToast()
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Poll the run until it completes, so the durable worker's progress reaches the surface.
  useEffect(() => {
    if (!run || run.complete) {
      if (pollRef.current) clearInterval(pollRef.current)
      return
    }
    pollRef.current = setInterval(async () => {
      try {
        const next = await api.getCSPMRun(engagementId, run.id)
        setRun(next)
      } catch {
        // A transient read error keeps the last known state; the next tick retries.
      }
    }, 2500)
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [engagementId, run])

  const valid = targets.filter((t) => t.root.trim() !== '' && t.credentialRef.trim() !== '')

  function patch(i: number, p: Partial<CloudTarget>) {
    setTargets((cur) => cur.map((t, j) => (j === i ? { ...t, ...p } : t)))
  }

  async function runScan() {
    setBusy(true)
    setErr('')
    try {
      const cleaned = valid.map((t) => ({ ...t, root: t.root.trim(), credentialRef: t.credentialRef.trim() }))
      const started = await api.runCSPM(engagementId, cleaned)
      setSubmitted(cleaned)
      setRun(started)
      notify('Cloud posture run accepted.', 'success')
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Failed to start CSPM run'
      setErr(message)
      notify(message, 'error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <Card title="Run cloud posture scan" titleClassName="flex items-center gap-2">
        <p className="text-xs text-tertiary">
          A bounded, read-only live scan of a cloud account's posture. Each target names a provider, its
          root (account, subscription, or project), and a vault credential reference. The reference points
          at a stored credential; it is never the credential material.
        </p>
        <div className="mt-4 space-y-2">
          {targets.map((t, i) => (
            <div key={i} className="grid grid-cols-1 items-end gap-2 sm:grid-cols-[8rem_1fr_1fr_auto]">
              <Field label={i === 0 ? 'Provider' : ''}>
                <Select value={t.provider} onValueChange={(v) => patch(i, { provider: v as CloudProvider })} options={PROVIDERS} ariaLabel={`Target ${i + 1} provider`} />
              </Field>
              <Field label={i === 0 ? ROOT_LABEL[t.provider] : ''}>
                <Input value={t.root} onChange={(e) => patch(i, { root: e.target.value })} placeholder={ROOT_HINT[t.provider]} className="font-mono" aria-label={`Target ${i + 1} root`} />
              </Field>
              <Field label={i === 0 ? 'Credential reference' : ''}>
                <Input value={t.credentialRef} onChange={(e) => patch(i, { credentialRef: e.target.value })} placeholder="vault reference" className="font-mono" aria-label={`Target ${i + 1} credential reference`} />
              </Field>
              <button
                type="button"
                onClick={() => setTargets((cur) => (cur.length === 1 ? cur : cur.filter((_, j) => j !== i)))}
                aria-label={`Remove target ${i + 1}`}
                disabled={targets.length === 1}
                className="justify-self-start rounded-md p-2.5 text-quaternary transition-colors hover:bg-secondary hover:text-critical disabled:opacity-40 sm:justify-self-auto"
              >
                <Trash01 className="size-4" />
              </button>
            </div>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => setTargets((cur) => [...cur, { provider: 'aws', root: '', credentialRef: '' }])}
            className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium text-brand-secondary transition-colors hover:bg-secondary"
          >
            <Plus className="size-3.5" /> Add target
          </button>
          <Button variant="primary" className="ml-auto px-3 py-2" loading={busy} disabled={busy || valid.length === 0} onClick={runScan}>
            <Play className="size-4" /> Run posture scan
          </Button>
        </div>
        {valid.length === 0 && (
          <p className="mt-2 text-[11px] text-quaternary">Each target needs a root and a credential reference.</p>
        )}
        {err && (
          <div className="mt-3">
            <ErrorState message={err} />
          </div>
        )}
      </Card>

      {run ? (
        <RunStatus run={run} targets={submitted} />
      ) : (
        <Card>
          <div className="flex items-center gap-2 text-sm text-tertiary">
            <Cloud01 className="size-4 text-quaternary" aria-hidden />
            No run yet. Add a target above and start a scan; its status and findings appear here.
          </div>
        </Card>
      )}
    </div>
  )
}

export default CloudPostureTab
