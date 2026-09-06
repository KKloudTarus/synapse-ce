import { useEffect, useMemo, useState } from 'react'
import { CheckCircle, Clock, Copy01, Plus, RefreshCcw01, ShieldTick } from '@untitledui/icons'
import { Button, Card, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../../components/ui'
import { useParallelFetch } from '../../hooks'
import { api } from '../../lib/api'
import { PRIVACY_CATEGORIES, type PrivacyAssignment, type PrivacyDisposition, type PrivacyPolicy } from '../../lib/api'

const DISPOSITIONS: { value: PrivacyDisposition; label: string }[] = [
  { value: 'allow', label: 'Allow (keep)' },
  { value: 'redact', label: 'Redact' },
  { value: 'hash', label: 'Hash' },
  { value: 'drop', label: 'Drop' },
]

// Tone runs from least private (allow, kept in the clear) to most private (drop, removed). The label
// text always carries the meaning, so colour is never the only signal.
function DispositionBadge({ d }: { d: PrivacyDisposition }) {
  const tone: Record<PrivacyDisposition, string> = {
    allow: 'text-warning-primary bg-warning-primary/10 border-warning-primary/25',
    redact: 'text-utility-blue-600 dark:text-utility-blue-400 bg-utility-blue-500/10 border-utility-blue-500/25',
    hash: 'text-utility-purple-600 dark:text-utility-purple-400 bg-utility-purple-500/10 border-utility-purple-500/25',
    drop: 'text-success-primary bg-success-primary/10 border-success-primary/25',
  }
  return <span className={cn('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-xs font-semibold', tone[d])}>{d}</span>
}

function formatWhen(iso: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function shortDigest(d: string): string {
  return d.length > 18 ? `${d.slice(0, 16)}…` : d
}

function newOperationId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`
}

function dispositionOf(policy: PrivacyPolicy | undefined, category: string): PrivacyDisposition {
  return (policy?.dispositions?.[category] as PrivacyDisposition) ?? 'allow'
}

function DigestChip({ digest }: { digest: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-tertiary">
      <span className="uppercase tracking-wider text-quaternary">digest</span>
      <span className="font-mono text-secondary" title={digest}>
        {shortDigest(digest)}
      </span>
      <button
        type="button"
        onClick={() => {
          navigator.clipboard?.writeText(digest).then(
            () => {
              setCopied(true)
              setTimeout(() => setCopied(false), 1200)
            },
            () => {},
          )
        }}
        className="text-quaternary hover:text-secondary"
        aria-label="Copy full digest"
      >
        {copied ? <CheckCircle className="size-3.5 text-success-primary" /> : <Copy01 className="size-3.5" />}
      </button>
    </span>
  )
}

function ActivePolicyCard({ active }: { active: PrivacyAssignment | null }) {
  if (!active) {
    return (
      <Card title="Active policy" titleClassName="flex items-center gap-2">
        <div className="flex items-center gap-2 text-sm text-tertiary">
          <ShieldTick className="size-4 text-quaternary" aria-hidden />
          No policy is active yet. Agents apply the built-in default (secrets redacted, argv and paths
          bounded) until you activate one below.
        </div>
      </Card>
    )
  }
  const p = active.policy
  return (
    <Card title="Active policy" titleClassName="flex items-center gap-2" actions={<DigestChip digest={active.digest} />}>
      <div className="overflow-hidden rounded-lg border border-secondary">
        <table className="w-full text-left text-sm">
          <thead className="bg-secondary/40 text-[10px] uppercase tracking-wider text-tertiary">
            <tr>
              <th className="px-4 py-2 font-bold">Telemetry field</th>
              <th className="px-4 py-2 font-bold">Disposition</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-secondary/50">
            {PRIVACY_CATEGORIES.map((c) => (
              <tr key={c.id}>
                <td className="px-4 py-2 text-secondary">{c.label}</td>
                <td className="px-4 py-2">
                  <DispositionBadge d={dispositionOf(p, c.id)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-tertiary">
        <span>redact secrets: {p.redactSecrets ? 'on' : 'off'}</span>
        <span>max arg len {p.maxArgLen || 'unlimited'}</span>
        <span>max arg count {p.maxArgCount || 'unlimited'}</span>
        <span>max path len {p.maxPathLen || 'unlimited'}</span>
        {active.createdBy && <span>admitted by {active.createdBy}</span>}
        {active.createdAt && <span>{formatWhen(active.createdAt)}</span>}
      </div>
    </Card>
  )
}

export function TelemetryPrivacy() {
  const [refresh, setRefresh] = useState(0)
  const { data, loading, error } = useParallelFetch<[PrivacyAssignment | null, PrivacyAssignment[]]>(
    () => Promise.all([api.activePrivacyPolicy(), api.privacyPolicyHistory()]),
    { deps: [refresh] },
  )
  const active = data?.[0] ?? null
  const history = useMemo(() => data?.[1] ?? [], [data])

  const [dispositions, setDispositions] = useState<Record<string, PrivacyDisposition>>({})
  const [redactSecrets, setRedactSecrets] = useState(true)
  const [maxArgLen, setMaxArgLen] = useState(4096)
  const [maxArgCount, setMaxArgCount] = useState(64)
  const [maxPathLen, setMaxPathLen] = useState(1024)
  const [seeded, setSeeded] = useState(false)
  useEffect(() => {
    if (seeded || !data) return
    const seed: Record<string, PrivacyDisposition> = {}
    for (const c of PRIVACY_CATEGORIES) seed[c.id] = dispositionOf(active?.policy, c.id)
    setDispositions(seed)
    if (active?.policy) {
      setRedactSecrets(active.policy.redactSecrets)
      setMaxArgLen(active.policy.maxArgLen || 4096)
      setMaxArgCount(active.policy.maxArgCount || 64)
      setMaxPathLen(active.policy.maxPathLen || 1024)
    }
    setSeeded(true)
  }, [data, active, seeded])

  const [busy, setBusy] = useState('')
  const [mutErr, setMutErr] = useState('')
  const [notice, setNotice] = useState('')
  const [confirmActivate, setConfirmActivate] = useState('')

  const draftPolicy = (): PrivacyPolicy => ({ dispositions, redactSecrets, maxArgLen, maxArgCount, maxPathLen, version: 'v1' })

  async function admit(thenActivate: boolean) {
    setBusy(thenActivate ? 'admit-activate' : 'admit')
    setMutErr('')
    setNotice('')
    try {
      const { assignment, created } = await api.admitPrivacyPolicy(draftPolicy())
      if (thenActivate) {
        await api.activatePrivacyPolicy(assignment.digest, newOperationId())
        setNotice(`Admitted and activated policy ${shortDigest(assignment.digest)}. Agents fetch it on their next poll.`)
      } else {
        setNotice(`${created ? 'Admitted' : 'Already admitted'} policy ${shortDigest(assignment.digest)}. Activate it below to roll it out.`)
      }
      setRefresh((v) => v + 1)
    } catch (e) {
      setMutErr(e instanceof Error ? e.message : 'failed to admit policy')
    } finally {
      setBusy('')
    }
  }

  async function activate(digest: string) {
    setBusy(digest)
    setMutErr('')
    setNotice('')
    try {
      await api.activatePrivacyPolicy(digest, newOperationId())
      setConfirmActivate('')
      setNotice(`Activated policy ${shortDigest(digest)}. Agents fetch it on their next poll.`)
      setRefresh((v) => v + 1)
    } catch (e) {
      setMutErr(e instanceof Error ? e.message : 'failed to activate policy')
    } finally {
      setBusy('')
    }
  }

  const mutating = busy !== ''

  if (loading) return <Spinner label="Loading privacy policy…" />
  if (error) return <ErrorState message={error} />

  return (
    <div className="space-y-6">
      <div className="flex items-start gap-2 rounded-lg border border-secondary bg-secondary/30 px-4 py-3 text-sm text-tertiary">
        <ShieldTick className="mt-0.5 size-4 shrink-0 text-quaternary" aria-hidden />
        <span>
          Fleet agents apply this policy at the source, redacting each telemetry field before it leaves the
          host. Admit a policy to register it by content digest, then activate the digest to roll it out.
        </span>
      </div>

      {notice && (
        <div aria-live="polite" className="flex items-center gap-2 rounded-lg border border-success-primary/25 bg-success-primary/5 px-4 py-2.5 text-sm text-success-primary">
          <CheckCircle className="size-4 shrink-0" aria-hidden />
          {notice}
        </div>
      )}
      {mutErr && (
        <div aria-live="polite">
          <ErrorState message={mutErr} />
        </div>
      )}

      <ActivePolicyCard active={active} />

      <Card title="Admit a policy">
        <fieldset disabled={mutating}>
          <legend className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-tertiary">Field dispositions</legend>
          <div className="grid grid-cols-1 gap-x-8 gap-y-3 sm:grid-cols-2">
            {PRIVACY_CATEGORIES.map((c) => {
              const changed = active?.policy && dispositions[c.id] !== dispositionOf(active.policy, c.id)
              return (
                <div key={c.id} className="flex items-center justify-between gap-3">
                  <span className="flex items-center gap-2 text-sm text-secondary">
                    {c.label}
                    {changed && <span className="size-1.5 rounded-full bg-brand-solid" title="changed from active" aria-label="changed from active" />}
                  </span>
                  <Select
                    ariaLabel={`Disposition for ${c.label}`}
                    value={dispositions[c.id] ?? 'allow'}
                    onValueChange={(v) => setDispositions((prev) => ({ ...prev, [c.id]: v as PrivacyDisposition }))}
                    options={DISPOSITIONS}
                    size="sm"
                    className="w-40"
                  />
                </div>
              )
            })}
          </div>
          <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-4">
            <label className="flex items-center gap-2 text-sm text-secondary">
              <input
                type="checkbox"
                checked={redactSecrets}
                onChange={(e) => setRedactSecrets(e.target.checked)}
                className="size-4 rounded border-secondary text-brand-solid focus:ring-brand/40"
              />
              Redact secrets
            </label>
            <Field label="Max arg length" htmlFor="p-arglen" hint="0 = unlimited">
              <Input id="p-arglen" type="number" min={0} value={maxArgLen} onChange={(e) => setMaxArgLen(Number(e.target.value) || 0)} />
            </Field>
            <Field label="Max arg count" htmlFor="p-argcount" hint="0 = unlimited">
              <Input id="p-argcount" type="number" min={0} value={maxArgCount} onChange={(e) => setMaxArgCount(Number(e.target.value) || 0)} />
            </Field>
            <Field label="Max path length" htmlFor="p-pathlen" hint="0 = unlimited">
              <Input id="p-pathlen" type="number" min={0} value={maxPathLen} onChange={(e) => setMaxPathLen(Number(e.target.value) || 0)} />
            </Field>
          </div>
        </fieldset>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <Button variant="primary" onClick={() => admit(true)} loading={busy === 'admit-activate'} disabled={mutating} className="px-3.5 py-2">
            <Plus className="size-4" aria-hidden />
            Admit and activate
          </Button>
          <Button variant="secondary" onClick={() => admit(false)} loading={busy === 'admit'} disabled={mutating} className="px-3.5 py-2">
            Admit only
          </Button>
        </div>
      </Card>

      <Card title="Policy history" actions={<Pill>{history.length}</Pill>}>
        {history.length === 0 ? (
          <p className="text-sm text-tertiary">No policies admitted yet. Admit one above to build the history.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-secondary/40 text-[10px] uppercase tracking-wider text-tertiary">
                <tr>
                  <th className="px-4 py-2 font-bold">Digest</th>
                  <th className="px-4 py-2 font-bold">Admitted by</th>
                  <th className="px-4 py-2 font-bold">When</th>
                  <th className="px-4 py-2 font-bold text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-secondary/50">
                {history.map((h) => {
                  const isActive = active?.digest === h.digest
                  return (
                    <tr key={h.digest}>
                      <td className="px-4 py-2.5 font-mono text-xs text-primary" title={h.digest}>{shortDigest(h.digest)}</td>
                      <td className="px-4 py-2.5 text-xs text-tertiary">{h.createdBy || '—'}</td>
                      <td className="px-4 py-2.5 text-xs text-tertiary">
                        <span className="inline-flex items-center gap-1">
                          <Clock className="size-3" aria-hidden />
                          {formatWhen(h.createdAt)}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        {isActive ? (
                          <Pill className="text-success-primary">
                            <CheckCircle className="size-3" aria-hidden />
                            active
                          </Pill>
                        ) : confirmActivate === h.digest ? (
                          <span className="inline-flex items-center gap-2">
                            <span className="text-xs text-warning-primary">Roll this policy out to every agent?</span>
                            <Button variant="secondary" onClick={() => activate(h.digest)} loading={busy === h.digest} disabled={mutating} className="px-2.5 py-1 text-xs">
                              Confirm
                            </Button>
                            <Button variant="ghost" onClick={() => setConfirmActivate('')} disabled={mutating} className="px-2.5 py-1 text-xs">
                              Cancel
                            </Button>
                          </span>
                        ) : (
                          <Button variant="secondary" onClick={() => setConfirmActivate(h.digest)} disabled={mutating} className="px-2.5 py-1 text-xs">
                            <RefreshCcw01 className="size-3.5" aria-hidden />
                            Activate
                          </Button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
