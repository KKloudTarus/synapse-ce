import { useState, useEffect } from 'react'
import { AlertTriangle, Plus, Save01, Trash01 } from '@untitledui/icons'
import { Button, Card, ErrorState, Field, Input, Pill, Select, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import { kindLabel } from '../../lib/format'
import type { BusinessAsset, Engagement, ScopeTarget } from '../../lib/types'
import { StatusPill } from '../Engagements'
import { TARGET_KINDS } from './ReconTab'

export function SettingsTab({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  return (
    <div className="space-y-4">
      <LifecycleCard eng={eng} onUpdated={onUpdated} />
      <AssetAssignmentCard eng={eng} onUpdated={onUpdated} />
      <ScopeEditorCard eng={eng} onUpdated={onUpdated} />
      <WindowEditorCard eng={eng} onUpdated={onUpdated} />
      <RoeEditorCard eng={eng} onUpdated={onUpdated} />
      <LiveReconCard eng={eng} onUpdated={onUpdated} />
    </div>
  )
}

export function AssetAssignmentCard({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  const { data: assets } = useFetch(
    () => api.listBusinessAssets('limit=200').then((r) => r.items).catch(() => [] as BusinessAsset[]),
    { deps: [] },
  )
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  async function assign(assetId: string) {
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      await api.assignEngagementAsset(eng.id, assetId)
      const updated = await api.getEngagement(eng.id)
      if (updated) onUpdated(updated)
      setSaved(true)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to assign Asset')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title="Asset assignment">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm text-tertiary">Link to a business asset</span>
        <Select
          value={eng.businessAssetId || ''}
          onValueChange={assign}
          disabled={saving}
          size="sm"
          className="w-72"
          options={[
            { value: '', label: 'Unassigned' },
            ...(assets ?? []).map((a) => ({ value: a.id, label: `${a.name} (${a.key})` })),
          ]}
        />
        {saved && !error && <span className="text-xs text-accent">Updated.</span>}
        {error && <span className="text-xs text-critical">{error}</span>}
      </div>
    </Card>
  )
}

export function LiveReconCard({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  async function toggle() {
    setBusy(true)
    setErr(null)
    try {
      onUpdated(await api.setLiveRecon(eng.id, !eng.liveReconEnabled))
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Update failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="Live reconnaissance">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="max-w-xl space-y-2 text-sm text-tertiary">
          <p>
            Live recon shells out to network tools against in-scope targets. Until the hardened sandbox + egress
            allowlist ship, it is <span className="font-medium text-primary">lab-only</span>: enable it only for
            authorized test environments.
          </p>
          <p className="flex items-center gap-2">
            <span className="text-tertiary">Status:</span>
            {eng.liveReconEnabled ? (
              <Pill className="bg-accent/10 text-accent ring-1 ring-inset ring-accent/25">Enabled</Pill>
            ) : (
              <Pill className="bg-secondary text-tertiary ring-1 ring-inset ring-secondary">Disabled</Pill>
            )}
          </p>
          {err && <span className="text-xs text-critical">{err}</span>}
        </div>
        <Button
          variant={eng.liveReconEnabled ? 'secondary' : 'primary'}
          loading={busy}
          onClick={toggle}
          className="px-3 py-1.5"
        >
          {eng.liveReconEnabled ? 'Disable live recon' : 'Enable live recon'}
        </Button>
      </div>
    </Card>
  )
}

export const LIFECYCLE_NEXT: Record<string, { status: string; label: string; variant: 'secondary-color' | 'secondary' }[]> = {
  draft: [
    { status: 'active', label: 'Activate', variant: 'secondary-color' },
    { status: 'archived', label: 'Archive', variant: 'secondary' },
  ],
  active: [
    { status: 'completed', label: 'Complete', variant: 'secondary-color' },
    { status: 'archived', label: 'Archive', variant: 'secondary' },
  ],
  completed: [{ status: 'archived', label: 'Archive', variant: 'secondary' }],
  archived: [],
}

export function LifecycleCard({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  const [busy, setBusy] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const next = LIFECYCLE_NEXT[eng.status] ?? []

  async function go(status: string) {
    setBusy(status)
    setErr(null)
    try {
      onUpdated(await api.transitionEngagement(eng.id, status))
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Transition failed')
    } finally {
      setBusy(null)
    }
  }

  return (
    <Card title="Lifecycle">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm text-tertiary">Status</span>
        <StatusPill status={eng.status} />
        <span className="hidden text-quaternary sm:inline">·</span>
        <span className="text-xs text-quaternary">
          {eng.status === 'archived' ? 'Terminal state' : 'Scope and authorization enforced on every run'}
        </span>
        <div className="ml-auto flex flex-wrap gap-2">
          {next.length === 0 ? (
            <span className="text-xs text-quaternary">No further transitions.</span>
          ) : (
            next.map((n) => (
              <Button
                key={n.status}
                variant={n.variant}
                loading={busy === n.status}
                disabled={busy !== null}
                onClick={() => go(n.status)}
              >
                {n.label}
              </Button>
            ))
          )}
        </div>
      </div>
      {err && (
        <div className="mt-2">
          <ErrorState message={err} />
        </div>
      )}
    </Card>
  )
}

export function ScopeEditorCard({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  const [inScope, setInScope] = useState<ScopeTarget[]>(eng.inScope)
  const [outScope, setOutScope] = useState<ScopeTarget[]>(eng.outOfScope)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  // Re-seed when navigating to a different engagement.
  useEffect(() => {
    setInScope(eng.inScope)
    setOutScope(eng.outOfScope)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eng.id])

  async function save() {
    setBusy(true)
    setErr(null)
    setSaved(false)
    const clean = (xs: ScopeTarget[]) => xs.filter((t) => t.value.trim() !== '')
    try {
      const updated = await api.updateScope(eng.id, clean(inScope), clean(outScope))
      onUpdated(updated)
      setInScope(updated.inScope)
      setOutScope(updated.outOfScope)
      setSaved(true)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to save scope')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Scope"
      actions={
        <Button loading={busy} onClick={save} variant="secondary-color" className="px-3 py-1.5">
          <Save01 className="size-4" /> Save scope
        </Button>
      }
    >
      <div className="space-y-4">
        <TargetList label="In scope" targets={inScope} onChange={setInScope} />
        <TargetList label="Out of scope" targets={outScope} onChange={setOutScope} />
      </div>
      <p className="mt-3 text-[11px] text-quaternary">
        Host-centric matching. Out-of-scope always wins. The execution gate reads this live.
      </p>
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
      {saved && !err && <p className="mt-3 text-xs text-accent">Scope saved.</p>}
    </Card>
  )
}

export function TargetList({
  label,
  targets,
  onChange,
}: {
  label: string
  targets: ScopeTarget[]
  onChange: (t: ScopeTarget[]) => void
}) {
  function update(i: number, patch: Partial<ScopeTarget>) {
    onChange(targets.map((t, j) => (j === i ? { ...t, ...patch } : t)))
  }
  return (
    <div>
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-tertiary">{label}</div>
      <div className="space-y-2">
        {targets.length === 0 && <p className="text-xs text-quaternary">No targets.</p>}
        {targets.map((t, i) => (
          <div key={i} className="flex items-center gap-2">
            <Select
              value={t.kind}
              onValueChange={(v) => update(i, { kind: v })}
              ariaLabel={`${label} target ${i + 1} kind`}
              options={TARGET_KINDS.map((k) => ({ value: k, label: kindLabel(k) }))}
              className="w-32 shrink-0"
            />
            <Input
              value={t.value}
              onChange={(e) => update(i, { value: e.target.value })}
              placeholder="value (e.g. *.example.com, 10.0.0.0/24)"
              className="flex-1 font-mono"
              aria-label={`${label} target ${i + 1} value`}
            />
            <button
              type="button"
              onClick={() => onChange(targets.filter((_, j) => j !== i))}
              aria-label={`Remove ${label} target ${i + 1}`}
              className="rounded-md p-2 text-quaternary transition-colors hover:bg-secondary hover:text-critical focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
            >
              <Trash01 className="size-4" />
            </button>
          </div>
        ))}
      </div>
      <button
        type="button"
        onClick={() => onChange([...targets, { kind: 'domain', value: '' }])}
        className="mt-2 inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium text-brand-secondary transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
      >
        <Plus className="size-3.5" /> Add target
      </button>
    </div>
  )
}

export function WindowEditorCard({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  const [from, setFrom] = useState(toLocalInput(eng.authorizedFrom))
  const [to, setTo] = useState(toLocalInput(eng.authorizedTo))
  const [tz, setTz] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    setFrom(toLocalInput(eng.authorizedFrom))
    setTo(toLocalInput(eng.authorizedTo))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eng.id])

  const clearsWindow = from === '' && to === ''

  async function save() {
    setBusy(true)
    setErr(null)
    setSaved(false)
    try {
      const f = from ? new Date(from).toISOString() : ''
      const t = to ? new Date(to).toISOString() : ''
      onUpdated(await api.setAuthorizationWindow(eng.id, f, t, tz.trim()))
      setSaved(true)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to save window')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Authorization window"
      actions={
        <Button loading={busy} onClick={save} variant="secondary-color" className="px-3 py-1.5">
          <Save01 className="size-4" /> Save window
        </Button>
      }
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Field label="From">
          <Input
            type="datetime-local"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            aria-label="Authorization window start"
          />
        </Field>
        <Field label="To">
          <Input
            type="datetime-local"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            aria-label="Authorization window end"
          />
        </Field>
        <Field label="Timezone" hint="IANA name (display/audit)">
          <Input
            value={tz}
            onChange={(e) => setTz(e.target.value)}
            placeholder="UTC"
            aria-label="Authorization window timezone"
          />
        </Field>
      </div>
      <p className="mt-3 text-[11px] text-quaternary">
        Tools are refused outside this window (±2 min skew). Leave a bound empty for open-ended.
      </p>
      {clearsWindow && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-medium/40 bg-medium/10 p-3 text-xs text-medium">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>Both bounds are empty – saving removes the authorization window (testing allowed at any time).</span>
        </div>
      )}
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
      {saved && !err && <p className="mt-3 text-xs text-accent">Window saved.</p>}
    </Card>
  )
}

export const KNOWN_TOOL_CLASSES = ['sca', 'recon', 'exploit']

export function RoeEditorCard({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  const seedBlackouts = () => eng.roe.blackouts.map((b) => ({ from: toLocalInput(b.from), to: toLocalInput(b.to) }))
  const [classes, setClasses] = useState<string[]>(eng.roe.allowedToolClasses)
  const [blackouts, setBlackouts] = useState<{ from: string; to: string }[]>(seedBlackouts)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    setClasses(eng.roe.allowedToolClasses)
    setBlackouts(seedBlackouts())
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eng.id])

  function toggleClass(c: string) {
    setClasses((cur) => (cur.includes(c) ? cur.filter((x) => x !== c) : [...cur, c]))
  }

  async function save() {
    setBusy(true)
    setErr(null)
    setSaved(false)
    try {
      const bs = blackouts
        .filter((b) => b.from && b.to)
        .map((b) => ({ from: new Date(b.from).toISOString(), to: new Date(b.to).toISOString() }))
      onUpdated(await api.setRoE(eng.id, classes, bs))
      setSaved(true)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to save rules of engagement')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Rules of engagement"
      actions={
        <Button loading={busy} onClick={save} variant="secondary-color" className="px-3 py-1.5">
          <Save01 className="size-4" /> Save RoE
        </Button>
      }
    >
      <div className="space-y-4">
        <div>
          <div id="roe-classes-label" className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-tertiary">
            Allowed tool classes
          </div>
          <div role="group" aria-labelledby="roe-classes-label" className="flex flex-wrap gap-2">
            {KNOWN_TOOL_CLASSES.map((c) => {
              const on = classes.includes(c)
              return (
                <button
                  key={c}
                  type="button"
                  aria-pressed={on}
                  aria-label={`Allow ${c} tools`}
                  onClick={() => toggleClass(c)}
                  className={cn(
                    'rounded-md px-3 py-1.5 text-sm font-medium capitalize ring-1 ring-inset transition-colors',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
                    on
                      ? 'bg-brand-primary text-brand-secondary ring-brand'
                      : 'bg-secondary text-tertiary ring-secondary hover:text-primary',
                  )}
                >
                  {c}
                </button>
              )
            })}
          </div>
          {classes.length === 0 ? (
            <div className="mt-2 flex items-start gap-2 rounded-lg border border-medium/40 bg-medium/10 p-3 text-xs text-medium">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span>
                None selected – <strong>all</strong> tool classes are allowed. Select one or more to restrict execution.
              </span>
            </div>
          ) : (
            <p className="mt-2 text-xs text-quaternary">
              Only the selected tool classes may run; everything else is denied.
            </p>
          )}
        </div>

        <div>
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-tertiary">Blackout windows</div>
          <div className="space-y-2">
            {blackouts.length === 0 && <p className="text-xs text-quaternary">No blackout windows.</p>}
            {blackouts.map((b, i) => (
              <div key={i} className="grid grid-cols-1 items-center gap-2 sm:grid-cols-[1fr_auto_1fr_auto]">
                <Input
                  type="datetime-local"
                  value={b.from}
                  onChange={(e) =>
                    setBlackouts((cur) => cur.map((x, j) => (j === i ? { ...x, from: e.target.value } : x)))
                  }
                  aria-label={`Blackout ${i + 1} start`}
                />
                <span className="hidden text-center text-quaternary sm:inline">→</span>
                <Input
                  type="datetime-local"
                  value={b.to}
                  onChange={(e) => setBlackouts((cur) => cur.map((x, j) => (j === i ? { ...x, to: e.target.value } : x)))}
                  aria-label={`Blackout ${i + 1} end`}
                />
                <button
                  type="button"
                  onClick={() => setBlackouts((cur) => cur.filter((_, j) => j !== i))}
                  aria-label={`Remove blackout ${i + 1}`}
                  className="justify-self-start rounded-md p-2 text-quaternary transition-colors hover:bg-secondary hover:text-critical focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40 sm:justify-self-auto"
                >
                  <Trash01 className="size-4" />
                </button>
              </div>
            ))}
          </div>
          <button
            type="button"
            onClick={() => setBlackouts((cur) => [...cur, { from: '', to: '' }])}
            className="mt-2 inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium text-brand-secondary transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
          >
            <Plus className="size-3.5" /> Add blackout
          </button>
        </div>
      </div>
      <p className="mt-3 text-[11px] text-quaternary">
        Enforced on every run: disallowed tool classes and blackout windows are denied and audited.
      </p>
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
      {saved && !err && <p className="mt-3 text-xs text-accent">Rules of engagement saved.</p>}
    </Card>
  )
}

export function toLocalInput(rfc: string | null): string {
  if (!rfc) return ''
  const d = new Date(rfc)
  if (Number.isNaN(d.getTime())) return ''
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
}
