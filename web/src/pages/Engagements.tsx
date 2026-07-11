import { Briefcase, Plus, Target, Trash2, Upload, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import type { Engagement, ScopeTarget } from '../lib/types'
import { kindLabel } from '../lib/format'
import { Button, Card, cn, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner } from '../components/ui'

const KINDS = ['repo', 'domain', 'host', 'url', 'image', 'cidr']

export function Engagements() {
  const [list, setList] = useState<Engagement[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [importing, setImporting] = useState(false)
  const [importErr, setImportErr] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()

  function load() {
    setError(null)
    api
      .listEngagements()
      .then(setList)
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load engagements'))
  }
  useEffect(load, [])

  async function onImportFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = '' // allow re-importing the same file
    if (!file) return
    setImporting(true)
    setImportErr(null)
    try {
      const eng = await api.importBundle(await file.text())
      navigate(`/engagements/${eng.id}`)
    } catch (err) {
      setImportErr(err instanceof Error ? err.message : 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  return (
    <div className="mx-auto max-w-6xl animate-fade-in">
      <header className="bg-hero mb-6 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border p-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Engagements</h1>
          <p className="mt-1.5 max-w-xl text-sm text-mutedfg">
            Authorized testing scopes – every scan is gated by an engagement's scope and window, server-side.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input ref={fileRef} type="file" accept="application/json,.json" className="hidden" onChange={onImportFile} />
          <Button variant="secondary" loading={importing} onClick={() => fileRef.current?.click()}>
            <Upload className="size-4" /> Import bundle
          </Button>
          <Button variant="brand" onClick={() => setCreating((v) => !v)}>
            {creating ? (
              <>
                <X className="size-4" /> Cancel
              </>
            ) : (
              <>
                <Plus className="size-4" /> New engagement
              </>
            )}
          </Button>
        </div>
      </header>

      {importErr && (
        <div className="mb-6">
          <ErrorState message={importErr} />
        </div>
      )}

      {creating && (
        <div className="mb-6">
          <CreateForm
            onCreated={() => {
              setCreating(false)
              load()
            }}
          />
        </div>
      )}

      {error && <ErrorState message={error} />}
      {!list && !error && <Spinner label="Loading engagements…" />}
      {list && list.length === 0 && !creating && (
        <EmptyState
          icon={Target}
          title="No engagements yet"
          hint="Create one to define an authorized testing scope, then run an SCA scan against it."
          action={
            <Button variant="brand" onClick={() => setCreating(true)}>
              <Plus className="size-4" /> New engagement
            </Button>
          }
        />
      )}
      {list && list.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {list.map((e) => (
            <EngagementCard key={e.id} e={e} />
          ))}
        </div>
      )}
    </div>
  )
}

function EngagementCard({ e }: { e: Engagement }) {
  return (
    <Link
      to={`/engagements/${e.id}`}
      className="lift card-sheen elev group block rounded-xl border border-border bg-card p-5 hover:border-brand/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="truncate font-medium text-foreground">{e.name || 'Untitled'}</h3>
          {e.client && (
            <p className="mt-0.5 flex items-center gap-1.5 text-sm text-mutedfg">
              <Briefcase className="size-3.5" /> {e.client}
            </p>
          )}
        </div>
        <StatusPill status={e.status} />
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Pill>
          <Target className="size-3" /> {e.inScope.length} in scope
        </Pill>
        {e.outOfScope.length > 0 && <Pill>{e.outOfScope.length} excluded</Pill>}
      </div>
      <p className="mt-4 truncate font-mono text-xs text-subtlefg">{e.id}</p>
    </Link>
  )
}

export function StatusPill({ status }: { status: string }) {
  const s = (status || 'draft').toLowerCase()
  // Engagement lifecycle vocabulary: draft -> active -> completed -> archived.
  const tone =
    s === 'active'
      ? 'bg-accent/10 text-accent ring-accent/25'
      : s === 'completed'
        ? 'bg-brand/10 text-branddim ring-brand/25'
        : s === 'archived'
          ? 'bg-muted text-mutedfg ring-border'
          : 'bg-info/10 text-info ring-info/25' // draft (and any unknown)
  return (
    <span
      className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset', tone)}
    >
      {s}
    </span>
  )
}

function CreateForm({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState('')
  const [client, setClient] = useState('')
  const [scope, setScope] = useState<ScopeTarget[]>([{ kind: 'repo', value: '' }])
  const [authFrom, setAuthFrom] = useState('')
  const [authTo, setAuthTo] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function setRow(i: number, patch: Partial<ScopeTarget>) {
    setScope((rows) => rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    const inScope = scope.filter((r) => r.value.trim() !== '')
    if (!name.trim()) {
      setError('Name is required.')
      return
    }
    if (inScope.length === 0) {
      setError('Add at least one in-scope target.')
      return
    }
    // datetime-local has no timezone; interpret in the browser's tz and send RFC3339.
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone
    const from = authFrom ? new Date(authFrom).toISOString() : undefined
    const to = authTo ? new Date(authTo).toISOString() : undefined
    if (from && to && new Date(from) >= new Date(to)) {
      setError('Authorization start must be before end.')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      await api.createEngagement({
        name: name.trim(),
        client: client.trim(),
        inScope,
        outOfScope: [],
        authorizedFrom: from,
        authorizedTo: to,
        timezone: from || to ? tz : undefined,
      })
      onCreated()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create engagement')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Card title="New engagement" className="animate-fade-in">
      <form onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Name">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="acme-q3-2026" autoFocus />
          </Field>
          <Field label="Client" hint="Optional">
            <Input value={client} onChange={(e) => setClient(e.target.value)} placeholder="Acme Corp" />
          </Field>
        </div>

        <div className="space-y-2">
          <span className="text-xs font-medium text-mutedfg">In-scope targets</span>
          {scope.map((row, i) => (
            <div key={i} className="flex gap-2">
              <Select
                value={row.kind}
                onValueChange={(v) => setRow(i, { kind: v })}
                ariaLabel="Target kind"
                options={KINDS.map((k) => ({ value: k, label: kindLabel(k) }))}
              />
              <Input
                value={row.value}
                onChange={(e) => setRow(i, { value: e.target.value })}
                placeholder="/path/to/repo or app.acme.io"
                className="font-mono"
              />
              {scope.length > 1 && (
                <button
                  type="button"
                  onClick={() => setScope((rows) => rows.filter((_, idx) => idx !== i))}
                  className="rounded-lg px-2 text-mutedfg transition-colors hover:bg-elevated hover:text-high"
                  aria-label="Remove target"
                >
                  <Trash2 className="size-4" />
                </button>
              )}
            </div>
          ))}
          <button
            type="button"
            onClick={() => setScope((rows) => [...rows, { kind: 'repo', value: '' }])}
            className="inline-flex items-center gap-1 text-xs font-medium text-branddim hover:underline"
          >
            <Plus className="size-3" /> Add target
          </button>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Authorized from" hint="Optional – testing is refused before this" htmlFor="auth-from">
            <Input id="auth-from" type="datetime-local" value={authFrom} onChange={(e) => setAuthFrom(e.target.value)} />
          </Field>
          <Field label="Authorized to" hint="Optional – testing is refused after this" htmlFor="auth-to">
            <Input id="auth-to" type="datetime-local" value={authTo} onChange={(e) => setAuthTo(e.target.value)} />
          </Field>
        </div>

        {error && <ErrorState message={error} />}
        <div className="flex justify-end">
          <Button variant="brand" type="submit" loading={submitting}>
            Create engagement
          </Button>
        </div>
      </form>
    </Card>
  )
}
