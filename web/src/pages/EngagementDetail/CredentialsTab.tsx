import { useState } from 'react'
import { AlertTriangle, CheckCircle, Key01, Lock01, Plus, Trash01, XClose } from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Skeleton } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { EngagementCredential } from '../../lib/api'

function formatWhen(iso: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function AddCredential({
  engagementId,
  existingNames,
  onStored,
  onCancel,
}: {
  engagementId: string
  existingNames: string[]
  onStored: (name: string, replaced: boolean) => void
  onCancel?: () => void
}) {
  const [name, setName] = useState('')
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const trimmed = name.trim()
  const validName = /^[A-Za-z0-9_.-]{1,64}$/.test(trimmed)
  const canStore = validName && value.length > 0 && !busy

  async function store() {
    if (!canStore) return
    setBusy(true)
    setErr('')
    try {
      const replaced = existingNames.includes(trimmed)
      await api.setEngagementCredential(engagementId, trimmed, value)
      setName('')
      setValue('')
      onStored(trimmed, replaced)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'failed to store credential')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Add a credential"
      actions={
        onCancel && (
          <Button variant="ghost" onClick={onCancel} className="px-2 py-1" aria-label="Cancel">
            <XClose className="size-4" />
          </Button>
        )
      }
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Field label="Placeholder name" htmlFor="cred-name" hint="Referenced in tool config as {{secret:NAME}}. Letters, digits, dot, dash, underscore.">
          <Input
            id="cred-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Enter a placeholder name"
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
        <Field label="Secret value" htmlFor="cred-value" hint="Sealed in the vault on store; resolved only at tool-execution time and never shown again.">
          <Input
            id="cred-value"
            type="password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Paste the secret value"
            autoComplete="new-password"
          />
        </Field>
      </div>
      {err && (
        <div aria-live="polite" className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <Button variant="primary" onClick={store} disabled={!canStore} loading={busy} className="px-3.5 py-2">
          <Plus className="size-4" aria-hidden />
          {existingNames.includes(trimmed) && validName ? 'Replace credential' : 'Store credential'}
        </Button>
        {name.length > 0 && !validName && (
          <span className="text-xs text-error-primary">Name allows letters, digits, dot, dash, underscore (max 64).</span>
        )}
      </div>
    </Card>
  )
}

function CredentialRow({
  cred,
  busy,
  confirming,
  onAskDelete,
  onCancelDelete,
  onConfirmDelete,
}: {
  cred: EngagementCredential
  busy: boolean
  confirming: boolean
  onAskDelete: () => void
  onCancelDelete: () => void
  onConfirmDelete: () => void
}) {
  return (
    <li className="flex flex-wrap items-center gap-x-4 gap-y-2 py-3">
      <Key01 className="size-4 shrink-0 text-quaternary" aria-hidden />
      <span className="font-mono text-sm font-semibold text-primary">{cred.name}</span>
      {cred.updatedAt && <span className="text-xs text-tertiary">updated {formatWhen(cred.updatedAt)}</span>}
      {confirming ? (
        <span className="ml-auto flex items-center gap-2">
          <span className="text-xs text-error-primary">Delete this credential?</span>
          <Button variant="secondary" onClick={onConfirmDelete} loading={busy} className="px-2.5 py-1 text-xs text-error-primary">
            Confirm
          </Button>
          <Button variant="ghost" onClick={onCancelDelete} className="px-2.5 py-1 text-xs">
            Cancel
          </Button>
        </span>
      ) : (
        <Button
          variant="secondary"
          onClick={onAskDelete}
          className="ml-auto px-2.5 py-1 text-xs text-error-primary"
          aria-label={`Delete credential ${cred.name}`}
        >
          <Trash01 className="size-3.5" aria-hidden />
          Delete
        </Button>
      )}
    </li>
  )
}

export function CredentialsTab({ engagementId }: { engagementId: string }) {
  const [refresh, setRefresh] = useState(0)
  const { data, loading, error } = useFetch<EngagementCredential[]>(
    () => api.engagementCredentials(engagementId),
    { deps: [engagementId, refresh] },
  )
  const creds = data ?? []

  const [adding, setAdding] = useState(false)
  const [success, setSuccess] = useState('')
  const [confirmName, setConfirmName] = useState('')
  const [pending, setPending] = useState('')
  const [mutErr, setMutErr] = useState('')

  const showForm = adding || (!loading && creds.length === 0)

  async function confirmDelete(name: string) {
    setPending(name)
    setMutErr('')
    try {
      await api.deleteEngagementCredential(engagementId, name)
      setConfirmName('')
      setSuccess(`Deleted "${name}".`)
      setRefresh((v) => v + 1)
    } catch (e) {
      setMutErr(e instanceof Error ? e.message : 'failed to delete credential')
    } finally {
      setPending('')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start gap-2 rounded-lg border border-secondary bg-secondary/30 px-4 py-3 text-sm text-tertiary">
        <Lock01 className="mt-0.5 size-4 shrink-0 text-quaternary" aria-hidden />
        <span>
          Credentials are sealed in the vault and resolved server-side only at tool-execution time. The
          secret never enters a log, the workspace, or this screen; it is write-only.
        </span>
      </div>

      {success && (
        <div aria-live="polite" className="flex items-center gap-2 rounded-lg border border-success-primary/25 bg-success-primary/5 px-4 py-2.5 text-sm text-success-primary">
          <CheckCircle className="size-4 shrink-0" aria-hidden />
          <span>{success}</span>
          <button type="button" onClick={() => setSuccess('')} className="ml-auto text-success-primary/70 hover:text-success-primary" aria-label="Dismiss">
            <XClose className="size-4" />
          </button>
        </div>
      )}

      {showForm ? (
        <AddCredential
          engagementId={engagementId}
          existingNames={creds.map((c) => c.name)}
          onStored={(name, replaced) => {
            setSuccess(`${replaced ? 'Replaced' : 'Stored'} "${name}".`)
            setAdding(false)
            setRefresh((v) => v + 1)
          }}
          onCancel={creds.length > 0 ? () => setAdding(false) : undefined}
        />
      ) : null}

      <Card
        title="Stored credentials"
        actions={
          <span className="flex items-center gap-2">
            <Pill>{creds.length}</Pill>
            {!showForm && (
              <Button variant="secondary" onClick={() => setAdding(true)} className="px-2.5 py-1 text-xs">
                <Plus className="size-3.5" aria-hidden />
                Add
              </Button>
            )}
          </span>
        }
      >
        {mutErr && (
          <div aria-live="polite" className="mb-3">
            <ErrorState message={mutErr} />
          </div>
        )}
        {loading ? (
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="flex items-center gap-4">
                <Skeleton className="size-4 rounded" />
                <Skeleton className="h-4 w-40" />
                <Skeleton className="ml-auto h-7 w-20" />
              </div>
            ))}
          </div>
        ) : error ? (
          <ErrorState message={error} />
        ) : creds.length === 0 ? (
          <EmptyState
            icon={Key01}
            title="No credentials yet"
            hint="Store a placeholder above, then reference it in a scan or tool as {{secret:NAME}}."
          />
        ) : (
          <ul className="divide-y divide-secondary/60">
            {creds.map((c) => (
              <CredentialRow
                key={c.name}
                cred={c}
                busy={pending === c.name}
                confirming={confirmName === c.name}
                onAskDelete={() => {
                  setConfirmName(c.name)
                  setMutErr('')
                }}
                onCancelDelete={() => setConfirmName('')}
                onConfirmDelete={() => confirmDelete(c.name)}
              />
            ))}
          </ul>
        )}
      </Card>

      <div className="flex items-start gap-2 text-xs text-quaternary">
        <AlertTriangle className="mt-0.5 size-3.5 shrink-0" aria-hidden />
        <span>Re-storing an existing name replaces its secret. Deleting one takes effect on the next tool run.</span>
      </div>
    </div>
  )
}
