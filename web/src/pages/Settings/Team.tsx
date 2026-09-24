import { Key01, ShieldTick, UserPlus01 } from '@untitledui/icons'
import { copyText } from '../../lib/clipboard'
import { useEffect, useRef, useState } from 'react'
import { api } from '../../lib/api'
import type { User, UserRole } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Input, Pill, Select, Spinner } from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { useUserList } from '../../hooks'

const ROLE_OPTIONS = [
  { value: 'member', label: 'Member' },
  { value: 'consultant', label: 'Consultant' },
  { value: 'reviewer', label: 'Reviewer' },
  { value: 'readonly', label: 'Read only' },
  { value: 'admin', label: 'Admin' },
]

export function Team() {
  const { data: users, loading, error, forbidden, refetch } = useUserList()

  if (forbidden) {
    return <EmptyState icon={ShieldTick} title="Admin only" hint="Ask an admin to add you to the team or grant the admin role." />
  }

  return (
    <div className="space-y-4">
      <Card
        title={`Members (${users?.length ?? 0})`}
        actions={<CreateUserInline onCreated={refetch} />}
        bodyClass="p-0"
      >
        {error && <div className="p-4"><ErrorState message={error} /></div>}
        {loading && <div className="p-4"><Spinner label="Loading team…" /></div>}
        {users && users.length > 0 && (
          <div className="divide-y divide-secondary">
            {users.map((u) => (
              <MemberRow key={u.id} user={u} onChanged={refetch} />
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

/**
 * Shows a credential the server returns exactly once.
 *
 * It is masked until the operator asks to see it, cleared when they dismiss it, and cleared when
 * the screen unmounts. Left rendered, a rotated key survived every later action on the roster and
 * stayed readable in the DOM long after the admin had moved on, which makes the "shown once" copy
 * beside it untrue.
 */
function OneTimeSecret({ label, value, onDismiss }: { label: string; value: string; onDismiss: () => void }) {
  const [revealed, setRevealed] = useState(false)
  const [copied, setCopied] = useState(false)
  const { notify } = useToast()

  useEffect(() => () => setRevealed(false), [])

  return (
    <div className="mt-2 space-y-1 rounded-md border border-secondary bg-secondary/40 px-2 py-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <Key01 className="size-3.5 shrink-0 text-medium" />
        <code className="flex-1 truncate font-mono text-[11px] text-primary">
          {revealed ? value : '•'.repeat(Math.min(value.length, 28))}
        </code>
        <button type="button" className="shrink-0 text-xs text-brand-secondary hover:underline" onClick={() => setRevealed((v) => !v)}>
          {revealed ? 'Hide' : 'Reveal'}
        </button>
        <button
          type="button"
          className="shrink-0 text-xs text-brand-secondary hover:underline"
          onClick={() => {
            void copyText(value)
              .then(() => { setCopied(true); notify('Copied. It cannot be retrieved again.', 'success') })
              .catch(() => notify('Copy failed. Reveal the value and copy it manually.', 'error'))
          }}
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
        <button type="button" aria-label={`Dismiss ${label}`} className="shrink-0 text-xs text-tertiary hover:text-primary" onClick={onDismiss}>
          Dismiss
        </button>
      </div>
      <p className="pl-5 text-[11px] font-medium text-medium">
        {label} is shown once. Once dismissed it cannot be retrieved again.
      </p>
    </div>
  )
}

/**
 * One member, with the lifecycle actions the server has always exposed and the dashboard never
 * reached: change the role, revoke access, restore it, and rotate a key that may have leaked.
 * Without these, an operator could add a person to the tenant but never take them out of it.
 *
 * The role change is an explicit edit with a Save, not a control that writes on selection. Moving
 * someone to admin, or down to read-only, is a privilege change, and a stray click should not be
 * able to make one.
 */
function MemberRow({ user, onChanged }: { user: User; onChanged: () => void }) {
  const [busy, setBusy] = useState<'role' | 'disabled' | 'key' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [rotated, setRotated] = useState<string | null>(null)
  const [editingRole, setEditingRole] = useState(false)
  const [pendingRole, setPendingRole] = useState<UserRole>(user.role)
  const [supersededBy, setSupersededBy] = useState<UserRole | null>(null)
  const roleWhenSeeded = useRef(user.role)
  const { notify } = useToast()

  // Clearing the key when the screen unmounts, so it does not outlive the route.
  useEffect(() => () => setRotated(null), [])

  // Any action on any row refetches the roster, and this row keeps its React key across that
  // refetch, so the editor can sit open while another admin moves this member. `Save role` is
  // disabled only while the selection equals the current role, and a role that changes
  // underneath re-enables it without the operator touching anything: pressing Save would then
  // write a role they never chose, over a change they never saw. Reseed to what the server now
  // holds, and say so.
  useEffect(() => {
    if (roleWhenSeeded.current === user.role) return
    roleWhenSeeded.current = user.role
    setPendingRole(user.role)
    setSupersededBy(user.role)
  }, [user.role])

  async function run(kind: 'role' | 'disabled' | 'key', action: () => Promise<void>, done: string) {
    setBusy(kind)
    setError(null)
    // A key shown for a previous action is stale context next to a new one.
    if (kind !== 'key') setRotated(null)
    try {
      await action()
      notify(done, 'success')
      onChanged()
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Action failed'
      setError(message)
      notify(message, 'error')
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="px-4 py-2 text-sm transition-colors hover:bg-secondary/30">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-primary">{user.name}</span>
        <Pill className="bg-secondary/50 text-tertiary ring-1 ring-inset ring-secondary">{user.role}</Pill>
        {user.disabled && <Pill className="bg-critical/10 text-critical ring-1 ring-inset ring-critical/25">disabled</Pill>}
        <span className="font-mono text-[11px] tabular-nums text-quaternary">{user.id}</span>

        <div className="ml-auto flex flex-wrap items-center gap-2">
          <Button
            variant="secondary"
            className="h-8 px-2.5 text-xs"
            onClick={() => { setPendingRole(user.role); setSupersededBy(null); setEditingRole((open) => !open) }}
          >
            Change role
          </Button>
          <Button
            variant="secondary"
            loading={busy === 'disabled'}
            className="h-8 px-2.5 text-xs"
            onClick={() => void run(
              'disabled',
              async () => { await api.setUserDisabled(user.id, !user.disabled) },
              user.disabled ? `${user.name} can sign in again.` : `${user.name} can no longer sign in.`,
            )}
          >
            {user.disabled ? 'Enable' : 'Disable'}
          </Button>
          <Button
            variant="secondary"
            loading={busy === 'key'}
            className="h-8 px-2.5 text-xs"
            onClick={() => void run('key', async () => {
              const { apiKey } = await api.rotateUserAPIKey(user.id)
              setRotated(apiKey)
            }, `${user.name}'s API key was rotated. The previous key no longer works.`)}
          >
            <Key01 className="size-3.5" /> Rotate key
          </Button>
        </div>
      </div>

      {editingRole && (
        <fieldset className="mt-2 rounded-md border border-secondary bg-secondary/30 px-3 py-2">
          <legend className="px-1 text-[11px] font-semibold uppercase tracking-wide text-quaternary">
            Role for {user.name}
          </legend>
          {supersededBy && (
            <p role="status" className="mb-2 text-xs text-warning-primary">
              {user.name} was moved to {supersededBy} elsewhere while this was open. The selection now
              matches the server.
            </p>
          )}
          <div className="flex flex-wrap items-center gap-3">
            {ROLE_OPTIONS.map((option) => (
              <label key={option.value} className="flex items-center gap-1.5 text-xs text-secondary">
                <input
                  type="radio"
                  name={`role-${user.id}`}
                  value={option.value}
                  checked={pendingRole === option.value}
                  onChange={() => setPendingRole(option.value as UserRole)}
                />
                {option.label}
              </label>
            ))}
            <div className="ml-auto flex items-center gap-2">
              <Button variant="ghost" className="h-8 px-2.5 text-xs" onClick={() => { setSupersededBy(null); setEditingRole(false) }}>Cancel</Button>
              <Button
                loading={busy === 'role'}
                disabled={pendingRole === user.role}
                className="h-8 px-2.5 text-xs"
                onClick={() => void run('role', async () => {
                  await api.updateUser(user.id, pendingRole)
                  setEditingRole(false)
                }, `${user.name} is now ${pendingRole}.`)}
              >
                Save role
              </Button>
            </div>
          </div>
        </fieldset>
      )}

      {error && <p className="mt-1 text-xs text-critical">{error}</p>}

      {rotated && (
        <OneTimeSecret label={`${user.name}'s new API key`} value={rotated} onDismiss={() => setRotated(null)} />
      )}
    </div>
  )
}


function CreateUserInline({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState('')
  const [role, setRole] = useState<UserRole>('member')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [issued, setIssued] = useState<{ name: string; key: string } | null>(null)
  const { notify } = useToast()

  async function submit() {
    if (!name.trim()) { setErr('Name required'); return }
    setBusy(true)
    setErr(null)
    try {
      const { user, apiKey } = await api.createUser(name.trim(), role)
      setIssued({ name: user.name, key: apiKey })
      setName('')
      onCreated()
      notify(`${user.name} added as ${role}. Copy the API key now: it is shown once.`, 'success')
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Failed'
      setErr(message)
      notify(message, 'error')
    } finally {
      setBusy(false)
    }
  }


  return (
    <div className="flex flex-col gap-2">
      {/* Wraps at narrow widths. As a single non-wrapping row the name input was squeezed to a few
          characters on a phone, so the field could not be read while it was being typed into. */}
      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={name}
          onChange={(e) => { setName(e.target.value); setErr(null); setIssued(null) }}
          placeholder="Name"
          aria-label="Name"
          className="h-9 min-w-40 flex-1 px-3 py-1.5 text-sm sm:w-56 sm:flex-none"
        />
        <Select
          value={role}
          onValueChange={(v) => setRole(v as UserRole)}
          ariaLabel="Role"
          className="h-9 w-32 text-sm"
          options={ROLE_OPTIONS}
        />
        <Button loading={busy} onClick={submit} className="h-9 px-3.5 text-sm">
          <UserPlus01 className="size-4" /> Add
        </Button>
      </div>
      {err && <span className="text-xs text-critical">{err}</span>}
      {issued && (
        <OneTimeSecret label={`${issued.name}'s API key`} value={issued.key} onDismiss={() => setIssued(null)} />
      )}
    </div>
  )
}
