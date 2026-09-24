import { Key01, ShieldTick, UserPlus01 } from '@untitledui/icons'
import { copyText } from '../../lib/clipboard'
import { useState } from 'react'
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
  const [copied, setCopied] = useState(false)
  const [editingRole, setEditingRole] = useState(false)
  const [pendingRole, setPendingRole] = useState<UserRole>(user.role)
  const { notify } = useToast()

  async function run(kind: 'role' | 'disabled' | 'key', action: () => Promise<void>, done: string) {
    setBusy(kind)
    setError(null)
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
            onClick={() => { setPendingRole(user.role); setEditingRole((open) => !open) }}
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
              setCopied(false)
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
              <Button variant="ghost" className="h-8 px-2.5 text-xs" onClick={() => setEditingRole(false)}>Cancel</Button>
              <Button
                loading={busy === 'role'}
                disabled={pendingRole === user.role}
                className="h-8 px-2.5 text-xs"
                onClick={() => void run('role', async () => {
                  await api.updateUser(user.id, user.name, pendingRole)
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
        <div className="mt-2 space-y-1 rounded-md border border-secondary bg-secondary/40 px-2 py-1.5">
          <div className="flex items-center gap-2">
            <Key01 className="size-3.5 shrink-0 text-medium" />
            <code className="flex-1 truncate font-mono text-[11px] text-primary">{rotated}</code>
            <button
              type="button"
              className="shrink-0 text-xs text-brand-secondary hover:underline"
              onClick={() => { void copyText(rotated).then(() => setCopied(true)).catch(() => setCopied(false)) }}
            >
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          {/* The server stores only the hash, so this is the only time the key can be read. */}
          <p className="pl-5 text-[11px] font-medium text-medium">
            Shown once. The previous key stopped working immediately.
          </p>
        </div>
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
  const [copied, setCopied] = useState(false)
  const [copyError, setCopyError] = useState<string | null>(null)
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

  async function copyKey() {
    if (!issued) return
    try {
      await copyText(issued.key)
      setCopied(true)
      setCopyError(null)
      notify('API key copied to the clipboard.', 'success')
    } catch {
      // Clipboard writes reject in non-secure contexts or when the permission is
      // denied — say so instead of leaving the button silently unchanged.
      setCopyError('Copy failed. Select the key above and copy it manually.')
    }
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <Input
          value={name}
          onChange={(e) => { setName(e.target.value); setErr(null); setIssued(null); setCopied(false); setCopyError(null) }}
          placeholder="Name"
          aria-label="Name"
          className="h-9 w-56 px-3 py-1.5 text-sm"
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
        <div className="space-y-1 rounded-md border border-secondary bg-secondary/40 px-2 py-1.5">
          <div className="flex items-center gap-2">
            <Key01 className="size-3.5 text-medium shrink-0" />
            <code className="flex-1 truncate font-mono text-[11px] text-primary">{issued.key}</code>
            <button type="button" onClick={copyKey} className="text-xs text-brand-secondary hover:underline shrink-0">
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          {/* The server never returns this key again, so say so where it is read. */}
          <p className="pl-5 text-[11px] font-medium text-medium">
            Shown once. Copy it now: {issued.name}'s key cannot be retrieved again.
          </p>
        </div>
      )}
      {copyError && <span className="text-xs text-critical">{copyError}</span>}
    </div>
  )
}
