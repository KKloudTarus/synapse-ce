import { Copy, KeyRound, ShieldCheck, UserPlus, Users } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, ApiError } from '../lib/api'
import type { User, UserRole } from '../lib/types'
import { Button, Card, cn, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner } from '../components/ui'

export function Team() {
  const [users, setUsers] = useState<User[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [forbidden, setForbidden] = useState(false)

  function load() {
    setError(null)
    api
      .listUsers()
      .then(setUsers)
      .catch((e) => {
        if (e instanceof ApiError && e.status === 403) setForbidden(true)
        else setError(e instanceof Error ? e.message : 'Failed to load the team')
      })
  }
  useEffect(load, [])

  return (
    <div className="mx-auto max-w-4xl animate-fade-in">
      <header className="bg-hero mb-6 rounded-xl border border-border p-6">
        <h1 className="flex items-center gap-2 text-3xl font-bold tracking-tight">
          <Users className="size-7 text-brand" /> Team
        </h1>
        <p className="mt-1.5 max-w-2xl text-sm text-mutedfg">
          Each consultant gets their own API key, so every finding edit, comment, assignment, and evidence capture is
          attributable to a real person – not a shared account.
        </p>
      </header>

      {forbidden ? (
        <EmptyState icon={ShieldCheck} title="Admin only" hint="Ask an admin to add you to the team or grant the admin role." />
      ) : (
        <>
          <div className="mb-6">
            <CreateUserForm onCreated={load} />
          </div>
          {error && <ErrorState message={error} />}
          {!users && !error && <Spinner label="Loading team…" />}
          {users && users.length > 0 && (
            <Card title="Members" bodyClass="p-0">
              <div className="divide-y divide-border">
                {users.map((u) => (
                  <div key={u.id} className="flex items-center gap-3 px-4 py-3 text-sm">
                    <span className="font-medium text-foreground">{u.name}</span>
                    <RolePill role={u.role} />
                    {u.disabled && <Pill className="bg-critical/10 text-critical ring-1 ring-inset ring-critical/25">disabled</Pill>}
                    <span className="ml-auto font-mono text-xs tabular-nums text-subtlefg">{u.id}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  )
}

function RolePill({ role }: { role: UserRole }) {
  return (
    <Pill
      className={cn(
        'ring-1 ring-inset',
        role === 'admin' ? 'bg-brand/10 text-branddim ring-brand/25' : 'bg-elevated text-mutedfg ring-border',
      )}
    >
      {role}
    </Pill>
  )
}

function CreateUserForm({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState('')
  const [role, setRole] = useState<UserRole>('member')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [issued, setIssued] = useState<{ name: string; key: string } | null>(null)
  const [copied, setCopied] = useState(false)

  async function submit() {
    if (!name.trim()) {
      setErr('Name is required.')
      return
    }
    setBusy(true)
    setErr(null)
    try {
      const { user, apiKey } = await api.createUser(name.trim(), role)
      setIssued({ name: user.name, key: apiKey })
      setName('')
      onCreated()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to create user')
    } finally {
      setBusy(false)
    }
  }

  async function copyKey() {
    if (!issued) return
    try {
      await navigator.clipboard.writeText(issued.key)
      setCopied(true)
    } catch {
      /* clipboard blocked – the key is visible to copy manually */
    }
  }

  return (
    <Card title="Add a consultant">
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Name" htmlFor="u-name">
          <Input id="u-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Jordan Rivera" />
        </Field>
        <Field label="Role">
          <Select
            value={role}
            onValueChange={(v) => setRole(v as UserRole)}
            ariaLabel="Role"
            options={[
              { value: 'member', label: 'Member' },
              { value: 'admin', label: 'Admin' },
            ]}
          />
        </Field>
        <Button loading={busy} onClick={submit} className="px-3 py-1.5">
          <UserPlus className="size-4" /> Create
        </Button>
      </div>
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
      {issued && (
        <div role="status" aria-live="polite" className="mt-4 rounded-lg border border-medium/40 bg-medium/10 p-4">
          <p className="flex items-center gap-1.5 text-sm font-medium text-foreground">
            <KeyRound className="size-4 text-medium" /> API key for {issued.name}
          </p>
          <p className="mt-1 text-xs text-mutedfg">Copy it now – it is shown once and cannot be recovered.</p>
          <div className="mt-2 flex items-center gap-2">
            <code className="flex-1 overflow-x-auto rounded-md border border-border bg-bg px-3 py-2 font-mono text-xs text-foreground">{issued.key}</code>
            <Button variant="secondary" onClick={copyKey} className="shrink-0 px-3 py-1.5">
              <Copy className="size-4" /> {copied ? 'Copied' : 'Copy'}
            </Button>
          </div>
        </div>
      )}
    </Card>
  )
}
