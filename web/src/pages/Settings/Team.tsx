import { Key01, ShieldTick, UserPlus01 } from '@untitledui/icons'
import { useState } from 'react'
import { api } from '../../lib/api'
import type { UserRole } from '../../lib/types'
import { Button, Card, cn, EmptyState, ErrorState, Input, Pill, Select, Spinner } from '../../components/ui'
import { useUserList } from '../../hooks'

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
              <div key={u.id} className="flex items-center gap-2 px-4 py-2 text-sm hover:bg-secondary/30 transition-colors">
                <span className="font-medium text-primary">{u.name}</span>
                <RolePill role={u.role} />
                {u.disabled && <Pill className="bg-critical/10 text-critical ring-1 ring-inset ring-critical/25">disabled</Pill>}
                <span className="ml-auto font-mono text-[11px] tabular-nums text-quaternary">{u.id}</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

function RolePill({ role }: { role: UserRole }) {
  return (
    <Pill
      className={cn(
        'ring-1 ring-inset',
        role === 'admin' ? 'bg-brand-primary/10 text-brand-secondary ring-brand-primary/25' : 'bg-secondary/50 text-tertiary ring-secondary',
      )}
    >
      {role}
    </Pill>
  )
}

function CreateUserInline({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState('')
  const [role, setRole] = useState<UserRole>('member')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [issued, setIssued] = useState<{ name: string; key: string } | null>(null)
  const [copied, setCopied] = useState(false)

  async function submit() {
    if (!name.trim()) { setErr('Name required'); return }
    setBusy(true)
    setErr(null)
    try {
      const { user, apiKey } = await api.createUser(name.trim(), role)
      setIssued({ name: user.name, key: apiKey })
      setName('')
      onCreated()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed')
    } finally {
      setBusy(false)
    }
  }

  async function copyKey() {
    if (!issued) return
    try { await navigator.clipboard.writeText(issued.key); setCopied(true) } catch {}
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <Input
          value={name}
          onChange={(e) => { setName(e.target.value); setErr(null); setIssued(null); setCopied(false) }}
          placeholder="Name"
          className="h-9 w-56 px-3 py-1.5 text-sm"
        />
        <Select
          value={role}
          onValueChange={(v) => setRole(v as UserRole)}
          ariaLabel="Role"
          className="h-9 w-32 text-sm"
          options={[
            { value: 'member', label: 'Member' },
            { value: 'admin', label: 'Admin' },
          ]}
        />
        <Button loading={busy} onClick={submit} className="h-9 px-3.5 text-sm">
          <UserPlus01 className="size-4" /> Add
        </Button>
      </div>
      {err && <span className="text-xs text-critical">{err}</span>}
      {issued && (
        <div className="flex items-center gap-2 rounded-md border border-secondary bg-secondary/40 px-2 py-1.5">
          <Key01 className="size-3.5 text-medium shrink-0" />
          <code className="flex-1 truncate font-mono text-[11px] text-primary">{issued.key}</code>
          <button type="button" onClick={copyKey} className="text-xs text-brand-secondary hover:underline shrink-0">
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      )}
    </div>
  )
}
