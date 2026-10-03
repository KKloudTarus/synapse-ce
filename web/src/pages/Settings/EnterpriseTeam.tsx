import { useCallback, useEffect, useRef, useState } from 'react'
import { useOptionalAuth } from '../../auth/AuthContext'
import { ConfirmDialog } from '../../components/synapse/ConfirmDialog'
import { ApiError } from '../../lib/api/errors'
import { identityAdministration, type EnterpriseInvitation, type EnterpriseMember } from '../../lib/api/identityAdministration'

const roles = ['member', 'consultant', 'reviewer', 'readonly', 'integration_admin', 'admin']
type Pending = { member?: EnterpriseMember; invitation?: EnterpriseInvitation; kind: 'suspend' | 'reactivate' | 'revoke' | 'change_role'; role?: string } | null
type Failure = { message: string; retryable: boolean }

function failure(cause: unknown): Failure {
  if (cause instanceof ApiError) {
    if (cause.status === 401) return { message: 'Your administrator session has expired. Reauthenticate, then retry.', retryable: false }
    if (cause.status === 403) return { message: 'You are not permitted to change this organization’s access.', retryable: false }
    if (cause.status === 409) return { message: 'This record changed elsewhere. Reload the team and try again.', retryable: true }
    if (cause.status === 0 || cause.status >= 500) return { message: 'The identity service is temporarily unavailable. Retry the request.', retryable: true }
  }
  return { message: cause instanceof Error ? cause.message : 'The request could not be completed.', retryable: false }
}

export function EnterpriseTeam() {
  const auth = useOptionalAuth()
  const [members, setMembers] = useState<EnterpriseMember[]>([])
  const [invitations, setInvitations] = useState<EnterpriseInvitation[]>([])
  const [bootstrapEligibility, setBootstrapEligibility] = useState<string>()
  const [pending, setPending] = useState<Pending>(null)
  const [error, setError] = useState<Failure | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [code, setCode] = useState<string>()
  const [revealed, setRevealed] = useState(false)
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('member')
  const loadGeneration = useRef(0)
  const mutationGeneration = useRef(0)
  const mounted = useRef(true)
  const loadController = useRef<AbortController | null>(null)
  const retryAction = useRef<(() => void) | null>(null)

  const load = useCallback(async () => {
    const attempt = ++loadGeneration.current
    loadController.current?.abort()
    const controller = new AbortController()
    loadController.current = controller
    if (mounted.current) { setLoading(true); setError(null); setMembers([]); setInvitations([]) }
    try {
      const [nextMembers, nextInvitations] = await Promise.all([
        identityAdministration.roster(controller.signal), identityAdministration.invitations(controller.signal),
      ])
      if (!mounted.current || attempt !== loadGeneration.current) return
      setMembers(nextMembers); setInvitations(nextInvitations); retryAction.current = () => { void load() }
    } catch (cause) {
      if (!mounted.current || attempt !== loadGeneration.current || (cause instanceof DOMException && cause.name === 'AbortError')) return
      setError(failure(cause)); retryAction.current = () => { void load() }
    } finally { if (mounted.current && attempt === loadGeneration.current) setLoading(false) }
  }, [])

  useEffect(() => {
    mounted.current = true
    void load()
    return () => { mounted.current = false; loadController.current?.abort() }
  }, [load])

  const run = useCallback(async (action: () => Promise<void>) => {
    const attempt = ++mutationGeneration.current
    setBusy(true); setError(null)
    retryAction.current = () => { void run(action) }
    try {
      await action()
      if (!mounted.current || attempt !== mutationGeneration.current) return
      await load()
    } catch (cause) {
      if (mounted.current && attempt === mutationGeneration.current) setError(failure(cause))
    } finally { if (mounted.current && attempt === mutationGeneration.current) setBusy(false) }
  }, [load])

  const canBootstrap = auth?.currentUser?.credentialKind === 'bootstrap'
  const recentAuth = auth?.currentUser?.recentAuth !== false
  const proof = bootstrapEligibility
  function acquireBootstrap() { void run(async () => { setBootstrapEligibility(await identityAdministration.bootstrap()) }) }
  function confirm() {
    if (!pending) return
    const next = pending
    setPending(null)
    void run(async () => {
      if (next.invitation) await identityAdministration.revokeInvitation(next.invitation.id, next.invitation.version, proof)
      else if (next.member) {
        const kind = next.kind === 'change_role' ? 'change_role' : next.kind === 'suspend' ? 'suspend' : 'reactivate'
        await identityAdministration.change(next.member.id, kind, next.member.version, next.role, proof)
      }
    })
  }
  function createInvitation() {
    void run(async () => {
      const result = await identityAdministration.createInvitation(email, role, proof) as { code?: unknown }
      if (typeof result.code !== 'string' || result.code === '') throw new Error('The server did not return an invitation code.')
      setCode(result.code); setRevealed(false); setEmail('')
    })
  }

  const button = 'rounded-lg bg-brand-solid px-3 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-brand-solid_hover disabled:cursor-not-allowed disabled:opacity-50'
  const secondaryButton = 'rounded-lg border border-secondary bg-primary px-3 py-2 text-sm font-medium text-secondary transition hover:bg-secondary disabled:cursor-not-allowed disabled:opacity-50'
  const select = 'min-w-40 rounded-lg border border-secondary bg-primary px-3 py-2 text-sm text-primary shadow-sm focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20 disabled:opacity-50'
  return <section className="space-y-6" aria-labelledby="enterprise-members-heading">
    <header className="space-y-1"><h2 id="enterprise-members-heading" className="text-xl font-semibold text-primary">Enterprise members</h2><p className="text-sm text-tertiary">Manage organization access and invitation-only membership.</p></header>
    {canBootstrap ? <button type="button" className={secondaryButton} disabled={busy} onClick={acquireBootstrap}>{proof ? 'Refresh administrator verification' : 'Verify administrator session'}</button> : null}
    {!canBootstrap && !recentAuth ? <p className="rounded-lg border border-warning-subtle bg-warning-primary/10 p-3 text-sm text-warning-primary">Reauthenticate with an approved provider before changing access.</p> : null}
    {error ? <p role="alert" className="rounded-lg border border-error-subtle bg-error-primary/10 p-3 text-sm text-error-primary">{error.message} {error.retryable ? <button type="button" className="ml-2 font-semibold underline" disabled={busy} onClick={() => retryAction.current?.()}>Retry</button> : null}</p> : null}
    {loading ? <p role="status" className="rounded-xl border border-secondary bg-secondary/30 p-5 text-sm text-tertiary">Loading enterprise team…</p> : <>
      <section className="overflow-hidden rounded-xl border border-secondary bg-primary" aria-label="Enterprise members"><div className="border-b border-secondary px-4 py-3 text-sm font-semibold text-primary">Members</div>
        {members.length ? <div className="divide-y divide-secondary">{members.map((member) => <article key={member.id} className="flex flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:justify-between"><div><p className="font-medium text-primary">{member.name}</p><p className="text-sm text-tertiary">{member.role} · {member.state}</p></div><div className="flex flex-col gap-2 sm:flex-row"><select aria-label={`Role for ${member.name}`} className={select} value={member.role} disabled={busy} onChange={(event) => setPending({ member, kind: 'change_role', role: event.target.value })}>{roles.map((item) => <option key={item} value={item}>{item}</option>)}</select><button type="button" className={secondaryButton} disabled={busy} onClick={() => setPending({ member, kind: member.state === 'active' ? 'suspend' : 'reactivate' })}>{member.state === 'active' ? 'Suspend' : 'Reactivate'}</button></div></article>)}</div> : <p className="px-4 py-6 text-sm text-tertiary">No enterprise members yet.</p>}</section>
      <section className="space-y-4 rounded-xl border border-secondary bg-primary p-4 sm:p-5"><div><h3 className="font-semibold text-primary">Create invitation</h3><p className="mt-1 text-sm text-tertiary">The code is shown once after creation.</p></div><div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_11rem_auto]"><label className="sr-only" htmlFor="enterprise-invitation-email">Invitation email</label><input id="enterprise-invitation-email" aria-label="Invitation email" className="rounded-lg border border-secondary bg-primary px-3 py-2 text-sm text-primary shadow-sm focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20" type="email" value={email} disabled={busy} onChange={(event) => setEmail(event.target.value)} /><label className="sr-only" htmlFor="enterprise-invitation-role">Invitation role</label><select id="enterprise-invitation-role" aria-label="Invitation role" className={select} value={role} disabled={busy} onChange={(event) => setRole(event.target.value)}>{roles.map((item) => <option key={item} value={item}>{item}</option>)}</select><button type="button" className={button} disabled={!email || busy} onClick={createInvitation}>Create invitation</button></div>
        {code ? <div role="status" className="rounded-lg border border-warning-subtle bg-warning-primary/10 p-3"><div className="flex flex-wrap items-center gap-2"><code className="min-w-0 break-all rounded bg-primary px-2 py-1 text-sm text-primary">{revealed ? code : '•'.repeat(Math.min(28, code.length))}</code><button type="button" className={secondaryButton} onClick={() => setRevealed(!revealed)}>{revealed ? 'Hide' : 'Reveal'}</button><button type="button" className={secondaryButton} onClick={() => { setCode(undefined); setRevealed(false) }}>Dismiss</button></div><p className="mt-2 text-sm text-tertiary">Copy this code now. It cannot be retrieved again.</p></div> : null}</section>
      <section className="overflow-hidden rounded-xl border border-secondary bg-primary"><div className="border-b border-secondary px-4 py-3"><h3 className="font-semibold text-primary">Invitations</h3></div>{invitations.length ? <div className="divide-y divide-secondary">{invitations.map((invitation) => <div key={invitation.id} className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"><p className="min-w-0 break-all text-sm text-primary">{invitation.recipient}<span className="text-tertiary"> · {invitation.role}</span></p><button type="button" className={secondaryButton} disabled={busy} onClick={() => setPending({ invitation, kind: 'revoke' })}>Revoke</button></div>)}</div> : <p className="px-4 py-6 text-sm text-tertiary">No pending invitations.</p>}</section>
    </>}
    <ConfirmDialog open={pending !== null} title="Confirm enterprise access change" description="The server records this access change." confirmLabel="Confirm" busy={busy} error={null} onCancel={() => setPending(null)} onConfirm={confirm} />
  </section>
}
