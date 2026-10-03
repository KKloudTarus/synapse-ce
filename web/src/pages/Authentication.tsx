import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { ConfirmDialog } from '../components/synapse/ConfirmDialog'
import { useOptionalAuth } from '../auth/AuthContext'
import { ApiError } from '../lib/api/client'
import {
  identityApi,
  type ConnectionDraft,
  type EnterpriseConnection,
  type IdentityPolicy,
  type RecoveryAlert,
} from '../lib/api/identity'

export interface AuthenticationProps {
  enabled: boolean
}

type PendingAction =
  | { kind: 'activate'; connection: EnterpriseConnection }
  | { kind: 'disable'; connection: EnterpriseConnection }
  | null

const emptyDraft: ConnectionDraft = { displayName: '', issuer: '', clientId: '', clientSecret: '' }

function messageFor(error: unknown, fallback: string): string {
  if (error instanceof ApiError && error.status === 409) {
    return 'These settings changed elsewhere. The latest values have been loaded; review them and try again.'
  }
  return error instanceof Error ? error.message : fallback
}

function formatTime(value: string | null): string {
  if (!value) return 'Not recorded'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

export function Authentication({ enabled }: AuthenticationProps) {
  const auth = useOptionalAuth()
  const [connections, setConnections] = useState<EnterpriseConnection[]>([])
  const [policy, setPolicy] = useState<IdentityPolicy | null>(null)
  const [alerts, setAlerts] = useState<RecoveryAlert[]>([])
  const [draft, setDraft] = useState<ConnectionDraft>(emptyDraft)
  const [membershipId, setMembershipId] = useState('')
  const [personId, setPersonId] = useState('')
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null)
  const [bootstrapProof, setBootstrapProof] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [pendingAction, setPendingAction] = useState<PendingAction>(null)
  const generation = useRef(0)
  const loadController = useRef<AbortController | null>(null)

  const load = useCallback(async () => {
    loadController.current?.abort()
    const requestGeneration = ++generation.current
    const controller = new AbortController()
    loadController.current = controller
    setLoading(true)
    setError(null)
    try {
      const [nextConnections, nextPolicy, nextAlerts] = await Promise.all([
        identityApi.connections(controller.signal),
        identityApi.policy(controller.signal),
        identityApi.alerts(controller.signal),
      ])
      if (generation.current !== requestGeneration) return
      setConnections(nextConnections)
      setPolicy(nextPolicy)
      setAlerts(nextAlerts)
    } catch (cause) {
      if (cause instanceof DOMException && cause.name === 'AbortError') return
      if (generation.current === requestGeneration) setError(messageFor(cause, 'Could not load authentication settings.'))
    } finally {
      if (generation.current === requestGeneration) setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (!enabled) {
      setLoading(false)
      return
    }
    void load()
    return () => {
      generation.current += 1
      loadController.current?.abort()
      loadController.current = null
    }
  }, [enabled, load])

  const run = useCallback(async (action: () => Promise<unknown>, success: string, refresh = true) => {
    setSaving(true)
    setError(null)
    setNotice(null)
    try {
      await action()
      setNotice(success)
      if (refresh) await load()
    } catch (cause) {
      setError(messageFor(cause, 'Authentication settings update failed. Reload and try again.'))
      if (cause instanceof ApiError && cause.status === 409) void load()
    } finally {
      setSaving(false)
    }
  }, [load])

  async function verifyAdministratorSession() {
    await run(async () => {
      const proof = await identityApi.bootstrap()
      setBootstrapProof(proof)
    }, 'Administrator session verified for this page. It expires shortly.', false)
  }
  async function testConnection(connection: EnterpriseConnection) {
    await run(async () => {
      const result = await identityApi.testConnection(connection.id, bootstrapProof ?? undefined)
      globalThis.location.assign(result.authorizationURL)
    }, 'Connection test started.', false)
  }

  async function savePolicy() {
    if (!policy) return
    const prior = policy
    const optimistic = { ...prior, version: prior.version + 1 }
    setPolicy(optimistic)
    setSaving(true)
    setError(null)
    setNotice(null)
    try {
      await identityApi.savePolicy(prior, bootstrapProof ?? undefined)
      setNotice('Sign-in requirement saved.')
      await load()
    } catch (cause) {
      setPolicy(prior)
      setError(messageFor(cause, 'Could not save the sign-in requirement.'))
      if (cause instanceof ApiError && cause.status === 409) void load()
    } finally {
      setSaving(false)
    }
  }

  async function confirmConnectionAction() {
    if (!pendingAction) return
    const { connection } = pendingAction
    const action = pendingAction.kind === 'activate'
      ? () => identityApi.activateConnection(connection.id, connection.draftRevision, connection.version, bootstrapProof ?? undefined)
      : () => identityApi.disableConnection(connection.id, connection.version, bootstrapProof ?? undefined)
    const success = pendingAction.kind === 'activate' ? 'Connection activated.' : 'Connection disabled.'
    setPendingAction(null)
    await run(action, success)
  }

  async function createRecoveryCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setRecoveryCode(null)
    await run(async () => {
      const code = await identityApi.createRecoveryCode({ membershipId, personId }, bootstrapProof ?? undefined)
      setRecoveryCode(code)
      setMembershipId('')
      setPersonId('')
    }, 'Recovery code created. Copy it now; it will not be shown again.', false)
  }

  if (!enabled) {
    return (
      <section aria-labelledby="authentication-heading">
        <h1 id="authentication-heading" className="text-2xl font-bold text-primary">Authentication</h1>
        <p className="mt-2 text-secondary">Enterprise identity is not enabled for this organization.</p>
      </section>
    )
  }

  return (
    <section aria-labelledby="authentication-heading" className="max-w-4xl space-y-8">
      <div>
        <h1 id="authentication-heading" className="text-2xl font-bold text-primary">Authentication</h1>
        <p className="mt-2 text-secondary">Manage organization sign-in connections, recovery controls, and their operational alerts.</p>
      </div>

      {error ? <div role="alert" className="rounded-md border border-error-subtle bg-error-primary p-4 text-error-primary">{error} <button type="button" className="underline" onClick={() => void load()}>Retry</button></div> : null}
      {notice ? <p role="status" className="rounded-md bg-success-primary p-3 text-success-primary">{notice}</p> : null}

      <section aria-labelledby="administrator-proof-heading" className="rounded-lg border border-secondary p-5">
        <h2 id="administrator-proof-heading" className="text-lg font-semibold text-primary">Administrator verification</h2>
        <p className="mt-1 text-sm text-secondary">Sensitive changes require a current administrator proof. The proof is held only in this page while it is open.</p>
        {auth?.currentUser?.credentialKind === 'bootstrap' ? <button type="button" disabled={saving} className="mt-4 rounded border px-3 py-2 disabled:opacity-50" onClick={() => void verifyAdministratorSession()}>{bootstrapProof ? 'Refresh administrator verification' : 'Verify administrator session'}</button> : <p className="mt-3 text-sm text-secondary">Signed-in administrators use their current SSO proof. If it has expired, reauthenticate from your profile before changing access.</p>}
      </section>

      {loading ? (
        <section aria-busy="true"><p className="text-secondary">Loading authentication settings…</p></section>
      ) : (
        <>
          <section aria-labelledby="policy-heading" className="rounded-lg border border-secondary p-5">
            <h2 id="policy-heading" className="text-lg font-semibold text-primary">Sign-in requirement</h2>
            <p className="mt-1 text-sm text-secondary">Required mode admits browser sessions only after approved organization SSO.</p>
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <label><input type="radio" name="sso-requirement" checked={policy?.requirement === 'optional'} onChange={() => setPolicy((current) => current && { ...current, requirement: 'optional' })} /> Optional</label>
              <label><input type="radio" name="sso-requirement" checked={policy?.requirement === 'required'} onChange={() => setPolicy((current) => current && { ...current, requirement: 'required' })} /> Required</label>
              <button type="button" disabled={!policy || saving} className="rounded bg-brand-primary px-3 py-2 text-white disabled:opacity-50" onClick={() => void savePolicy()}>Save policy</button>
              <button type="button" disabled={saving} className="rounded border px-3 py-2 disabled:opacity-50" onClick={() => void run(() => identityApi.rehearse(bootstrapProof ?? undefined), 'Recovery rehearsal recorded.')}>Rehearse recovery</button>
              <button type="button" disabled={saving} className="rounded border px-3 py-2 disabled:opacity-50" onClick={() => void run(() => identityApi.testAlert(bootstrapProof ?? undefined), 'Recovery alert test requested.')}>Test alert</button>
            </div>
            <dl className="mt-4 grid gap-2 text-sm text-secondary sm:grid-cols-3">
              <div><dt className="font-medium text-primary">Last rehearsal</dt><dd>{formatTime(policy?.rehearsedAt ?? null)}</dd></div>
              <div><dt className="font-medium text-primary">Alert delivery</dt><dd>{policy?.alertConfigured ? 'Configured' : 'Not configured'}</dd></div>
              <div><dt className="font-medium text-primary">Grace cutoff</dt><dd>{formatTime(policy?.graceCutoff ?? null)}</dd></div>
            </dl>
          </section>

          <section aria-labelledby="connections-heading" className="rounded-lg border border-secondary p-5">
            <h2 id="connections-heading" className="text-lg font-semibold text-primary">Approved connections</h2>
            {connections.length === 0 ? <p className="mt-2 text-secondary">No approved connections yet.</p> : (
              <ul className="mt-3 space-y-3">
                {connections.map((connection) => (
                  <li key={connection.id} className="flex flex-wrap items-center justify-between gap-3 rounded border border-secondary p-3">
                    <span>
                      <strong>{connection.displayName}</strong>
                      <span className="ml-2 text-sm text-secondary">{connection.enabled ? 'Active' : 'Draft'} · revision {connection.draftRevision} · {connection.testPassed ? 'tested' : 'not tested'}</span>
                    </span>
                    <span className="flex gap-2">
                      <button type="button" disabled={saving} className="rounded border px-2 py-1 disabled:opacity-50" onClick={() => void testConnection(connection)}>Test</button>
                      <button type="button" disabled={saving || connection.draftRevision === 0 || connection.version === 0} className="rounded border px-2 py-1 disabled:opacity-50" onClick={() => setPendingAction({ kind: 'activate', connection })}>Activate</button>
                      <button type="button" disabled={saving || !connection.enabled || connection.version === 0} className="rounded border px-2 py-1 disabled:opacity-50" onClick={() => setPendingAction({ kind: 'disable', connection })}>Disable</button>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <form className="rounded-lg border border-secondary p-5" onSubmit={(event) => { event.preventDefault(); void run(async () => { await identityApi.draftConnection(draft, bootstrapProof ?? undefined); setDraft(emptyDraft) }, 'Connection draft saved.') }}>
            <h2 className="text-lg font-semibold text-primary">Create connection draft</h2>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              {([
                ['displayName', 'Display name', 'text'],
                ['issuer', 'Issuer URL', 'url'],
                ['clientId', 'Client ID', 'text'],
                ['clientSecret', 'Client secret', 'password'],
              ] as const).map(([field, label, type]) => (
                <label key={field} className="grid gap-1 text-sm text-primary">{label}
                  <input required type={type} value={draft[field]} onChange={(event) => setDraft((current) => ({ ...current, [field]: event.target.value }))} className="rounded border border-secondary px-3 py-2" />
                </label>
              ))}
            </div>
            <button disabled={saving} className="mt-4 rounded bg-brand-primary px-3 py-2 text-white disabled:opacity-50">Save draft</button>
          </form>

          <section aria-labelledby="recovery-heading" className="rounded-lg border border-secondary p-5">
            <h2 id="recovery-heading" className="text-lg font-semibold text-primary">Emergency recovery</h2>
            <p className="mt-1 text-sm text-secondary">Generate a one-time activation code for a specific membership and person.</p>
            <form className="mt-4 grid gap-3 sm:grid-cols-2" onSubmit={(event) => { void createRecoveryCode(event) }}>
              <label className="grid gap-1 text-sm text-primary">Membership ID<input required value={membershipId} onChange={(event) => setMembershipId(event.target.value)} className="rounded border border-secondary px-3 py-2" /></label>
              <label className="grid gap-1 text-sm text-primary">Person ID<input required value={personId} onChange={(event) => setPersonId(event.target.value)} className="rounded border border-secondary px-3 py-2" /></label>
              <button disabled={saving} className="justify-self-start rounded border px-3 py-2 disabled:opacity-50">Generate recovery code</button>
            </form>
            {recoveryCode ? <div role="status" className="mt-4 rounded border border-warning-subtle bg-warning-primary p-3 text-primary"><p className="font-medium">Copy this recovery code now. It will disappear when this page reloads.</p><code className="mt-2 block break-all select-all rounded bg-secondary p-2">{recoveryCode}</code><button type="button" className="mt-2 underline" onClick={() => setRecoveryCode(null)}>I have copied it</button></div> : null}
          </section>

          <section aria-labelledby="alerts-heading" className="rounded-lg border border-secondary p-5">
            <h2 id="alerts-heading" className="text-lg font-semibold text-primary">Recovery alerts</h2>
            {alerts.length === 0 ? <p className="mt-2 text-secondary">No recovery alerts have been recorded.</p> : (
              <ul className="mt-3 space-y-2">
                {alerts.map((alert) => <li key={alert.id} className="rounded border border-secondary p-3 text-sm text-secondary"><strong className="text-primary">{alert.state || 'pending'}</strong> · attempts {alert.attempts}/{alert.maxAttempts} · created {formatTime(alert.createdAt || null)}</li>)}
              </ul>
            )}
          </section>
        </>
      )}

      <ConfirmDialog
        open={pendingAction !== null}
        title={pendingAction?.kind === 'activate' ? 'Activate identity connection?' : 'Disable identity connection?'}
        description={pendingAction?.kind === 'activate'
          ? 'Activation changes the organization connection used for sign-in. The tested draft revision will become active.'
          : 'Disabling this connection prevents new sign-ins through it. Existing sessions are governed by their server-side policy.'}
        confirmLabel={pendingAction?.kind === 'activate' ? 'Activate connection' : 'Disable connection'}
        tone={pendingAction?.kind === 'activate' ? 'brand' : 'destructive'}
        busy={saving}
        onConfirm={() => { void confirmConnectionAction() }}
        onCancel={() => setPendingAction(null)}
      />
    </section>
  )
}

export default Authentication
