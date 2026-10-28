import { EntraDiscoverySettings, entraDirectory } from './EntraDiscoverySettings'
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { type ProvisioningDraft, type InitialOrganizationProvisioning as ProvisioningSnapshot, identityProvisioningApi } from '../lib/api/identityProvisioning'

type DraftFields = Omit<ProvisioningDraft, 'capability' | 'version'>

const emptyDraft: DraftFields = { displayName: '', issuer: '', clientId: '', clientSecret: '', auth0OrganizationId: '' }

function errorMessage(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

function isClosed(snapshot: ProvisioningSnapshot | null): boolean {
  return snapshot?.state === 'closed'
}

/** Scoped capability and client secret remain only in React memory. */
export function InitialOrganizationProvisioning() {
  const [searchParams] = useSearchParams()
  const callbackTenant = searchParams.get('provisioning_tenant') ?? ''
  const [tenantId, setTenantId] = useState(callbackTenant)
  const [recipient, setRecipient] = useState('')
  const [draft, setDraft] = useState<DraftFields>(emptyDraft)
  const [snapshot, setSnapshot] = useState<ProvisioningSnapshot | null>(null)
  const [capability, setCapability] = useState<string | null>(null)
  const [invitationCode, setInvitationCode] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const generation = useRef(0)
  const autoResume = useRef(new Set<string>())
  const current = useCallback((requestGeneration: number) => generation.current === requestGeneration, [])

  const applySnapshot = useCallback((next: ProvisioningSnapshot, requestGeneration: number) => {
    if (!current(requestGeneration)) return false
    setSnapshot(next)
    setTenantId(next.tenantId)
    setRecipient(next.recipient)
    if (next.connection) {
      setDraft((value) => ({ ...value, displayName: next.connection!.displayName, issuer: next.connection!.issuer, clientId: next.connection!.clientId, auth0OrganizationId: next.connection!.auth0OrganizationId, entraDiscoveryMode: next.connection!.draftEntraDiscoveryMode ?? next.connection!.entraDiscoveryMode ?? '' }))
    }
    if (isClosed(next)) {
      setCapability(null)
      setInvitationCode(null)
      setDraft(emptyDraft)
    }
    return true
  }, [current])

  const begin = useCallback(async (resume: boolean, callbackTarget?: string) => {
    const target = (callbackTarget ?? tenantId).trim()
    const firstRecipient = recipient.trim()
    if (!target) return setError('Enter the target organization ID before beginning provisioning.')
    if (!resume && !firstRecipient) return setError('Enter the first administrator email before beginning provisioning.')
    const requestGeneration = ++generation.current
    setPending(true)
    setError(null)
    setNotice(null)
    setInvitationCode(null)
    try {
      const result = await identityProvisioningApi.begin(target, resume ? '' : firstRecipient)
      if (!current(requestGeneration)) return
      setCapability(result.capability)
      applySnapshot(result.provisioning, requestGeneration)
      setNotice(resume ? 'Provisioning state resumed.' : 'Provisioning reserved. Save and test the connection before activation.')
    } catch (cause) {
      if (current(requestGeneration)) setError(errorMessage(cause, 'Could not begin provisioning.'))
    } finally {
      if (current(requestGeneration)) setPending(false)
    }
  }, [applySnapshot, current, recipient, tenantId])

  useEffect(() => {
    if (!callbackTenant || autoResume.current.has(callbackTenant)) return
    autoResume.current.add(callbackTenant)
    setTenantId(callbackTenant)
    void begin(true, callbackTenant)
  }, [begin, callbackTenant])
  useEffect(() => () => { generation.current += 1; autoResume.current.clear() }, [])

  const refresh = useCallback(async () => {
    if (!capability) return
    const requestGeneration = ++generation.current
    setPending(true); setError(null); setNotice(null)
    try {
      const next = await identityProvisioningApi.status(capability)
      if (applySnapshot(next, requestGeneration)) setNotice('Provisioning status refreshed.')
    } catch (cause) {
      if (current(requestGeneration)) setError(errorMessage(cause, 'Could not refresh provisioning status.'))
    } finally {
      if (current(requestGeneration)) setPending(false)
    }
  }, [applySnapshot, capability, current])

  const saveDraft = useCallback(async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!capability || !snapshot) return
    const requestGeneration = ++generation.current
    setPending(true); setError(null); setNotice(null)
    try {
      const next = await identityProvisioningApi.draft({ ...draft, capability, version: snapshot.connection?.version ?? 0 })
      if (applySnapshot(next, requestGeneration)) setNotice('Connection draft saved. Test the actual provider before activation.')
    } catch (cause) {
      if (current(requestGeneration)) setError(errorMessage(cause, 'Could not save the connection draft.'))
    } finally {
      if (current(requestGeneration)) { setDraft((value) => ({ ...value, clientSecret: '' })); setPending(false) }
    }
  }, [applySnapshot, capability, current, draft, snapshot])

  const testProvider = useCallback(async () => {
    if (!capability) return
    const requestGeneration = ++generation.current
    setPending(true); setError(null); setNotice(null)
    try {
      const result = await identityProvisioningApi.test(capability)
      if (!current(requestGeneration)) return
      globalThis.location.assign(result.authorizationURL)
    } catch (cause) {
      if (current(requestGeneration)) setError(errorMessage(cause, 'Could not start the provider test.'))
    } finally {
      if (current(requestGeneration)) setPending(false)
    }
  }, [capability, current])

  const activate = useCallback(async () => {
    if (!capability || !snapshot?.connection) return
    const requestGeneration = ++generation.current
    setPending(true); setError(null); setNotice(null)
    try {
      const next = await identityProvisioningApi.activate(capability, snapshot.connection.draftRevision, snapshot.connection.version)
      if (applySnapshot(next, requestGeneration)) setNotice('Connection activated. Review the first administrator invitation before creating it.')
    } catch (cause) {
      if (current(requestGeneration)) setError(errorMessage(cause, 'Could not activate the connection.'))
    } finally {
      if (current(requestGeneration)) setPending(false)
    }
  }, [applySnapshot, capability, current, snapshot])

  const createInvitation = useCallback(async () => {
    if (!capability) return
    const requestGeneration = ++generation.current
    setPending(true); setError(null); setNotice(null)
    try {
      const result = await identityProvisioningApi.invitation(capability)
      if (!applySnapshot(result.provisioning, requestGeneration)) return
      setInvitationCode(result.code)
      setNotice('First administrator invitation created. Store the code only with the intended recipient.')
    } catch (cause) {
      if (current(requestGeneration)) setError(errorMessage(cause, 'Could not create the first administrator invitation.'))
    } finally {
      if (current(requestGeneration)) setPending(false)
    }
  }, [applySnapshot, capability, current])

  const cancel = useCallback(() => {
    generation.current += 1
    setCapability(null); setSnapshot(null); setInvitationCode(null); setDraft(emptyDraft); setError(null); setNotice(null)
  }, [])

  const reserved = snapshot !== null
  const connection = snapshot?.connection ?? null
  const mayTest = connection !== null && !connection.testPassed && !connection.enabled
  const mayActivate = connection !== null && connection.testPassed && !connection.enabled
  const mayInvite = connection?.enabled === true && !isClosed(snapshot)

  if (isClosed(snapshot)) return <section aria-labelledby="initial-provisioning-heading" className="max-w-3xl space-y-4"><h1 id="initial-provisioning-heading" className="text-2xl font-bold text-primary">Initial organization provisioning</h1><p role="status" className="rounded-md bg-success-primary p-3 text-success-primary">Provisioning is complete. The scoped capability has been discarded.</p></section>

  return <section aria-labelledby="initial-provisioning-heading" className="max-w-3xl space-y-6">
    <div><h1 id="initial-provisioning-heading" className="text-2xl font-bold text-primary">Initial organization provisioning</h1><p className="mt-2 text-secondary">This creates one initial identity connection and one administrator invitation for a new organization. Existing organizations, memberships, and roles are not changed.</p></div>
    {error ? <div role="alert" className="rounded-md border border-error-subtle bg-error-primary p-4 text-error-primary">{error} {reserved ? <button type="button" className="underline" disabled={pending} onClick={() => void begin(true)}>Resume provisioning</button> : null}</div> : null}
    {notice ? <p role="status" className="rounded-md bg-success-primary p-3 text-success-primary">{notice}</p> : null}
    {!reserved ? <form className="space-y-4 rounded-lg border border-secondary p-5" onSubmit={(event) => { event.preventDefault(); void begin(false) }}><label className="grid gap-1 text-sm text-primary">Target organization ID<input required value={tenantId} onChange={(event) => setTenantId(event.target.value)} autoComplete="off" className="rounded border border-secondary bg-primary px-3 py-2 text-primary" /></label><label className="grid gap-1 text-sm text-primary">First administrator email<input required type="email" value={recipient} onChange={(event) => setRecipient(event.target.value)} autoComplete="email" className="rounded border border-secondary bg-primary px-3 py-2 text-primary" /></label><button type="submit" disabled={pending} className="rounded bg-brand-solid px-3 py-2 text-white disabled:opacity-50">{pending ? 'Beginning…' : 'Begin provisioning'}</button></form> : <>
      <section aria-labelledby="reserved-provisioning-heading" className="rounded-lg border border-secondary p-5"><h2 id="reserved-provisioning-heading" className="text-lg font-semibold text-primary">Provisioning reserved</h2><dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2"><div><dt className="font-medium text-primary">Target organization ID</dt><dd>{snapshot.tenantId}</dd></div><div><dt className="font-medium text-primary">First administrator</dt><dd>{snapshot.recipient}</dd></div><div><dt className="font-medium text-primary">State</dt><dd>{snapshot.state || 'Pending'}</dd></div></dl><div className="mt-4 flex flex-wrap gap-3"><button type="button" disabled={pending} className="rounded border px-3 py-2 disabled:opacity-50" onClick={() => void refresh()}>Refresh status</button><button type="button" disabled={pending} className="rounded border px-3 py-2 disabled:opacity-50" onClick={cancel}>Cancel</button></div></section>
      {!connection?.enabled ? <form className="space-y-4 rounded-lg border border-secondary p-5" onSubmit={saveDraft}><h2 className="text-lg font-semibold text-primary">{connection ? 'Correct connection credential' : 'Identity connection draft'}</h2>{connection ? <p className="text-sm text-secondary">Trust settings are fixed. Save a replacement client secret and test it before activation.</p> : null}<label className="grid gap-1 text-sm text-primary">Display name<input required readOnly={connection !== null} value={draft.displayName} onChange={(event) => setDraft((value) => ({ ...value, displayName: event.target.value }))} className="rounded border border-secondary bg-primary px-3 py-2 text-primary" /></label><label className="grid gap-1 text-sm text-primary">Issuer<input required readOnly={connection !== null} type="url" value={draft.issuer} onChange={(event) => setDraft((value) => ({ ...value, issuer: event.target.value, entraDiscoveryMode: '' }))} autoComplete="url" className="rounded border border-secondary bg-primary px-3 py-2 text-primary" /></label><label className="grid gap-1 text-sm text-primary">Client ID<input required readOnly={connection !== null} value={draft.clientId} onChange={(event) => setDraft((value) => ({ ...value, clientId: event.target.value }))} autoComplete="off" className="rounded border border-secondary bg-primary px-3 py-2 text-primary" /></label><label className="grid gap-1 text-sm text-primary">Client secret<input required type="password" value={draft.clientSecret} onChange={(event) => setDraft((value) => ({ ...value, clientSecret: event.target.value }))} autoComplete="new-password" className="rounded border border-secondary bg-primary px-3 py-2 text-primary" /></label><label className="grid gap-1 text-sm text-primary">Auth0 organization ID (optional)<input readOnly={connection !== null} value={draft.auth0OrganizationId} onChange={(event) => setDraft((value) => ({ ...value, auth0OrganizationId: event.target.value, entraDiscoveryMode: '' }))} autoComplete="off" className="rounded border border-secondary bg-primary px-3 py-2 text-primary" /></label>{entraDirectory(draft.issuer) && !draft.auth0OrganizationId ? <EntraDiscoverySettings issuer={draft.issuer} mode={draft.entraDiscoveryMode ?? ''} disabled={connection !== null} onChange={(mode) => setDraft((value) => ({ ...value, entraDiscoveryMode: mode }))} /> : null}<button type="submit" disabled={pending} className="rounded bg-brand-solid px-3 py-2 text-white disabled:opacity-50">{pending ? 'Saving…' : connection ? 'Save corrected credential' : 'Save connection draft'}</button></form> : null}
      {connection ? <section aria-labelledby="connection-phase-heading" className="rounded-lg border border-secondary p-5"><h2 id="connection-phase-heading" className="text-lg font-semibold text-primary">Connection phase</h2><dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2"><div><dt className="font-medium text-primary">Connection</dt><dd>{connection.displayName}</dd></div><div><dt className="font-medium text-primary">Provider test</dt><dd>{connection.testPassed ? 'Passed' : 'Required before activation'}</dd></div></dl><div className="mt-4 flex flex-wrap gap-3">{mayTest ? <button type="button" disabled={pending} className="rounded border px-3 py-2 disabled:opacity-50" onClick={() => void testProvider()}>Test actual provider</button> : null}{mayActivate ? <button type="button" disabled={pending} className="rounded bg-brand-solid px-3 py-2 text-white disabled:opacity-50" onClick={() => void activate()}>Activate connection</button> : null}</div></section> : null}
      {mayInvite ? <section aria-labelledby="first-admin-invitation-heading" className="rounded-lg border border-secondary p-5"><h2 id="first-admin-invitation-heading" className="text-lg font-semibold text-primary">First administrator invitation</h2><p className="mt-2 text-sm text-secondary">Review this final administrator action before creating the invitation.</p><dl className="mt-3 grid gap-2 text-sm sm:grid-cols-3"><div><dt className="font-medium text-primary">Target</dt><dd>{snapshot.tenantId}</dd></div><div><dt className="font-medium text-primary">Recipient</dt><dd>Recipient: {snapshot.recipient}</dd></div><div><dt className="font-medium text-primary">Role</dt><dd>Role: ADMIN</dd></div></dl><button type="button" disabled={pending} className="mt-4 rounded bg-brand-solid px-3 py-2 text-white disabled:opacity-50" onClick={() => void createInvitation()}>Create first administrator invitation</button>{invitationCode ? <label className="mt-4 grid gap-1 text-sm text-primary">First administrator invitation code<input aria-label="First administrator invitation code" readOnly type="password" value={invitationCode} autoComplete="off" className="rounded border border-secondary bg-primary px-3 py-2 font-mono text-primary" /></label> : null}</section> : null}
    </>}
  </section>
}

export default InitialOrganizationProvisioning
