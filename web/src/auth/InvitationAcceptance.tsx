import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { useAuth } from './AuthContext'
import { setCSRFToken, snapshotAuth } from '../lib/api/client'
import { ApiError, errorFromResponse } from '../lib/api/errors'

type Connection = { id: string; name: string }
type Action = { kind: 'invitation' | 'challenge'; code: string; connectionId?: string }

function record(value: unknown): Record<string, unknown> { return value !== null && typeof value === 'object' ? value as Record<string, unknown> : {} }
function text(value: unknown): string { return typeof value === 'string' ? value : '' }
function connections(value: unknown): Connection[] {
  return Array.isArray(value) ? value.map((item) => {
    const candidate = record(item)
    return { id: text(candidate.id), name: text(candidate.name) }
  }).filter((item) => item.id !== '' && item.name !== '') : []
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const auth = snapshotAuth()
  let response: Response
  try { response = await fetch(path, auth.requestInit(init)) } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  if (!response.ok) {
    const error = await errorFromResponse(response)
    auth.notifyUnauthorized(error)
    throw error
  }
  return response.json()
}

function takeMailboxMarker(): boolean {
  const url = new URL(window.location.href)
  if (url.searchParams.get('auth_error') !== 'mailbox_verification_required') return false
  url.searchParams.delete('auth_error')
  window.history.replaceState(window.history.state, '', url.pathname + url.search + url.hash)
  return true
}

/** Accepts server-routed invitation and mailbox codes without storing either outside component state. */
export function InvitationAcceptance() {
  const { retry } = useAuth()
  const [invitationCode, setInvitationCode] = useState('')
  const [mailboxCode, setMailboxCode] = useState('')
  const [providerChoices, setProviderChoices] = useState<Connection[]>([])
  const [provider, setProvider] = useState('')
  const [mailbox, setMailbox] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [canRetry, setCanRetry] = useState(false)
  const generation = useRef(0)
  const controller = useRef<AbortController | null>(null)
  const pending = useRef<Action | null>(null)
  const errorRef = useRef<HTMLParagraphElement>(null)
  const mailboxRequested = useRef(new URL(window.location.href).searchParams.get('auth_error') === 'mailbox_verification_required')
  useEffect(() => { if (error) errorRef.current?.focus() }, [error])

  const pendingMailbox = useCallback(async () => {
    const generationAtStart = ++generation.current
    controller.current?.abort()
    const next = new AbortController()
    controller.current = next
    setLoading(true); setError(null)
    try {
      const value = record(await request('/api/auth/enterprise/invitation/pending', { signal: next.signal }))
      if (generation.current !== generationAtStart) return
      if (value.challenge_required === true) setMailbox(true)
      else setError('The mailbox verification session is no longer available. Start the invitation again.')
    } catch (cause) {
      if (!(cause instanceof DOMException && cause.name === 'AbortError') && generation.current === generationAtStart) {
        setError(cause instanceof Error ? cause.message : 'Could not check mailbox verification.')
        setCanRetry(cause instanceof ApiError && (cause.status === 0 || cause.status >= 500))
      }
    } finally { if (generation.current === generationAtStart) setLoading(false) }
  }, [])

  useEffect(() => {
    if (!mailboxRequested.current) return
    takeMailboxMarker()
    void pendingMailbox()
  }, [pendingMailbox])

  useEffect(() => {
    const currentGeneration = generation
    return () => { currentGeneration.current++; controller.current?.abort() }
  }, [])

  const submit = useCallback(async (action: Action) => {
    const generationAtStart = ++generation.current
    controller.current?.abort()
    const next = new AbortController()
    controller.current = next
    pending.current = action
    setLoading(true); setError(null); setCanRetry(false)
    try {
      const value = record(await request(action.kind === 'invitation' ? '/api/auth/enterprise/invitation' : '/api/auth/enterprise/invitation/challenge', {
        method: 'POST', signal: next.signal,
        body: JSON.stringify(action.kind === 'invitation' ? { code: action.code, ...(action.connectionId ? { connection_id: action.connectionId } : {}) } : { code: action.code }),
      }))
      if (generation.current !== generationAtStart) return
      if (action.kind === 'challenge') {
        const csrfToken = text(value.csrf_token)
        if (!csrfToken) throw new Error('The mailbox verification response was incomplete.')
        pending.current = null; setMailboxCode(''); setCSRFToken(csrfToken); await retry(); return
      }
      const authorizationURL = text(value.authorization_url)
      if (authorizationURL) { window.location.assign(authorizationURL); return }
      const choices = connections(value.connections)
      if (choices.length) { setProviderChoices(choices); setProvider(choices.length === 1 ? choices[0].id : ''); return }
      throw new Error('The invitation response did not include an approved identity provider.')
    } catch (cause) {
      if (!(cause instanceof DOMException && cause.name === 'AbortError') && generation.current === generationAtStart) {
        setError(cause instanceof Error ? cause.message : 'Could not continue the invitation.')
        setCanRetry(cause instanceof ApiError && (cause.status === 0 || cause.status >= 500))
      }
    } finally { if (generation.current === generationAtStart) setLoading(false) }
  }, [retry])

  function cancel() {
    mailboxRequested.current = false
    generation.current++; controller.current?.abort(); pending.current = null
    setInvitationCode(''); setMailboxCode(''); setProviderChoices([]); setProvider(''); setMailbox(false); setError(null); setCanRetry(false)
  }
  function retryAction() { const action = pending.current; if (action) void submit(action); else if (mailbox || mailboxRequested.current) void pendingMailbox() }
  function invitationSubmit(event: FormEvent) { event.preventDefault(); if (invitationCode) { setProviderChoices([]); void submit({ kind: 'invitation', code: invitationCode }) } }
  function mailboxSubmit(event: FormEvent) { event.preventDefault(); if (mailboxCode) void submit({ kind: 'challenge', code: mailboxCode }) }
  function providerSubmit() {
    const action = pending.current
    const selected = provider || (providerChoices.length === 1 ? providerChoices[0].id : '')
    if (action?.kind === 'invitation' && selected) void submit({ ...action, connectionId: selected })
  }
  const errorNode = error ? <p ref={errorRef} tabIndex={-1} role="alert" className="mt-3 text-sm text-critical">{error} {canRetry ? <button type="button" className="underline" onClick={retryAction}>Retry</button> : null}</p> : null

  if (mailbox) return <section aria-labelledby="mailbox-heading" className="mt-5 rounded-xl border border-secondary bg-secondary/30 p-4">
    <h2 id="mailbox-heading" className="text-sm font-semibold text-primary">Verify your mailbox</h2><p className="mt-1 text-sm text-tertiary">Enter the one-time code sent to the invitation recipient.</p>
    {loading ? <p role="status" className="mt-3 text-sm text-tertiary">Checking mailbox verification…</p> : <form className="mt-3 space-y-3" onSubmit={mailboxSubmit}><label className="grid gap-1 text-sm text-primary">Mailbox verification code<input required type="password" autoComplete="one-time-code" value={mailboxCode} onChange={(event) => setMailboxCode(event.target.value)} className="rounded-lg border border-secondary bg-primary px-3 py-2 text-primary" /></label><button disabled={!mailboxCode} className="rounded-lg bg-brand-solid px-3 py-2 text-sm font-semibold text-white disabled:opacity-50">Verify mailbox</button><button type="button" className="ml-2 text-sm underline" onClick={cancel}>Cancel</button></form>}{errorNode}
  </section>

  return <section aria-labelledby="invitation-heading" className="mt-5 border-t border-secondary pt-4">
    <h2 id="invitation-heading" className="text-sm font-semibold text-primary">Accept an invitation</h2><p className="mt-1 text-sm text-tertiary">Use the invitation code supplied by your administrator.</p>
    <form className="mt-3 space-y-3" onSubmit={invitationSubmit}><label className="grid gap-1 text-sm text-primary">Invitation code<input required type="password" autoComplete="one-time-code" value={invitationCode} onChange={(event) => setInvitationCode(event.target.value)} className="rounded-lg border border-secondary bg-primary px-3 py-2 text-primary" /></label><button disabled={loading || !invitationCode} className="rounded-lg border border-secondary px-3 py-2 text-sm font-semibold text-primary disabled:opacity-50">{loading ? 'Checking invitation…' : 'Continue with invitation'}</button></form>
    {providerChoices.length > 0 ? <div className="mt-3 space-y-2 rounded-lg border border-secondary p-3"><p className="text-sm text-tertiary">Choose an approved identity provider.</p>{providerChoices.length === 1 ? <button type="button" disabled={loading} onClick={providerSubmit} className="w-full rounded-lg bg-brand-solid px-3 py-2 text-sm font-semibold text-white">Continue with {providerChoices[0].name}</button> : <><label htmlFor="invitation-provider" className="text-sm text-primary">Approved identity provider</label><select id="invitation-provider" required value={provider} disabled={loading} onChange={(event) => setProvider(event.target.value)} className="w-full rounded-lg border border-secondary bg-primary px-3 py-2 text-primary"><option value="">Choose a provider</option>{providerChoices.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select><button type="button" disabled={!provider || loading} onClick={providerSubmit} className="w-full rounded-lg bg-brand-solid px-3 py-2 text-sm font-semibold text-white disabled:opacity-50">Continue to provider</button></>}<button type="button" className="text-sm underline" onClick={cancel}>Cancel invitation</button></div> : null}{errorNode}
  </section>
}
