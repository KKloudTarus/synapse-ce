import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, ApiError, type UserContact } from '../../lib/api'

export function ProfilePage() {
  const [contacts, setContacts] = useState<UserContact[] | null>(null)
  const [email, setEmail] = useState('')
  const [codes, setCodes] = useState<Record<string,string>>({})
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [unavailable, setUnavailable] = useState(false)

  const reload = useCallback(async () => {
    try {
      setContacts(await api.listMyContacts())
      setUnavailable(false)
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) { setUnavailable(true); setContacts([]) }
      else setError(e instanceof Error ? e.message : 'Could not load contacts')
    }
  }, [])
  useEffect(() => { void reload() }, [reload])

  async function run(key: string, action: () => Promise<unknown>, success: string) {
    setBusy(key); setError(null); setMessage(null)
    try { await action(); await reload(); setMessage(success) }
    catch (e) { setError(e instanceof Error ? e.message : 'The request failed') }
    finally { setBusy(null) }
  }

  function add(e: FormEvent) {
    e.preventDefault()
    void run('add', async () => { await api.addMyEmail(email); setEmail('') }, 'Email added. Request a verification code to activate it.')
  }

  return <div className="mx-auto max-w-3xl space-y-6">
    <header><h1 className="text-2xl font-semibold text-primary">My profile</h1><p className="mt-1 text-sm text-secondary">Manage email addresses for personal notifications.</p></header>
    {error && <div role="alert" className="rounded-lg border border-error-primary bg-error-primary p-3 text-sm text-error-primary">{error}</div>}
    {message && <div role="status" className="rounded-lg border border-success-primary p-3 text-sm text-success-primary">{message}</div>}
    {contacts === null ? <p role="status" className="text-secondary">Loading contacts…</p> : unavailable ?
      <p className="rounded-lg border border-secondary p-4 text-secondary">Personal contacts are unavailable on this deployment.</p> : <>
      <form onSubmit={add} className="space-y-3 rounded-xl border border-secondary bg-primary p-5">
        <label htmlFor="profile-email" className="block text-sm font-medium text-primary">Add an email address</label>
        <div className="flex flex-col gap-2 sm:flex-row">
          <input id="profile-email" type="email" autoComplete="email" required maxLength={320} value={email} onChange={e => setEmail(e.target.value)} className="min-w-0 flex-1 rounded-lg border border-primary bg-primary px-3 py-2 text-primary" />
          <button type="submit" disabled={busy !== null} className="rounded-lg bg-brand-solid px-4 py-2 font-medium text-white disabled:opacity-50">Add email</button>
        </div>
      </form>
      <section aria-labelledby="profile-contacts-heading" className="space-y-3">
        <h2 id="profile-contacts-heading" className="text-lg font-semibold text-primary">Email contacts</h2>
        {contacts.length === 0 ? <p className="rounded-lg border border-secondary p-4 text-secondary">No email addresses yet.</p> : contacts.map(contact =>
          <article key={contact.id} className="space-y-3 rounded-xl border border-secondary bg-primary p-5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div><p className="break-all font-medium text-primary">{contact.value}</p><p className="text-sm text-secondary">{contact.verified_at ? 'Verified' : 'Pending verification'}{contact.source === 'oidc' ? ' · Managed by identity provider' : ''}</p></div>
              {contact.source === 'manual' && <button type="button" disabled={busy !== null} onClick={() => void run(contact.id, () => api.deleteMyContact(contact.id), 'Email removed.')} className="rounded-lg border border-secondary px-3 py-2 text-sm text-secondary disabled:opacity-50">Remove</button>}
            </div>
            {!contact.verified_at && contact.source === 'manual' && <div className="space-y-2">
              <button type="button" disabled={busy !== null} onClick={() => void run(contact.id, () => api.requestMyContactVerification(contact.id), 'Verification email queued. Check your inbox.')} className="rounded-lg border border-secondary px-3 py-2 text-sm text-primary disabled:opacity-50">Send verification code</button>
              <form onSubmit={e => { e.preventDefault(); void run(contact.id, () => api.verifyMyContact(contact.id,codes[contact.id] ?? ''), 'Email verified.') }} className="flex flex-col gap-2 sm:flex-row">
                <label htmlFor={`code-${contact.id}`} className="sr-only">Eight-digit code for {contact.value}</label>
                <input id={`code-${contact.id}`} inputMode="numeric" pattern="[0-9]{8}" maxLength={8} autoComplete="one-time-code" required value={codes[contact.id] ?? ''} onChange={e => setCodes(prev => ({ ...prev, [contact.id]: e.target.value }))} className="min-w-0 flex-1 rounded-lg border border-primary bg-primary px-3 py-2 text-primary" placeholder="8-digit code" />
                <button type="submit" disabled={busy !== null} className="rounded-lg bg-brand-solid px-4 py-2 text-white disabled:opacity-50">Verify</button>
              </form>
            </div>}
          </article>) }
      </section>
    </>}
  </div>
}
