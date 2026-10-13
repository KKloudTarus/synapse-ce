import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, ApiError } from '../../lib/api'
import type { NotificationEmailSettings, NotificationEmailSettingsInput } from '../../lib/api/notification-email'
import { Button, Card, ErrorState, Field, Input, Select, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { isAdminRole } from '../../lib/roles'

export function NotificationEmail() {
  const { data: me, loading, error } = useFetch(() => api.me(), { deps: [] })
  if (loading) return <div role="status"><Spinner label="Loading permissions…" /></div>
  if (error) return <ErrorState message={error} />
  if (!isAdminRole(me?.role)) return <Card title="Email delivery"><p>Only tenant administrators can manage the relay and verified domains.</p></Card>
  return <EmailSettingsEditor />
}

function EmailSettingsEditor() {
  const { data, loading, error, refetch } = useFetch(() => api.notificationEmailSettings(), { deps: [] })
  const [saved, setSaved] = useState<NotificationEmailSettings | null>(null)
  const confirmation = useRef<HTMLParagraphElement>(null)
  useEffect(() => { if (saved) confirmation.current?.focus() }, [saved])
  const current = saved ?? data
  function reload() { setSaved(null); refetch() }
  if (loading) return <div role="status"><Spinner label="Loading email delivery settings…" /></div>
  if (error) return <Card title="Email delivery"><ErrorState message={error} /><Button variant="secondary" onClick={reload}>Retry</Button></Card>
  if (!current) return null
  return <><EmailSettingsForm key={current.revision} current={current} onSaved={setSaved} onReload={reload} />{saved && <p ref={confirmation} tabIndex={-1} role="status" className="text-sm text-success-primary">Email delivery settings saved.</p>}</>
}

function EmailSettingsForm({ current, onSaved, onReload }: { current: NotificationEmailSettings; onSaved: (value: NotificationEmailSettings) => void; onReload: () => void }) {
  const [replace, setReplace] = useState(false)
  const [clearRelay, setClearRelay] = useState(false)
  const [host, setHost] = useState('')
  const [port, setPort] = useState('587')
  const [from, setFrom] = useState('')
  const [username, setUsername] = useState('')
  const [mode, setMode] = useState('password')
  const [password, setPassword] = useState('')
  const [clientID, setClientID] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [refreshToken, setRefreshToken] = useState('')
  const [directoryID, setDirectoryID] = useState('')
  const [domains, setDomains] = useState(current.domains.join(', '))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [conflict, setConflict] = useState(false)
  async function save(e: FormEvent) {
    e.preventDefault()
    if (busy) return
    setBusy(true); setError(null); setConflict(false)
    const input: NotificationEmailSettingsInput = { revision: current.revision, domains: domains.split(',').map(v => v.trim()).filter(Boolean) }
    if (clearRelay) input.clear_relay = true
    else if (replace) input.relay = {
      host: host.trim(), port: Number(port), from: from.trim(), username: username.trim(),
      ...(mode === 'password' ? { password } : { oauth: { provider: mode as 'google' | 'microsoft', client_id: clientID.trim(), client_secret: clientSecret, ...(mode === 'google' ? { refresh_token: refreshToken } : { directory_id: directoryID.trim() }) } }),
    }
    try {
      const result = await api.updateNotificationEmailSettings(input)
      setPassword(''); setClientSecret(''); setRefreshToken(''); setUsername(''); setClientID(''); setDirectoryID('')
      setReplace(false); setClearRelay(false); onSaved(result)
    } catch (cause) { setError(cause instanceof ApiError ? cause.message : 'Email settings could not be saved. Try again.'); setConflict(cause instanceof ApiError && cause.status === 409) }
    finally { setBusy(false) }
  }
  const credentialsMissing = replace && (!host.trim() || !from.trim() || !username.trim() || (mode === 'password' ? !password : !clientID.trim() || !clientSecret || (mode === 'google' ? !refreshToken : !directoryID.trim())))
  return <Card title="Email delivery">
    <p className="mb-4 text-sm text-secondary">{current.relay_configured ? `Tenant relay: ${current.relay_host}:${current.relay_port} · ${current.auth_mode}` : 'The operator relay is used. No tenant relay is configured.'}</p>
    <p className="mb-4 text-sm text-tertiary">Recipients must be verified contacts in this tenant or belong to a verified domain. Test sends are limited to five per channel per hour.</p>
    <form onSubmit={save} className="space-y-4">
      <Field label="Verified domains" htmlFor="email-domains" hint="Comma-separated exact domains. Additions require a matching DNS TXT record; removing a domain revokes its recipient eligibility.">
        <Input id="email-domains" aria-describedby="email-domains-hint" value={domains} onChange={e => setDomains(e.target.value)} placeholder="example.test" disabled={busy} />
      </Field>
      <p className="text-sm text-secondary">For each new domain, publish a TXT record at <code>_synapse-email.&lt;domain&gt;</code> with value <code>{current.dns_txt_value}</code>.</p>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={replace} disabled={busy || clearRelay} onChange={e => setReplace(e.target.checked)} />{current.relay_configured ? 'Replace tenant relay' : 'Configure tenant relay'}</label>
      {current.relay_configured && <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={clearRelay} disabled={busy || replace} onChange={e => setClearRelay(e.target.checked)} />Use the operator relay</label>}
      {replace && <fieldset disabled={busy} className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <legend className="mb-4 text-sm text-tertiary">Enter the full configuration. Credentials are never returned after save. The host must be approved by the operator; certificates are always verified.</legend>
        <Field label="Relay host" htmlFor="email-host"><Input id="email-host" value={host} onChange={e => setHost(e.target.value)} autoComplete="off" /></Field>
        <Field label="TLS port" htmlFor="email-port"><Select id="email-port" value={port} onValueChange={setPort} options={[...(mode === 'microsoft' ? [] : [{ value: '465', label: '465 — implicit TLS' }]), { value: '587', label: '587 — STARTTLS' }]} /></Field>
        <Field label="Sender address" htmlFor="email-from"><Input id="email-from" type="email" value={from} onChange={e => setFrom(e.target.value)} autoComplete="off" /></Field>
        <Field label="Mailbox username" htmlFor="email-user"><Input id="email-user" type={mode === 'password' ? 'text' : 'email'} value={username} onChange={e => setUsername(e.target.value)} autoComplete="off" /></Field>
        <Field label="Authentication" htmlFor="email-auth"><Select id="email-auth" value={mode} onValueChange={value => { setMode(value); if (value === 'microsoft') setPort('587'); setPassword(''); setClientSecret(''); setRefreshToken('') }} options={[{ value: 'password', label: 'Relay password' }, { value: 'google', label: 'Google Workspace XOAUTH2' }, { value: 'microsoft', label: 'Microsoft 365 XOAUTH2' }]} /></Field>
        {mode === 'password' ? <Field label="Relay password" htmlFor="email-password"><Input id="email-password" type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} /></Field> : <>
          <Field label="OAuth client ID" htmlFor="email-client-id"><Input id="email-client-id" value={clientID} onChange={e => setClientID(e.target.value)} autoComplete="off" /></Field>
          <Field label="OAuth client secret" htmlFor="email-client-secret"><Input id="email-client-secret" type="password" autoComplete="new-password" value={clientSecret} onChange={e => setClientSecret(e.target.value)} /></Field>
          {mode === 'google' ? <Field label="OAuth refresh token" htmlFor="email-refresh-token"><Input id="email-refresh-token" type="password" autoComplete="new-password" value={refreshToken} onChange={e => setRefreshToken(e.target.value)} /></Field> : <Field label="Microsoft directory ID" htmlFor="email-directory"><Input id="email-directory" value={directoryID} onChange={e => setDirectoryID(e.target.value)} autoComplete="off" /></Field>}
        </>}
      </fieldset>}
      {error && <ErrorState message={error} />}
      {conflict && <><p className="text-sm text-secondary">Another administrator changed these settings. Reload the current configuration before saving again; unsaved values will be discarded.</p><Button type="button" variant="secondary" onClick={onReload}>Reload settings</Button></>}
      <Button type="submit" loading={busy} disabled={busy || credentialsMissing}>Save email settings</Button>
    </form>
  </Card>
}
