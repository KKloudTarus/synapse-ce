import { useEffect, useRef, useState } from 'react'
import { Button, Card, ErrorState, Input } from '../../components/ui'
import { api } from '../../lib/api'
import type { Integration } from '../../lib/types'

export function JiraInboundSettings({ integrations, canAdmin }: { integrations: Integration[]; canAdmin: boolean }) {
  return <Card title="Signed Jira webhooks" bodyClass="space-y-3">
    <p className="text-sm text-secondary">Jira changes create retest proposals and external comments. A reviewer still decides the finding status.</p>
    {!canAdmin ? <p className="text-sm text-tertiary">Only a tenant administrator can configure webhook credentials.</p> : integrations.length === 0 ? <p className="text-sm text-tertiary">Connect and enable Jira before configuring a webhook.</p> : integrations.map((integration) => <JiraWebhookEditor key={`${integration.id}:${integration.connectionRevision}:${integration.credentialRevision}`} integration={integration} />)}
  </Card>
}

function JiraWebhookEditor({ integration }: { integration: Integration }) {
  const [secret, setSecret] = useState('')
  const [path, setPath] = useState('')
  const [showPath, setShowPath] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState('')
  const live = useRef(true)
  const pending = useRef(false)
  useEffect(() => { live.current = true; return () => { live.current = false } }, [])
  async function save() {
    if (pending.current || !integration.enabled) return
    pending.current = true; setBusy(true); setError(null); setNotice(''); setShowPath(false)
    try {
      const result = await api.configureJiraInboundWebhook(integration.id, secret)
      if (live.current) { setSecret(''); setPath(result.path); setNotice(`Signed webhook ${result.rotated ? 'rotated' : 'configured'} (version ${result.version}). Use the same secret in Jira.`) }
    } catch (cause) { if (live.current) setError(cause instanceof Error ? cause.message : 'Could not configure the Jira webhook.') }
    finally { pending.current = false; if (live.current) setBusy(false) }
  }
  return <div className="space-y-2 rounded-lg border border-secondary p-3">
    <p className="text-sm font-medium text-primary">{integration.name}</p>
    {!integration.enabled && <p className="text-sm text-tertiary">Enable and test this connection first.</p>}
    <p className="text-xs text-tertiary">Use a 32–128 byte secret in both systems. Jira Data Center requires a supported signed-webhook version. The secret is never returned.</p>
    <label className="block text-sm text-secondary" htmlFor={`jira-hook-secret-${integration.id}`}>Webhook secret</label>
    <Input id={`jira-hook-secret-${integration.id}`} type="password" autoComplete="new-password" value={secret} disabled={busy || !integration.enabled} onChange={(event) => setSecret(event.target.value)} />
    <Button variant="secondary" disabled={busy || !integration.enabled || new TextEncoder().encode(secret).length < 32 || new TextEncoder().encode(secret).length > 128 || secret.trim() !== secret} onClick={() => void save()}>{busy ? 'Configuring webhook…' : 'Configure or rotate webhook'}</Button>
    {error && <ErrorState message={error} />}
    {notice && <p role="status" className="text-sm text-success-primary">{notice}</p>}
    {path && <div className="space-y-2"><Button variant="ghost" onClick={() => setShowPath((value) => !value)}>{showPath ? 'Hide webhook path' : 'Show webhook path'}</Button><p className="break-all font-mono text-xs text-secondary">{showPath ? path : 'Webhook path hidden'}</p><p className="text-xs text-tertiary">Append this path to your public Synapse origin when configuring Jira. Keep it out of screenshots.</p></div>}
  </div>
}
