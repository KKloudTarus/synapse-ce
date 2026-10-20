import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Link2, RefreshCw, Ticket, Trash2 } from 'lucide-react'
import { Button, Card, EmptyState, ErrorState, Field, Input, Spinner } from '../../components/ui'
import { api, type TicketMapping, type TicketMetadata } from '../../lib/api'
import type { Integration, IntegrationProviderDescriptor } from '../../lib/types'
import { canManageIntegrations, isAdminRole } from '../../lib/roles'

type Draft = Omit<TicketMapping, 'id' | 'version'>
const blank = (integrationId = '', scopeId = '', scope: Draft['scope'] = 'engagement'): Draft => ({ integrationId, scope, scopeId, projectKey: '', issueType: '', component: '', labels: [], priorityMap: {}, securityLevel: '', waiverReason: '', dataClass: 'summary', locale: 'en', summaryTemplate: '', descriptionTemplate: '', fieldValues: {}, transitionId: '', statusTransitions: {}, groupingMode: 'finding', autoPushEnabled: false, autoPushMinSeverity: 'high' })
const message = (error: unknown) => error instanceof Error ? error.message : 'Ticket settings could not be loaded.'
const isJira = (provider: string) => provider === 'jira-cloud' || provider === 'jira-dc'
const privacy: Record<string, string> = { private_repository: 'Private repository required. Visibility and write access are checked again before issue creation.', confidential_issue: 'Every issue is confidential. Access is checked again before issue creation.', provider_access: 'Access follows the selected provider project or team. Review its membership before enabling delivery.' }

export function TicketProviderSettings() {
  const [role, setRole] = useState<string>()
  const [providers, setProviders] = useState<IntegrationProviderDescriptor[]>([])
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [scopes, setScopes] = useState<{ engagement: Array<{ id: string; name: string }>; project: Array<{ id: string; name: string }> }>({ engagement: [], project: [] })
  const [draft, setDraft] = useState<Draft>(blank())
  const [selected, setSelected] = useState<TicketMapping | null>(null)
  const [mappings, setMappings] = useState<TicketMapping[]>([])
  const [metadata, setMetadata] = useState<TicketMetadata | null>(null)
  const [loading, setLoading] = useState(true)
  const [mappingLoading, setMappingLoading] = useState(false)
  const [metadataLoading, setMetadataLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [metadataError, setMetadataError] = useState<string | null>(null)
  const [notice, setNotice] = useState('')
  const [refresh, setRefresh] = useState(0)
  const metadataEpoch = useRef(0)
  const mappingEpoch = useRef(0)
  const canManage = canManageIntegrations(role)
  const canAdmin = isAdminRole(role)

  useEffect(() => {
    let live = true
    setLoading(true); setError(null)
    void api.me().then(async (me) => {
      if (!live) return
      const nextRole = me?.role ?? ''
      setRole(nextRole)
      if (!canManageIntegrations(nextRole)) return
      const [descriptors, items, engagements, projects] = await Promise.all([api.listIntegrationProviders(), api.listIntegrations(), api.listEngagements(), api.listProjects()])
      if (!live) return
      const supported = descriptors.filter((item) => item.capabilities.includes('tickets') && !isJira(item.provider))
      const available = items.filter((item) => !item.archived && supported.some((provider) => provider.provider === item.provider))
      setProviders(supported); setIntegrations(available)
      setScopes({ engagement: engagements.map(({ id, name }) => ({ id, name })), project: projects.map(({ id, name }) => ({ id, name })) })
      setDraft((current) => current.integrationId ? current : blank(available[0]?.id, engagements[0]?.id))
    }).catch((cause) => { if (live) setError(message(cause)) }).finally(() => { if (live) setLoading(false) })
    return () => { live = false }
  }, [refresh])

  useEffect(() => {
    const epoch = ++metadataEpoch.current
    setMetadata(null)
    setMetadataError(null)
    if (!canManage || !draft.integrationId) { setMetadataLoading(false); return }
    setMetadataLoading(true)
    api.ticketMetadata(draft.integrationId, draft.projectKey).then((value) => { if (epoch === metadataEpoch.current) setMetadata(value) }, (cause) => { if (epoch === metadataEpoch.current) setMetadataError(message(cause)) }).finally(() => { if (epoch === metadataEpoch.current) setMetadataLoading(false) })
    return () => { metadataEpoch.current++ }
  }, [canManage, draft.integrationId, draft.projectKey, refresh])

  useEffect(() => {
    const epoch = ++mappingEpoch.current
    setMappings([])
    if (!canManage || !draft.scopeId) { setMappingLoading(false); return }
    setMappingLoading(true)
    api.listTicketMappings(draft.scope, draft.scopeId).then((value) => { if (epoch === mappingEpoch.current) setMappings(value) }, (cause) => { if (epoch === mappingEpoch.current) setError(message(cause)) }).finally(() => { if (epoch === mappingEpoch.current) setMappingLoading(false) })
    return () => { mappingEpoch.current++ }
  }, [canManage, draft.scope, draft.scopeId, refresh])

  function update(value: Partial<Draft>) {
    if ((value.integrationId !== undefined && value.integrationId !== draft.integrationId) || (value.projectKey !== undefined && value.projectKey !== draft.projectKey)) { metadataEpoch.current++; setMetadata(null); setMetadataLoading(true) }
    setDraft((current) => ({ ...current, ...value })); setNotice('')
  }
  function changeScope(scope: Draft['scope'], scopeId = scopes[scope][0]?.id ?? '') { mappingEpoch.current++; setSelected(null); setMappings([]); setDraft(blank(draft.integrationId, scopeId, scope)); setNotice('') }
  function choose(mapping: TicketMapping) { setSelected(mapping); setDraft({ ...mapping }); setError(null); setNotice('') }
  async function save() {
    if (!canAdmin || !metadata || mappingLoading || metadataLoading || busy) return
    setBusy(true); setError(null)
    try {
      const saved = selected ? await api.updateTicketMapping(selected, draft) : await api.createTicketMapping(draft)
      setMappings((items) => selected ? items.map((item) => item.id === saved.id ? saved : item) : [...items, saved]); setSelected(saved); setDraft({ ...saved }); setNotice('Ticket mapping saved.')
    } catch (cause) { setError(message(cause)) } finally { setBusy(false) }
  }
  async function remove() {
    if (!canAdmin || !selected || busy) return
    setBusy(true); setError(null)
    try { await api.deleteTicketMapping(selected); setMappings((items) => items.filter((item) => item.id !== selected.id)); setSelected(null); setDraft(blank(draft.integrationId, draft.scopeId, draft.scope)); setNotice('Ticket mapping removed.') } catch (cause) { setError(message(cause)) } finally { setBusy(false) }
  }
  const provider = providers.find((item) => item.provider === integrations.find((item) => item.id === draft.integrationId)?.provider)
  const supportedMappings = mappings.filter((mapping) => integrations.some((item) => item.id === mapping.integrationId))
  const choices = (items: Array<{ id: string; name: string }>) => items.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)
  const selectClass = 'w-full rounded-lg border border-secondary bg-primary px-3 py-2 text-sm text-primary'
  if (loading) return <Spinner label="Loading ticket providers…" />
  if (error && role === undefined) return <ErrorState message={error} />
  if (!canManage) return <EmptyState icon={Ticket} title="Ticket settings require integration access" hint="Ask a tenant administrator or integration administrator to configure ticket destinations." />
  return <div className="space-y-5">
    <header className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-lg font-semibold text-primary">Ticket providers</h2><p className="mt-1 text-sm text-secondary">Create tickets from an approved preview. Provider changes produce proposals for human review.</p></div><Button variant="secondary" disabled={busy} onClick={() => setRefresh((value) => value + 1)}><RefreshCw className="size-4" />Refresh</Button></header>
    <nav className="flex flex-wrap gap-4 text-sm text-brand-primary"><Link to="/settings/integrations/ci"><Link2 className="mr-1 inline size-4" />Manage connections and credentials</Link><Link to="/settings/integrations/jira">Jira settings</Link></nav>
    {error && <ErrorState message={error} />}{metadataError && <ErrorState message={metadataError} />}{notice && <p role="status" className="text-sm text-success-primary">{notice}</p>}
    {integrations.length === 0 ? <EmptyState icon={Ticket} title="No ticket provider connections" hint="Add GitHub Issues, GitLab Issues, Azure Boards, ServiceNow or Linear from Manage connections, test the connection, then enable it." /> : <Card title="Ticket mappings" bodyClass="space-y-4">
      {!canAdmin && <p className="text-sm text-tertiary">Only tenant administrators can create or change ticket destinations. Existing mappings remain visible.</p>}
      <div className="grid gap-3 md:grid-cols-2"><Field label="Scope"><select aria-label="Ticket mapping scope" className={selectClass} value={draft.scope} disabled={busy} onChange={(event) => changeScope(event.target.value === 'project' ? 'project' : 'engagement')}><option value="engagement">Engagement</option><option value="project">Project</option></select></Field><Field label="Scope target"><select aria-label="Ticket scope target" className={selectClass} value={draft.scopeId} disabled={busy} onChange={(event) => changeScope(draft.scope, event.target.value)}><option value="">Select scope</option>{choices(scopes[draft.scope])}</select></Field></div>
      {mappingLoading ? <Spinner label="Loading ticket mappings…" /> : supportedMappings.length ? <ul aria-label="Saved ticket mappings" className="flex flex-wrap gap-2">{supportedMappings.map((mapping) => <li key={mapping.id}><Button variant="secondary" disabled={busy} onClick={() => choose(mapping)}>{mapping.projectKey} · {mapping.issueType}</Button></li>)}</ul> : <p className="text-sm text-tertiary">No mappings for this scope.</p>}
      <fieldset disabled={!canAdmin || busy || mappingLoading} className="grid gap-3 border-t border-secondary pt-4 md:grid-cols-2"><legend className="sr-only">Ticket destination</legend>
        <Field label="Connection"><select aria-label="Ticket connection" className={selectClass} value={draft.integrationId} disabled={!!selected} onChange={(event) => update({ integrationId: event.target.value, projectKey: '', issueType: '', priorityMap: {}, labels: [], fieldValues: {} })}>{integrations.map((item) => <option key={item.id} value={item.id}>{item.name}{item.enabled ? '' : ' (disabled)'}</option>)}</select></Field>
        <p className="self-end text-sm text-tertiary">{provider?.description}</p>
        {provider?.secretFields.length === 0 && <p className="md:col-span-2 text-sm text-secondary">Uses the SCM connector for this tenant and forge host. Configure its credential in source-control settings.</p>}
        {metadataLoading && <div className="md:col-span-2"><Spinner label="Discovering ticket metadata…" /></div>}
        <Field label="Provider project or repository"><select aria-label="Provider project" className={selectClass} disabled={metadataLoading || !metadata} value={draft.projectKey} onChange={(event) => update({ projectKey: event.target.value, issueType: '', priorityMap: {}, fieldValues: {} })}><option value="">Select destination</option>{choices(metadata?.projects ?? [])}</select></Field>
        <Field label="Issue type"><select aria-label="Provider issue type" className={selectClass} disabled={metadataLoading || !metadata} value={draft.issueType} onChange={(event) => update({ issueType: event.target.value })}><option value="">Select type</option>{choices(metadata?.issueTypes ?? [])}</select></Field>
        {metadata?.securityPolicy && <p role="status" className="md:col-span-2 text-sm text-secondary">{privacy[metadata.securityPolicy] ?? 'The provider must verify its configured access policy before writing.'}</p>}
        <Field label="Data class"><select aria-label="Ticket data class" className={selectClass} value={draft.dataClass} onChange={(event) => update({ dataClass: event.target.value as Draft['dataClass'] })}><option value="signal">Signal</option><option value="summary">Summary</option><option value="detail">Detail</option></select></Field>
        <Field label="Ticket language"><select aria-label="Ticket language" className={selectClass} value={draft.locale} onChange={(event) => update({ locale: event.target.value === 'vi' ? 'vi' : 'en' })}><option value="en">English</option><option value="vi">Tiếng Việt</option></select></Field>
        <Field label="Summary template" hint="Leave blank to use the governed default."><Input value={draft.summaryTemplate} onChange={(event) => update({ summaryTemplate: event.target.value })} /></Field><Field label="Description template" hint="Leave blank to use the governed default."><textarea aria-label="Ticket description template" className={selectClass} rows={3} value={draft.descriptionTemplate} onChange={(event) => update({ descriptionTemplate: event.target.value })} /></Field>
        <p className="md:col-span-2 text-xs text-tertiary">One ticket per finding. Polling reads external state into proposals; it does not change a finding. An uncertain create is reconciled before any retry.</p>
        <div className="md:col-span-2 flex flex-wrap gap-2"><Button loading={busy} disabled={!draft.scopeId || !draft.projectKey || !draft.issueType || metadataLoading || !metadata} onClick={() => void save()}>{selected ? 'Save ticket mapping' : 'Create ticket mapping'}</Button>{selected && <><Button variant="secondary" onClick={() => { setSelected(null); setDraft(blank(draft.integrationId, draft.scopeId, draft.scope)) }}>New mapping</Button><Button variant="danger" onClick={() => void remove()}><Trash2 className="size-4" />Delete mapping</Button></>}</div>
      </fieldset>
    </Card>}
  </div>
}
