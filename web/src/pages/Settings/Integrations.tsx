import { Link01, Plus, RefreshCw01 } from '@untitledui/icons'
import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../../components/ui'
import { api } from '../../lib/api'
import type {
  Integration,
  IntegrationBinding,
  IntegrationExternalRun,
  IntegrationFieldDescriptor,
  IntegrationInput,
  IntegrationOperation,
  IntegrationOperationType,
  IntegrationProviderDescriptor,
  Project,
} from '../../lib/types'

const TERMINAL_STATES = new Set(['succeeded', 'partial', 'failed', 'cancelled'])

export function Integrations() {
  const [providers, setProviders] = useState<IntegrationProviderDescriptor[]>([])
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [operations, setOperations] = useState<IntegrationOperation[]>([])
  const [bindings, setBindings] = useState<IntegrationBinding[]>([])
  const [runs, setRuns] = useState<IntegrationExternalRun[]>([])
  const [loading, setLoading] = useState(true)
  const [detailLoading, setDetailLoading] = useState(false)
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState(false)
  const [credentialOpen, setCredentialOpen] = useState(false)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const selected = integrations.find((item) => item.id === selectedId) ?? null
  const provider = providers.find((item) => item.provider === selected?.provider) ?? null

  const loadOverview = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [providerItems, integrationItems, projectItems] = await Promise.all([
        api.listIntegrationProviders(),
        api.listIntegrations(),
        api.listProjects(),
      ])
      setProviders(providerItems)
      setIntegrations(integrationItems)
      setProjects(projectItems)
      setSelectedId((current) => integrationItems.some((item) => item.id === current) ? current : (integrationItems[0]?.id ?? ''))
      if (integrationItems.length === 0) setCreating(true)
    } catch (caught) {
      setError(message(caught))
    } finally {
      setLoading(false)
    }
  }, [])

  const loadDetail = useCallback(async (integrationId: string, quiet = false) => {
    if (!integrationId) return
    if (!quiet) setDetailLoading(true)
    try {
      const [item, operationItems, bindingItems, runItems] = await Promise.all([
        api.getIntegration(integrationId),
        api.listIntegrationOperations(integrationId),
        api.listIntegrationBindings(integrationId),
        api.listIntegrationExternalRuns(integrationId),
      ])
      setIntegrations((current) => current.map((entry) => entry.id === item.id ? item : entry))
      setOperations(operationItems)
      setBindings(bindingItems)
      setRuns(runItems)
    } catch (caught) {
      setError(message(caught))
    } finally {
      if (!quiet) setDetailLoading(false)
    }
  }, [])

  useEffect(() => { void loadOverview() }, [loadOverview])
  useEffect(() => {
    setOperations([])
    setBindings([])
    setRuns([])
    setEditing(false)
    setCredentialOpen(false)
    void loadDetail(selectedId)
  }, [loadDetail, selectedId])

  const activeOperation = operations.find((operation) => !TERMINAL_STATES.has(operation.state))
  useEffect(() => {
    if (!activeOperation || !selectedId) return
    const timer = window.setInterval(async () => {
      try {
        const current = await api.getIntegrationOperation(activeOperation.id)
        setOperations((items) => items.map((item) => item.id === current.id ? current : item))
        if (TERMINAL_STATES.has(current.state)) {
          window.clearInterval(timer)
          await loadDetail(selectedId, true)
          setNotice(`${operationLabel(current.type)} ${current.state}.`)
        }
      } catch (caught) {
        window.clearInterval(timer)
        setError(message(caught))
      }
    }, 1000)
    return () => window.clearInterval(timer)
  }, [activeOperation, loadDetail, selectedId])

  async function operate(key: string, action: () => Promise<void>, success: string) {
    setBusy(key)
    setError('')
    setNotice('')
    try {
      await action()
      setNotice(success)
    } catch (caught) {
      setError(message(caught))
    } finally {
      setBusy('')
    }
  }

  async function saveCreated(input: IntegrationInput, secrets: Record<string, string>) {
    await operate('create', async () => {
      const item = await api.createIntegration(input)
      setIntegrations((current) => [...current, item])
      setSelectedId(item.id)
      setCreating(false)
      if (Object.values(secrets).some(Boolean)) await api.setIntegrationCredential(item.id, secrets)
      await loadOverview()
    }, 'Integration created.')
  }

  async function saveUpdated(input: IntegrationInput) {
    if (!selected) return
    await operate('update', async () => {
      const item = await api.updateIntegration(selected, input)
      setIntegrations((current) => current.map((entry) => entry.id === item.id ? item : entry))
      setEditing(false)
    }, 'Integration configuration updated.')
  }

  async function runOperation(type: IntegrationOperationType) {
    if (!selected) return
    await operate(`operation:${type}`, async () => {
      const operation = await api.startIntegrationOperation(selected.id, type)
      setOperations((current) => [operation, ...current.filter((item) => item.id !== operation.id)])
    }, `${operationLabel(type)} queued.`)
  }

  async function toggleEnabled() {
    if (!selected) return
    await operate('toggle', async () => {
      const item = await api.setIntegrationEnabled(selected, !selected.enabled)
      setIntegrations((current) => current.map((entry) => entry.id === item.id ? item : entry))
    }, `${selected.name} ${selected.enabled ? 'disabled' : 'enabled'}.`)
  }

  async function archiveSelected() {
    if (!selected || !window.confirm(`Archive ${selected.name}? Historical operations and runs remain available.`)) return
    await operate('archive', async () => {
      await api.archiveIntegration(selected)
      const remaining = integrations.filter((item) => item.id !== selected.id)
      setIntegrations(remaining)
      setSelectedId(remaining[0]?.id ?? '')
      if (remaining.length === 0) setCreating(true)
    }, `${selected.name} archived.`)
  }

  async function saveCredential(secrets: Record<string, string>) {
    if (!selected) return
    await operate('credential', async () => {
      await api.setIntegrationCredential(selected.id, secrets)
      setCredentialOpen(false)
      await loadDetail(selected.id, true)
    }, 'Credentials saved and cleared from the form.')
  }

  async function deleteCredential() {
    if (!selected || !window.confirm(`Delete credentials for ${selected.name}?`)) return
    await operate('delete-credential', async () => {
      await api.deleteIntegrationCredential(selected.id)
      await loadDetail(selected.id, true)
    }, 'Credentials deleted.')
  }

  if (loading) return <Spinner label="Loading integrations…" />
  if (error && providers.length === 0) return <ErrorState message={error} />

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-primary">CI/CD integrations</h2>
          <p className="mt-1 text-sm text-tertiary">Connect read-only providers, discover pipelines, and link external runs to Project analyses.</p>
        </div>
        <Button onClick={() => setCreating(true)}><Plus className="size-4" />Add integration</Button>
      </div>

      {error && <ErrorState message={error} />}
      {notice && <div role="status" className="rounded-lg border border-low/30 bg-low/10 px-4 py-3 text-sm text-low">{notice}</div>}

      {creating && (
        <IntegrationForm
          providers={providers}
          loading={busy === 'create'}
          onCancel={() => setCreating(false)}
          onSubmit={saveCreated}
        />
      )}

      {integrations.length === 0 && !creating ? (
        <EmptyState icon={Link01} title="No integrations configured" hint="Add a provider connection to start discovering external pipelines." action={<Button onClick={() => setCreating(true)}>Add integration</Button>} />
      ) : integrations.length > 0 && (
        <div className="grid gap-5 xl:grid-cols-[280px_minmax(0,1fr)]">
          <Card title="Connections" bodyClass="p-2">
            <div className="space-y-1" role="list">
              {integrations.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setSelectedId(item.id)}
                  className={cn(
                    'w-full rounded-lg px-3 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand',
                    item.id === selectedId ? 'bg-brand-primary text-brand-secondary' : 'hover:bg-secondary',
                  )}
                >
                  <span className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-semibold">{item.name}</span>
                    <StatusPill value={item.enabled ? 'enabled' : 'disabled'} />
                  </span>
                  <span className="mt-1 block truncate text-xs text-tertiary">{item.provider} · {item.endpoint}</span>
                </button>
              ))}
            </div>
          </Card>

          {detailLoading || !selected || !provider ? <Spinner label="Loading integration details…" /> : (
            <div className="min-w-0 space-y-5">
              <IntegrationOverview
                integration={selected}
                provider={provider}
                operations={operations}
                activeOperation={activeOperation}
                busy={busy}
                editing={editing}
                credentialOpen={credentialOpen}
                onEdit={() => setEditing(true)}
                onCancelEdit={() => setEditing(false)}
                onUpdate={saveUpdated}
                onCredentialOpen={() => setCredentialOpen(true)}
                onCredentialClose={() => setCredentialOpen(false)}
                onCredentialSave={saveCredential}
                onCredentialDelete={deleteCredential}
                onOperation={runOperation}
                onToggle={toggleEnabled}
                onArchive={archiveSelected}
              />
              <BindingsCard integration={selected} projects={projects} operations={operations} bindings={bindings} busy={busy} operate={operate} onReload={() => loadDetail(selected.id, true)} />
              <RunsCard runs={runs} />
              <OperationsCard operations={operations} activeOperation={activeOperation} busy={busy} operate={operate} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function IntegrationOverview({ integration, provider, operations, activeOperation, busy, editing, credentialOpen, onEdit, onCancelEdit, onUpdate, onCredentialOpen, onCredentialClose, onCredentialSave, onCredentialDelete, onOperation, onToggle, onArchive }: {
  integration: Integration
  provider: IntegrationProviderDescriptor
  operations: IntegrationOperation[]
  activeOperation?: IntegrationOperation
  busy: string
  editing: boolean
  credentialOpen: boolean
  onEdit: () => void
  onCancelEdit: () => void
  onUpdate: (input: IntegrationInput) => Promise<void>
  onCredentialOpen: () => void
  onCredentialClose: () => void
  onCredentialSave: (secrets: Record<string, string>) => Promise<void>
  onCredentialDelete: () => Promise<void>
  onOperation: (type: IntegrationOperationType) => Promise<void>
  onToggle: () => Promise<void>
  onArchive: () => Promise<void>
}) {
  const latest = operations[0]
  const successfulTest = operations.find((operation) => operation.type === 'test' && operation.state === 'succeeded')
  const successfulPoll = operations.find((operation) => operation.type === 'poll' && operation.state === 'succeeded')
  const staleAfter = Math.max(integration.pollIntervalSeconds * 2, 600) * 1000
  const stale = integration.enabled && (!successfulPoll || Date.now() - Date.parse(successfulPoll.finishedAt ?? successfulPoll.updatedAt) > staleAfter)
  const health = activeOperation ? activeOperation.state : latest?.state === 'failed' ? 'error' : stale ? 'stale' : integration.enabled ? 'healthy' : 'disabled'

  return (
    <Card
      title={<span className="flex flex-wrap items-center gap-2">{integration.name}<Pill>{provider.name}</Pill><StatusPill value={health} /></span>}
      actions={<span className="text-xs text-tertiary">v{integration.version}</span>}
    >
      {editing ? (
        <IntegrationForm providers={[provider]} integration={integration} loading={busy === 'update'} onCancel={onCancelEdit} onSubmit={(input) => onUpdate(input)} />
      ) : (
        <div className="space-y-5">
          <dl className="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <Stat label="Endpoint" value={integration.endpoint} />
            <Stat label="Credentials" value={integration.credentialConfigured ? 'Configured' : 'Missing'} />
            <Stat label="Last successful test" value={formatDate(successfulTest?.finishedAt)} />
            <Stat label="Last successful poll" value={formatDate(successfulPoll?.finishedAt)} />
          </dl>
          {latest?.errors[0] && <ErrorState message={latest.errors[0]} />}
          <div className="flex flex-wrap gap-2">
            <Button variant="secondary" onClick={onEdit}>Edit configuration</Button>
            <Button variant="secondary" onClick={onCredentialOpen}>{integration.credentialConfigured ? 'Replace credentials' : 'Add credentials'}</Button>
            {integration.credentialConfigured && <Button variant="ghost" loading={busy === 'delete-credential'} onClick={onCredentialDelete}>Delete credentials</Button>}
            <Button variant="secondary" disabled={!!activeOperation || !integration.credentialConfigured} loading={busy === 'operation:test'} onClick={() => onOperation('test')}>Test connection</Button>
            <Button variant="secondary" disabled={!!activeOperation || !integration.credentialConfigured} loading={busy === 'operation:discover'} onClick={() => onOperation('discover')}>Discover</Button>
            <Button variant="secondary" disabled={!!activeOperation || !integration.enabled} loading={busy === 'operation:poll'} onClick={() => onOperation('poll')}>Poll now</Button>
            <Button disabled={!!activeOperation || (!integration.enabled && !successfulTest)} loading={busy === 'toggle'} onClick={onToggle}>{integration.enabled ? 'Disable' : 'Enable'}</Button>
            <Button variant="ghost" loading={busy === 'archive'} onClick={onArchive}>Archive</Button>
          </div>
        </div>
      )}
      {credentialOpen && (
        <div className="mt-5 border-t border-secondary pt-5">
          <CredentialForm fields={provider.secretFields} loading={busy === 'credential'} onCancel={onCredentialClose} onSubmit={onCredentialSave} />
        </div>
      )}
    </Card>
  )
}

function IntegrationForm({ providers, integration, loading, onCancel, onSubmit }: {
  providers: IntegrationProviderDescriptor[]
  integration?: Integration
  loading: boolean
  onCancel: () => void
  onSubmit: (input: IntegrationInput, secrets: Record<string, string>) => Promise<void>
}) {
  const [providerSlug, setProviderSlug] = useState(integration?.provider ?? providers[0]?.provider ?? '')
  const descriptor = providers.find((item) => item.provider === providerSlug) ?? providers[0]
  const [name, setName] = useState(integration?.name ?? '')
  const [endpoint, setEndpoint] = useState(integration?.endpoint ?? '')
  const [pollInterval, setPollInterval] = useState(String(integration?.pollIntervalSeconds ?? 300))
  const [allowPrivate, setAllowPrivate] = useState(integration?.allowPrivateNetwork ?? false)
  const [config, setConfig] = useState<Record<string, unknown>>(integration?.config ?? {})
  const [secrets, setSecrets] = useState<Record<string, string>>({})
  const [formError, setFormError] = useState('')

  useEffect(() => {
    if (!integration) {
      setConfig({})
      setSecrets({})
    }
  }, [integration, providerSlug])

  async function submit(event: FormEvent) {
    event.preventDefault()
    setFormError('')
    if (!descriptor || !name.trim() || !endpoint.trim()) return setFormError('Provider, name, and HTTPS endpoint are required.')
    const seconds = Number(pollInterval)
    if (!Number.isInteger(seconds) || seconds < 30 || seconds > 86400) return setFormError('Poll interval must be between 30 and 86400 seconds.')
    const missingSecret = !integration && descriptor.secretFields.some((field) => field.required && !secrets[field.name]?.trim())
    if (missingSecret) return setFormError('Complete all required credential fields.')
    await onSubmit({ provider: descriptor.provider, name: name.trim(), endpoint: endpoint.trim(), config, allowPrivateNetwork: allowPrivate, pollIntervalSeconds: seconds }, secrets)
    setSecrets({})
  }

  return (
    <Card title={integration ? `Edit ${integration.name}` : 'Add integration'} className={integration ? 'border-0 shadow-none' : undefined} bodyClass={integration ? 'p-0' : undefined}>
      <form className="space-y-4" onSubmit={submit}>
        {formError && <ErrorState message={formError} />}
        <div className="grid gap-4 md:grid-cols-2">
          <Field label="Provider" htmlFor="integration-provider">
            <Select id="integration-provider" value={descriptor?.provider ?? ''} disabled={!!integration} onValueChange={setProviderSlug} options={providers.map((item) => ({ value: item.provider, label: item.name }))} />
          </Field>
          <Field label="Display name" htmlFor="integration-name"><Input id="integration-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={120} required /></Field>
          <Field label="HTTPS endpoint" hint="Example: https://jenkins.example.com" htmlFor="integration-endpoint"><Input id="integration-endpoint" type="url" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} placeholder="https://jenkins.example.com" required /></Field>
          <Field label="Poll interval (seconds)" htmlFor="integration-poll"><Input id="integration-poll" type="number" min={30} max={86400} value={pollInterval} onChange={(event) => setPollInterval(event.target.value)} required /></Field>
          {descriptor?.configFields.map((field) => <DynamicField key={field.name} field={field} value={config[field.name]} onChange={(value) => setConfig((current) => ({ ...current, [field.name]: value }))} />)}
        </div>
        <label className="flex items-start gap-3 rounded-lg border border-secondary p-3 text-sm text-secondary">
          <input type="checkbox" className="mt-0.5 size-4 accent-brand" checked={allowPrivate} onChange={(event) => setAllowPrivate(event.target.checked)} />
          <span><strong className="block text-primary">Allow private network</strong>Only enable for explicitly approved internal Jenkins endpoints; public-network protections remain enforced per request.</span>
        </label>
        {!integration && descriptor?.secretFields.length > 0 && (
          <div className="grid gap-4 border-t border-secondary pt-4 md:grid-cols-2">
            {descriptor.secretFields.map((field) => <DynamicField key={field.name} field={field} value={secrets[field.name]} onChange={(value) => setSecrets((current) => ({ ...current, [field.name]: String(value) }))} />)}
          </div>
        )}
        <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button><Button type="submit" loading={loading}>{integration ? 'Save changes' : 'Create integration'}</Button></div>
      </form>
    </Card>
  )
}

function CredentialForm({ fields, loading, onCancel, onSubmit }: { fields: IntegrationFieldDescriptor[]; loading: boolean; onCancel: () => void; onSubmit: (values: Record<string, string>) => Promise<void> }) {
  const [values, setValues] = useState<Record<string, string>>({})
  const [formError, setFormError] = useState('')
  async function submit(event: FormEvent) {
    event.preventDefault()
    if (fields.some((field) => field.required && !values[field.name]?.trim())) return setFormError('Complete all required credential fields.')
    await onSubmit(values)
    setValues({})
  }
  return (
    <form className="space-y-4" onSubmit={submit}>
      <div><h3 className="text-sm font-semibold text-primary">Write-only credentials</h3><p className="mt-1 text-xs text-tertiary">Saved values are encrypted and never loaded back into this form.</p></div>
      {formError && <ErrorState message={formError} />}
      <div className="grid gap-4 md:grid-cols-2">{fields.map((field) => <DynamicField key={field.name} field={field} value={values[field.name]} onChange={(value) => setValues((current) => ({ ...current, [field.name]: String(value) }))} />)}</div>
      <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button><Button type="submit" loading={loading}>Save credentials</Button></div>
    </form>
  )
}

function DynamicField({ field, value, onChange }: { field: IntegrationFieldDescriptor; value: unknown; onChange: (value: unknown) => void }) {
  if (field.kind === 'boolean') {
    return <label className="flex items-center gap-2 text-sm text-secondary"><input type="checkbox" className="size-4 accent-brand" checked={value === true} onChange={(event) => onChange(event.target.checked)} />{field.label}</label>
  }
  return <Field label={field.label} hint={field.description} htmlFor={`integration-field-${field.name}`}><Input id={`integration-field-${field.name}`} type={field.kind === 'password' ? 'password' : 'text'} autoComplete={field.kind === 'password' ? 'new-password' : 'off'} value={typeof value === 'string' ? value : ''} onChange={(event) => onChange(event.target.value)} required={field.required} /></Field>
}

function BindingsCard({ integration, projects, operations, bindings, busy, operate, onReload }: { integration: Integration; projects: Project[]; operations: IntegrationOperation[]; bindings: IntegrationBinding[]; busy: string; operate: (key: string, action: () => Promise<void>, success: string) => Promise<void>; onReload: () => Promise<void> }) {
  const pipelines = useMemo(() => operations.find((operation) => operation.type === 'discover' && operation.pipelines.length > 0)?.pipelines ?? [], [operations])
  const available = pipelines.filter((pipeline) => !bindings.some((binding) => binding.externalKey === pipeline.externalKey))
  const [pipelineKey, setPipelineKey] = useState('')
  const [projectId, setProjectId] = useState('')
  const projectNames = new Map(projects.map((project) => [project.id, project.name]))
  const selectedPipeline = available.find((pipeline) => pipeline.externalKey === pipelineKey)

  async function bind() {
    if (!selectedPipeline || !projectId) return
    await operate('bind', async () => {
      await api.createIntegrationBinding(integration.id, projectId, selectedPipeline.externalKey, selectedPipeline.fullName || selectedPipeline.name)
      setPipelineKey('')
      setProjectId('')
      await onReload()
    }, 'Pipeline bound to Project.')
  }

  return (
    <Card title="Project bindings" actions={<Pill>{bindings.length}</Pill>}>
      <div className="space-y-4">
        {pipelines.length === 0 ? <p className="text-sm text-tertiary">Run discovery to select a pipeline.</p> : (
          <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
            <Select value={pipelineKey} onValueChange={setPipelineKey} ariaLabel="Discovered pipeline" placeholder="Select pipeline" options={available.map((pipeline) => ({ value: pipeline.externalKey, label: `${pipeline.fullName || pipeline.name} (${pipeline.kind})` }))} />
            <Select value={projectId} onValueChange={setProjectId} ariaLabel="Synapse Project" placeholder="Select Project" options={projects.map((project) => ({ value: project.id, label: project.name }))} />
            <Button disabled={!selectedPipeline || !projectId} loading={busy === 'bind'} onClick={bind}>Bind</Button>
          </div>
        )}
        {bindings.length === 0 ? <p className="text-sm text-tertiary">No pipelines are bound yet.</p> : (
          <div className="divide-y divide-secondary rounded-lg border border-secondary">
            {bindings.map((binding) => (
              <div key={binding.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-sm">
                <div className="min-w-0"><p className="truncate font-medium text-primary">{binding.externalName}</p><p className="truncate text-xs text-tertiary">{projectNames.get(binding.projectId) ?? binding.projectId} · {binding.externalKey}</p></div>
                <Button variant="ghost" loading={busy === `unbind:${binding.id}`} onClick={() => operate(`unbind:${binding.id}`, async () => { await api.deleteIntegrationBinding(integration.id, binding.id); await onReload() }, 'Binding removed.')}>Remove</Button>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  )
}

function RunsCard({ runs }: { runs: IntegrationExternalRun[] }) {
  return (
    <Card title="Recent external runs" actions={<Pill>{runs.length}</Pill>} bodyClass="p-0">
      {runs.length === 0 ? <p className="p-6 text-sm text-tertiary">No external runs materialized yet.</p> : (
        <div className="overflow-x-auto"><table className="w-full min-w-[720px] text-left text-sm"><thead className="border-b border-secondary bg-secondary/40 text-xs uppercase tracking-wide text-tertiary"><tr><th className="px-5 py-3">Run</th><th className="px-5 py-3">Pipeline</th><th className="px-5 py-3">Result</th><th className="px-5 py-3">Revision</th><th className="px-5 py-3">Correlation</th><th className="px-5 py-3">Updated</th></tr></thead><tbody className="divide-y divide-secondary">{runs.map((run) => <tr key={run.id}><td className="px-5 py-3 font-medium text-primary">{run.url ? <a className="text-brand-secondary hover:underline" href={run.url} target="_blank" rel="noreferrer">#{run.number || run.providerKey}</a> : `#${run.number || run.providerKey}`}</td><td className="max-w-64 truncate px-5 py-3 text-secondary">{run.pipelineKey}</td><td className="px-5 py-3"><StatusPill value={run.lifecycle === 'completed' ? run.result : run.lifecycle} /></td><td className="px-5 py-3 font-mono text-xs text-tertiary">{run.revision ? run.revision.slice(0, 12) : '—'}</td><td className="px-5 py-3"><StatusPill value={run.correlation} /></td><td className="px-5 py-3 text-tertiary">{formatDate(run.providerUpdatedAt)}</td></tr>)}</tbody></table></div>
      )}
    </Card>
  )
}

function OperationsCard({ operations, activeOperation, busy, operate }: { operations: IntegrationOperation[]; activeOperation?: IntegrationOperation; busy: string; operate: (key: string, action: () => Promise<void>, success: string) => Promise<void> }) {
  return (
    <Card title="Operation history" actions={activeOperation ? <Button variant="ghost" loading={busy === 'cancel'} onClick={() => operate('cancel', async () => { await api.cancelIntegrationOperation(activeOperation.id) }, 'Operation cancelled.')}>Cancel active</Button> : <RefreshCw01 className="size-4 text-tertiary" />} bodyClass="p-0">
      {operations.length === 0 ? <p className="p-6 text-sm text-tertiary">No operations have run yet.</p> : <div className="divide-y divide-secondary">{operations.map((operation) => <div key={operation.id} className="grid gap-2 px-5 py-4 text-sm sm:grid-cols-[120px_110px_minmax(0,1fr)_auto]"><span className="font-medium capitalize text-primary">{operationLabel(operation.type)}</span><StatusPill value={operation.state} /><span className="text-tertiary">{operation.type === 'discover' ? `${operation.counts.pipelines} pipelines` : operation.type === 'poll' ? `${operation.counts.runs} runs · ${operation.counts.linked} linked` : operation.errors[0] ?? 'Connection check'}</span><span className="text-xs text-tertiary">{formatDate(operation.finishedAt ?? operation.createdAt)}</span></div>)}</div>}
    </Card>
  )
}

function Stat({ label, value }: { label: string; value: string }) { return <div className="min-w-0"><dt className="text-xs font-medium uppercase tracking-wide text-tertiary">{label}</dt><dd className="mt-1 truncate text-primary" title={value}>{value}</dd></div> }

function StatusPill({ value }: { value: string }) {
  const danger = value === 'failed' || value === 'error' || value === 'failure' || value === 'ambiguous'
  const good = value === 'healthy' || value === 'enabled' || value === 'succeeded' || value === 'success' || value === 'linked'
  const warning = value === 'stale' || value === 'partial' || value === 'unstable' || value === 'missing'
  return <Pill className={danger ? 'bg-high/10 text-high' : good ? 'bg-low/10 text-low' : warning ? 'bg-medium/10 text-medium' : ''}>{value.replaceAll('_', ' ')}</Pill>
}

function operationLabel(type: IntegrationOperationType) { return type === 'test' ? 'Connection test' : type === 'discover' ? 'Discovery' : 'Poll' }
function formatDate(value?: string | null) { return value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'Never' }
function message(error: unknown) { return error instanceof Error ? error.message : 'An unexpected error occurred.' }

export default Integrations
