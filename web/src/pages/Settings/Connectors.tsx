import { Eye, EyeOff, GitBranch01, Key01, Lock01, Plus, Trash01 } from '@untitledui/icons'
import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type Connector, type ConnectorProvider } from '../../lib/api'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { isAdminRole } from '../../lib/roles'

const PROVIDERS: { value: ConnectorProvider; label: string; hint: string; scope: string }[] = [
  { value: 'github', label: 'GitHub', hint: 'github.com or GitHub Enterprise; username defaults to x-access-token.', scope: 'Needs the classic repo scope, or a fine-grained token with Contents: Read.' },
  { value: 'gitlab', label: 'GitLab', hint: 'gitlab.com or self-managed; username defaults to oauth2.', scope: 'Needs a token with the read_repository scope.' },
  { value: 'bitbucket', label: 'Bitbucket', hint: 'bitbucket.org or Data Center; set the username the token belongs to.', scope: 'Needs an app password with Repositories: Read.' },
  { value: 'azure-devops', label: 'Azure DevOps', hint: 'Azure DevOps Services uses dev.azure.com; username defaults to pat.', scope: 'Azure Repos PAT needs Code (Read & write) plus Code (Status) for PR comments and statuses.' },
  { value: 'generic', label: 'Generic', hint: 'Any git host that authenticates a token over HTTPS basic auth.', scope: 'Needs read access to the repositories you will scan.' },
]

// The REST API suffix a self-hosted forge serves; only these providers take an API base URL.
const API_SUFFIX: Partial<Record<ConnectorProvider, string>> = { github: '/api/v3', gitlab: '/api/v4' }

const API_BASE_HINT: Partial<Record<ConnectorProvider, string>> = {
  github: 'Optional. For GitHub Enterprise Server, e.g. https://ghe.example.com/api/v3, so pull request decoration reaches it. Leave empty for github.com. The host must match Host and be on the operator allowlist.',
  gitlab: 'Optional. For self-managed GitLab, e.g. https://gitlab.example.com/api/v4, so merge request decoration reaches it. Leave empty for gitlab.com. The host must match Host and be on the operator allowlist.',
}

/**
 * Mirrors the server's shape checks so an obvious mistake is shown before submitting. The server
 * still decides: it also checks that the host equals the connector host and is allowlisted.
 */
function apiBaseError(provider: ConnectorProvider, raw: string): string | null {
  const value = raw.trim()
  if (value === '') return null
  const suffix = API_SUFFIX[provider]
  if (!suffix) return 'An API base URL applies only to GitHub Enterprise Server and self-managed GitLab.'
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return 'Enter an absolute URL such as https://host' + suffix + '.'
  }
  if (url.protocol !== 'https:') return 'The API base URL must use https.'
  if (url.username || url.password || value.includes('@')) return 'The API base URL must not contain credentials.'
  if (value.includes('?') || value.includes('#')) return 'The API base URL must not have a query or fragment.'
  if (!url.pathname.replace(/\/$/, '').endsWith(suffix)) return `The API base URL path must end in ${suffix}.`
  return null
}

const PROVIDER_LABEL: Record<string, string> = { github: 'GitHub', gitlab: 'GitLab', bitbucket: 'Bitbucket', 'azure-devops': 'Azure DevOps', generic: 'Generic' }

/**
 * Settings → Connectors. Tenant-scoped source-control connectors: a git host plus a personal access
 * token, so a server-initiated scan of a Project can clone a PRIVATE repository. The token is
 * write-only — entered here, sealed server-side, never shown again.
 */
export function Connectors() {
  const [connectors, setConnectors] = useState<Connector[] | null | undefined>(undefined)
  const [unsupported, setUnsupported] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  // An integration_admin may list connectors; adding (a new host and token) and removing one stay
  // with administrators (#1358). The server enforces both.
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  const canAdmin = isAdminRole(me?.role)

  const load = useCallback(() => {
    setLoadError(null)
    api
      .listConnectors()
      .then((list) => {
        if (list === null) {
          setUnsupported(true)
          setConnectors([])
        } else {
          setUnsupported(false)
          setConnectors(list)
        }
      })
      .catch((e) => setLoadError(e instanceof Error ? e.message : 'Failed to load connectors'))
  }, [])

  useEffect(() => load(), [load])

  return (
    <div className="space-y-6">
      <div className="max-w-3xl space-y-1">
        <p className="text-sm text-secondary">
          Connect a source-control host so a scan can clone a private repository. The token is encrypted at
          rest and supplied to git only at clone time; it is never shown again, logged, or placed on the
          command line.
        </p>
      </div>

      {unsupported ? (
        <EmptyState
          icon={Lock01}
          title="Connectors are not enabled on this deployment"
          hint="The server was built or configured without the connector store. Private-repo scanning is unavailable until it is wired."
        />
      ) : (
        <>
          {canAdmin ? (
            <AddConnector onCreated={load} />
          ) : (
            me && <p className="text-sm text-tertiary">Only tenant administrators can add or remove a connector.</p>
          )}
          {loadError && <ErrorState message={loadError} />}
          {connectors === undefined && !loadError && <Spinner label="Loading connectors…" />}
          {connectors && connectors.length === 0 && !loadError && (
            <EmptyState
              icon={GitBranch01}
              title="No connectors yet"
              hint="Add one above to scan a private repository on that host."
            />
          )}
          {connectors && connectors.length > 0 && <ConnectorList connectors={connectors} canRemove={canAdmin} onDeleted={load} />}
        </>
      )}
    </div>
  )
}

function AddConnector({ onCreated }: { onCreated: () => void }) {
  const [provider, setProvider] = useState<ConnectorProvider>('github')
  const [name, setName] = useState('')
  const [host, setHost] = useState('')
  const [username, setUsername] = useState('')
  const [token, setToken] = useState('')
  const [apiBase, setApiBase] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const providerMeta = PROVIDERS.find((p) => p.value === provider)
  const providerHint = providerMeta?.hint ?? ''
  const providerScope = providerMeta?.scope ?? ''
  const apiBaseHint = API_BASE_HINT[provider]
  // The field is shown only for providers that take it; a value typed for another provider is not sent.
  const effectiveApiBase = apiBaseHint ? apiBase.trim() : ''
  const apiBaseProblem = apiBaseError(provider, effectiveApiBase)
  const canSubmit = name.trim() !== '' && host.trim() !== '' && token.trim() !== '' && apiBaseProblem === null && !busy

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!canSubmit) return
    setBusy(true)
    setError(null)
    try {
      await api.createConnector({
        name: name.trim(),
        provider,
        host: host.trim(),
        username: username.trim() || undefined,
        token,
        apiBase: effectiveApiBase || undefined,
      })
      setName('')
      setHost('')
      setUsername('')
      setToken('')
      setApiBase('')
      setShowToken(false)
      onCreated()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to add connector')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="Add a connector">
      <form className="grid grid-cols-1 gap-4 sm:grid-cols-2" onSubmit={submit}>
        <Field label="Provider" htmlFor="conn-provider">
          <Select
            id="conn-provider"
            value={provider}
            onValueChange={(v) => setProvider(v as ConnectorProvider)}
            ariaLabel="Connector provider"
            className="w-full"
            options={PROVIDERS.map((p) => ({ value: p.value, label: p.label }))}
          />
        </Field>
        <Field label="Name" htmlFor="conn-name" hint="A label to recognize this connector.">
          <Input id="conn-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Production GitHub" autoComplete="off" />
        </Field>
        <Field label="Host" htmlFor="conn-host" hint={providerHint}>
          <Input id="conn-host" value={host} onChange={(e) => setHost(e.target.value)} placeholder={provider === 'azure-devops' ? 'dev.azure.com' : 'github.com'} autoComplete="off" spellCheck={false} />
        </Field>
        <Field label="Username" htmlFor="conn-user" hint="Optional; a sensible default is used per provider.">
          <Input id="conn-user" value={username} onChange={(e) => setUsername(e.target.value)} placeholder={provider === 'azure-devops' ? 'pat' : 'x-access-token'} autoComplete="off" spellCheck={false} />
        </Field>
        {apiBaseHint && (
          <Field label="API base URL" htmlFor="conn-api-base" hint={apiBaseHint}>
            <div>
              <Input
                id="conn-api-base"
                value={apiBase}
                onChange={(e) => setApiBase(e.target.value)}
                placeholder={provider === 'gitlab' ? 'https://gitlab.example.com/api/v4' : 'https://ghe.example.com/api/v3'}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={apiBaseProblem !== null}
                aria-describedby={apiBaseProblem ? 'conn-api-base-error' : undefined}
              />
              {apiBaseProblem && (
                <p id="conn-api-base-error" role="alert" className="mt-1 text-xs text-critical">
                  {apiBaseProblem}
                </p>
              )}
            </div>
          </Field>
        )}
        <Field label="Personal access token" htmlFor="conn-token" hint={providerScope}>
          <div className="relative">
            <Input
              id="conn-token"
              type={showToken ? 'text' : 'password'}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder={provider === 'azure-devops' ? 'Azure DevOps PAT' : 'ghp_…'}
              autoComplete="off"
              spellCheck={false}
              className="pr-10"
            />
            <button
              type="button"
              onClick={() => setShowToken((s) => !s)}
              aria-label={showToken ? 'Hide token' : 'Show token'}
              className="absolute inset-y-0 right-0 flex items-center px-3 text-tertiary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
            >
              {showToken ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
            </button>
          </div>
        </Field>
        <div className="flex items-end sm:col-span-2">
          <div className="flex-1">{error && <ErrorState message={error} />}</div>
          <Button type="submit" loading={busy} disabled={!canSubmit} className="ml-3 shrink-0">
            <Plus className="size-4" /> Add connector
          </Button>
        </div>
      </form>
    </Card>
  )
}

function ConnectorList({ connectors, canRemove, onDeleted }: { connectors: Connector[]; canRemove: boolean; onDeleted: () => void }) {
  return (
    <Card title="Connectors" bodyClass="p-0">
      <ul className="divide-y divide-secondary">
        {connectors.map((c) => (
          <ConnectorRow key={c.id} connector={c} canRemove={canRemove} onDeleted={onDeleted} />
        ))}
      </ul>
    </Card>
  )
}

function ConnectorRow({ connector, canRemove, onDeleted }: { connector: Connector; canRemove: boolean; onDeleted: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const remove = async () => {
    if (!window.confirm(`Remove the connector for ${connector.host}? A private-repo scan on that host will stop authenticating.`)) return
    setBusy(true)
    setError(null)
    try {
      await api.deleteConnector(connector.id)
      onDeleted()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove connector')
      setBusy(false)
    }
  }

  return (
    <li className="flex items-center gap-4 px-6 py-4">
      <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-secondary text-tertiary">
        <Key01 className="size-4" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-semibold text-primary">{connector.name}</span>
          <Pill className={cn('shrink-0')}>{PROVIDER_LABEL[connector.provider] ?? connector.provider}</Pill>
        </div>
        <p className="mt-0.5 truncate font-mono text-xs text-tertiary">
          {connector.host} · {connector.username}
        </p>
        {connector.apiBase && <p className="mt-0.5 truncate font-mono text-xs text-tertiary">API {connector.apiBase}</p>}
        {error && <p className="mt-1 text-xs text-critical">{error}</p>}
      </div>
      {canRemove && (
        <Button variant="secondary" onClick={remove} loading={busy} className="shrink-0" aria-label={`Remove connector ${connector.name}`}>
          <Trash01 className="size-4" /> Remove
        </Button>
      )}
    </li>
  )
}

export default Connectors
