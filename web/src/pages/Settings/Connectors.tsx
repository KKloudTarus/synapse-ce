import { Eye, EyeOff, GitBranch01, Key01, Lock01, Plus, Trash01 } from '@untitledui/icons'
import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type Connector, type ConnectorProvider } from '../../lib/api'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../../components/ui'

const PROVIDERS: { value: ConnectorProvider; label: string; hint: string; scope: string }[] = [
  { value: 'github', label: 'GitHub', hint: 'github.com or GitHub Enterprise; username defaults to x-access-token.', scope: 'Needs the classic repo scope, or a fine-grained token with Contents: Read.' },
  { value: 'gitlab', label: 'GitLab', hint: 'gitlab.com or self-managed; username defaults to oauth2.', scope: 'Needs a token with the read_repository scope.' },
  { value: 'bitbucket', label: 'Bitbucket', hint: 'bitbucket.org or Data Center; set the username the token belongs to.', scope: 'Needs an app password with Repositories: Read.' },
  { value: 'generic', label: 'Generic', hint: 'Any git host that authenticates a token over HTTPS basic auth.', scope: 'Needs read access to the repositories you will scan.' },
]

const PROVIDER_LABEL: Record<string, string> = { github: 'GitHub', gitlab: 'GitLab', bitbucket: 'Bitbucket', generic: 'Generic' }

/**
 * Settings → Connectors. Tenant-scoped source-control connectors: a git host plus a personal access
 * token, so a server-initiated scan of a Project can clone a PRIVATE repository. The token is
 * write-only — entered here, sealed server-side, never shown again.
 */
export function Connectors() {
  const [connectors, setConnectors] = useState<Connector[] | null | undefined>(undefined)
  const [unsupported, setUnsupported] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)

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
          <AddConnector onCreated={load} />
          {loadError && <ErrorState message={loadError} />}
          {connectors === undefined && <Spinner label="Loading connectors…" />}
          {connectors && connectors.length === 0 && !loadError && (
            <EmptyState
              icon={GitBranch01}
              title="No connectors yet"
              hint="Add one above to scan a private repository on that host."
            />
          )}
          {connectors && connectors.length > 0 && <ConnectorList connectors={connectors} onDeleted={load} />}
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
  const [showToken, setShowToken] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const providerMeta = PROVIDERS.find((p) => p.value === provider)
  const providerHint = providerMeta?.hint ?? ''
  const providerScope = providerMeta?.scope ?? ''
  const canSubmit = name.trim() !== '' && host.trim() !== '' && token.trim() !== '' && !busy

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!canSubmit) return
    setBusy(true)
    setError(null)
    try {
      await api.createConnector({ name: name.trim(), provider, host: host.trim(), username: username.trim() || undefined, token })
      setName('')
      setHost('')
      setUsername('')
      setToken('')
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
            options={PROVIDERS.map((p) => ({ value: p.value, label: p.label }))}
          />
        </Field>
        <Field label="Name" htmlFor="conn-name" hint="A label to recognize this connector.">
          <Input id="conn-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Production GitHub" autoComplete="off" />
        </Field>
        <Field label="Host" htmlFor="conn-host" hint={providerHint}>
          <Input id="conn-host" value={host} onChange={(e) => setHost(e.target.value)} placeholder="github.com" autoComplete="off" spellCheck={false} />
        </Field>
        <Field label="Username" htmlFor="conn-user" hint="Optional; a sensible default is used per provider.">
          <Input id="conn-user" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="x-access-token" autoComplete="off" spellCheck={false} />
        </Field>
        <Field label="Personal access token" htmlFor="conn-token" hint={providerScope}>
          <div className="relative">
            <Input
              id="conn-token"
              type={showToken ? 'text' : 'password'}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="ghp_…"
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

function ConnectorList({ connectors, onDeleted }: { connectors: Connector[]; onDeleted: () => void }) {
  return (
    <Card title="Connectors" bodyClass="p-0">
      <ul className="divide-y divide-secondary">
        {connectors.map((c) => (
          <ConnectorRow key={c.id} connector={c} onDeleted={onDeleted} />
        ))}
      </ul>
    </Card>
  )
}

function ConnectorRow({ connector, onDeleted }: { connector: Connector; onDeleted: () => void }) {
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
        {error && <p className="mt-1 text-xs text-critical">{error}</p>}
      </div>
      <Button variant="secondary" onClick={remove} loading={busy} className="shrink-0" aria-label={`Remove connector ${connector.name}`}>
        <Trash01 className="size-4" /> Remove
      </Button>
    </li>
  )
}

export default Connectors
