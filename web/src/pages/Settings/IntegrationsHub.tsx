import {
  BellRinging01,
  BookOpen01,
  CheckDone01,
  Dataflow01,
  GitBranch01,
  Lock01,
  RefreshCw01,
  Send01,
  ShieldTick,
} from '@untitledui/icons'
import { useCallback, useEffect, useState, type ComponentType, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Button, EmptyState, ErrorState, InfoNote, Pill, Spinner, cn } from '../../components/ui'
import { api, ApiError, type Connector, type NotificationChannel, type NotificationDelivery } from '../../lib/api'
import { capabilityHint, disabledCapability, loadCapabilities, type CapabilityIndex } from '../../lib/capabilities'
import type { Capability, Integration, IntegrationOperation, IntegrationProviderDescriptor } from '../../lib/types'
import { canManageIntegrations } from '../../lib/roles'

/**
 * Settings → Integrations: one place for every integration, grouped by capability (EPIC #1327 WS9,
 * issue #1463). The hub reads only existing APIs. Configuration stays on the detail pages it links to
 * (CI/CD, Connectors, Alerting); a field an API does not expose is shown as "Not reported" instead of
 * being guessed.
 *
 * Gating follows the rest of the console: a capability the deployment reports as disabled renders
 * "off" with the switch that turns it on, a `planned` capability renders "not available in this build
 * yet", and a deployment that does not report capabilities is assumed on.
 */

export type HealthTone = 'good' | 'warning' | 'danger' | 'neutral'
export interface Health {
  label: string
  tone: HealthTone
}

interface CardFact {
  /** ISO timestamp, or null when there is none yet. */
  at: string | null
  detail?: string
}

/** Unavailable means the API behind this card does not expose the field at all. */
type Fact = CardFact | 'unavailable'

const UNAVAILABLE = 'Not reported by this integration'


export function IntegrationsHub() {
  const [capabilities, setCapabilities] = useState<CapabilityIndex | undefined>(undefined)
  const [role, setRole] = useState<string | undefined>(undefined)
  const [meError, setMeError] = useState<string | null>(null)
  const [generation, setGeneration] = useState(0)

  useEffect(() => {
    let live = true
    loadCapabilities().then((index) => {
      if (live) setCapabilities(index)
    })
    api
      .me()
      .then((me) => {
        if (live) setRole(me?.role ?? '')
      })
      .catch((caught) => {
        if (live) setMeError(message(caught))
      })
    return () => {
      live = false
    }
  }, [])

  if (meError) return <ErrorState message={`Could not load your permissions: ${meError}`} />
  if (capabilities === undefined || role === undefined) return <Spinner label="Loading integrations…" />

  // Everything the hub reads or tests needs manage_integrations (#1358), which admin and
  // integration_admin hold; adding or re-pointing a destination happens on the detail pages.
  const canAdmin = canManageIntegrations(role)

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-3xl text-sm text-secondary">
          Every external system Synapse talks to, grouped by what it is for. Each card shows the health, last
          success and last error its API reports; configure an integration on its detail page.
        </p>
        <Button variant="secondary" onClick={() => setGeneration((value) => value + 1)}>
          <RefreshCw01 className="size-4" /> Refresh
        </Button>
      </div>
      {!canAdmin && (
        <p className="rounded-lg border border-secondary bg-secondary/40 px-4 py-3 text-sm text-tertiary">
          You can view CI/CD integrations. Source control, messaging, SIEM and test actions need a tenant administrator or an integration administrator.
        </p>
      )}
      <CiCdGroup key={`ci-${generation}`} canAdmin={canAdmin} />
      <SourceControlGroup key={`scm-${generation}`} canAdmin={canAdmin} />
      <MessagingGroup key={`msg-${generation}`} canAdmin={canAdmin} capabilities={capabilities} />
      <UnavailableGroup
        title="Ticketing"
        icon={CheckDone01}
        info="Push confirmed findings to Jira and other trackers, with a link back on the finding."
        capability={capabilities?.get('ticketing') ?? null}
      />
      <UnavailableGroup
        title="Documentation"
        icon={BookOpen01}
        info="Publish engagement and assessment reports to Confluence and other documentation spaces."
        capability={capabilities?.get('docpublish') ?? null}
      />
      <SIEMGroup key={`siem-${generation}`} canAdmin={canAdmin} />
    </div>
  )
}

// ---- Group shell ----

type GroupStatus = 'on' | 'off' | 'planned' | 'restricted' | 'unknown' | 'available'

const GROUP_STATUS: Record<GroupStatus, { label: string; className: string }> = {
  on: { label: 'On', className: 'bg-low/10 text-low' },
  off: { label: 'Off', className: 'text-tertiary' },
  planned: { label: 'Not available yet', className: 'text-tertiary' },
  restricted: { label: 'Admin only', className: 'text-tertiary' },
  unknown: { label: 'Unknown', className: 'text-tertiary' },
  available: { label: 'Available', className: 'bg-low/10 text-low' },
}

function Group({
  title,
  icon: Icon,
  info,
  status,
  manage,
  links = [],
  children,
}: {
  title: string
  icon: ComponentType<{ className?: string }>
  info: string
  status: GroupStatus
  manage?: { to: string; label: string }
  /** Further configuration pages of the group, shown beside `manage`. */
  links?: Array<{ to: string; label: string }>
  children: ReactNode
}) {
  const headingId = `integration-group-${title.toLowerCase().replace(/[^a-z]+/g, '-')}`
  return (
    <section aria-labelledby={headingId} className="space-y-3">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="flex size-8 items-center justify-center rounded-lg bg-secondary text-tertiary">
            <Icon className="size-4" />
          </div>
          <h2 id={headingId} className="text-base font-semibold text-primary">{title}</h2>
          <InfoNote label={`About ${title}`}>{info}</InfoNote>
          <Pill className={GROUP_STATUS[status].className}>{GROUP_STATUS[status].label}</Pill>
        </div>
        {(manage || links.length > 0) && (
          <div className="flex flex-wrap items-center gap-4">
            {[...(manage ? [manage] : []), ...links].map((link) => (
              <Link key={link.to} to={link.to} className="text-sm font-semibold text-brand-secondary hover:underline">
                {link.label}
              </Link>
            ))}
          </div>
        )}
      </header>
      {children}
    </section>
  )
}

function Notice({ tone = 'neutral', children }: { tone?: 'neutral' | 'success'; children: ReactNode }) {
  return (
    <p role="status" className={cn('text-sm', tone === 'success' ? 'text-success-primary' : 'text-tertiary')}>
      {children}
    </p>
  )
}

// ---- Integration card ----

const TONE: Record<HealthTone, string> = {
  good: 'bg-low/10 text-low',
  warning: 'bg-medium/10 text-medium',
  danger: 'bg-high/10 text-high',
  neutral: '',
}

function IntegrationCard({
  name,
  kind,
  detail,
  health,
  lastSuccess,
  lastError,
  test,
}: {
  name: string
  kind: string
  detail: string
  health: Health | 'unavailable'
  lastSuccess: Fact
  lastError: Fact
  test: ReactNode
}) {
  return (
    <li aria-label={name} className="flex flex-col gap-4 rounded-xl border border-secondary bg-primary p-5 shadow-xs">
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="truncate text-sm font-semibold text-primary">{name}</span>
          <Pill>{kind}</Pill>
        </div>
        <p className="truncate font-mono text-xs text-tertiary" title={detail}>{detail}</p>
      </div>
      <dl className="grid gap-3 text-sm">
        <Row label="Health">
          {health === 'unavailable' ? <Unavailable /> : <Pill className={TONE[health.tone]}>{health.label}</Pill>}
        </Row>
        <Row label="Last success"><FactValue fact={lastSuccess} /></Row>
        <Row label="Last error"><FactValue fact={lastError} error /></Row>
      </dl>
      <div className="mt-auto">{test}</div>
    </li>
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[96px_minmax(0,1fr)] items-start gap-2">
      <dt className="text-xs font-medium uppercase tracking-wide text-tertiary">{label}</dt>
      <dd className="min-w-0 text-primary">{children}</dd>
    </div>
  )
}

function Unavailable() {
  return <span className="text-tertiary">{UNAVAILABLE}</span>
}

function FactValue({ fact, error }: { fact: Fact; error?: boolean }) {
  if (fact === 'unavailable') return <Unavailable />
  if (!fact.at) return <span className="text-tertiary">{error ? 'None' : 'Never'}</span>
  return (
    <span className="block min-w-0">
      <span>{formatDate(fact.at)}</span>
      {fact.detail && <span className={cn('block break-words text-xs', error ? 'text-high' : 'text-tertiary')}>{fact.detail}</span>}
    </span>
  )
}

function CardGrid({ children }: { children: ReactNode }) {
  return <ul className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{children}</ul>
}

function TestButton({
  name,
  canAdmin,
  disabledReason,
  onTest,
}: {
  name: string
  canAdmin: boolean
  disabledReason?: string
  onTest: () => Promise<void>
}) {
  const [busy, setBusy] = useState(false)
  const reason = !canAdmin ? 'Only tenant administrators and integration administrators can run a test.' : disabledReason
  return (
    <div className="space-y-1">
      <Button
        variant="secondary"
        aria-label={`Test ${name}`}
        disabled={!!reason}
        loading={busy}
        onClick={async () => {
          setBusy(true)
          try {
            await onTest()
          } finally {
            setBusy(false)
          }
        }}
      >
        <Send01 className="size-4" /> Test
      </Button>
      {reason && <p className="text-xs text-tertiary">{reason}</p>}
    </div>
  )
}

// ---- CI/CD ----

const TERMINAL = new Set(['succeeded', 'partial', 'failed', 'cancelled'])

/** Mirrors the health the CI/CD detail page shows for the same integration. */
export function ciHealth(integration: Integration, operations: IntegrationOperation[], now = Date.now(), supportsPoll = true): Health {
  const latest = operations[0]
  const active = operations.find((operation) => !TERMINAL.has(operation.state))
  if (active) return { label: 'Running', tone: 'neutral' }
  if (latest?.state === 'failed') return { label: 'Error', tone: 'danger' }
  if (latest?.state === 'partial') return { label: 'Partial', tone: 'warning' }
  if (!integration.enabled) return { label: 'Disabled', tone: 'neutral' }
  if (!supportsPoll) return { label: 'Healthy', tone: 'good' }
  const poll = operations.find((operation) => operation.type === 'poll' && operation.state === 'succeeded')
  const staleAfter = Math.max(integration.pollIntervalSeconds * 2, 600) * 1000
  if (!poll || now - Date.parse(poll.finishedAt ?? poll.updatedAt) > staleAfter) return { label: 'Stale', tone: 'warning' }
  return { label: 'Healthy', tone: 'good' }
}

function ciLastSuccess(operations: IntegrationOperation[]): CardFact {
  const operation = operations.find((item) => item.state === 'succeeded')
  return operation ? { at: operation.finishedAt ?? operation.updatedAt, detail: operationLabel(operation.type) } : { at: null }
}

function ciLastError(operations: IntegrationOperation[]): CardFact {
  const operation = operations.find((item) => item.state === 'failed' || item.state === 'partial')
  if (!operation) return { at: null }
  return { at: operation.finishedAt ?? operation.updatedAt, detail: operation.errors[0] ?? `${operationLabel(operation.type)} ${operation.state}` }
}

function operationLabel(type: IntegrationOperation['type']) {
  return type === 'test' ? 'Connection test' : type === 'discover' ? 'Discovery' : 'Poll'
}

interface CiItem {
  integration: Integration
  provider: IntegrationProviderDescriptor | undefined
  /** null when the operation history could not be read. */
  operations: IntegrationOperation[] | null
}

function CiCdGroup({ canAdmin }: { canAdmin: boolean }) {
  const [items, setItems] = useState<CiItem[] | undefined>(undefined)
  const [unsupported, setUnsupported] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const loadOperations = (integrationId: string) =>
    api.listIntegrationOperations(integrationId).then(
      (list) => [...list].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt)),
      () => null,
    )

  useEffect(() => {
    let live = true
    ;(async () => {
      try {
        const [providers, integrations] = await Promise.all([api.listIntegrationProviders(), api.listIntegrations()])
        const active = integrations.filter((item) => !item.archived)
        const operations = await Promise.all(active.map((item) => loadOperations(item.id)))
        if (!live) return
        setItems(active.map((integration, index) => ({
          integration,
          provider: providers.find((item) => item.provider === integration.provider),
          operations: operations[index],
        })))
      } catch (caught) {
        if (!live) return
        if (caught instanceof ApiError && caught.status === 404) setUnsupported(true)
        else setError(message(caught))
        setItems([])
      }
    })()
    return () => {
      live = false
    }
  }, [])

  async function test(item: CiItem) {
    setNotice(null)
    setError(null)
    try {
      await api.startIntegrationOperation(item.integration.id, 'test')
      setNotice(`Connection test queued for ${item.integration.name}.`)
      const operations = await loadOperations(item.integration.id)
      setItems((current) => current?.map((entry) => entry.integration.id === item.integration.id ? { ...entry, operations } : entry))
    } catch (caught) {
      setError(message(caught))
    }
  }

  return (
    <Group
      title="CI/CD"
      icon={Dataflow01}
      info="CI/CD and inbound SCM integrations. Poll-capable providers link external runs to Project analyses; inbound-only providers receive authenticated events."
      status={unsupported ? 'off' : 'on'}
      manage={unsupported ? undefined : { to: '/settings/integrations/ci', label: 'Manage CI/CD' }}
    >
      {notice && <Notice tone="success">{notice}</Notice>}
      {error && <ErrorState message={error} />}
      {items === undefined ? (
        <Spinner label="Loading CI/CD integrations…" />
      ) : unsupported ? (
        <EmptyState icon={Dataflow01} title="CI/CD integrations are not enabled on this deployment" hint="The server was started without the integrations framework." />
      ) : items.length === 0 && !error ? (
        <EmptyState icon={Dataflow01} title="No CI/CD integrations yet" hint={canAdmin ? 'Add one from Manage CI/CD.' : 'A tenant administrator can add one.'} />
      ) : (
        <CardGrid>
          {items.map((item) => {
            const history = item.operations
            const supportsTest = item.provider?.capabilities.includes('test_connection') ?? false
            const supportsPoll = item.provider?.capabilities.includes('read_runs') ?? true
            const running = history?.some((operation) => !TERMINAL.has(operation.state)) ?? false
            return (
              <IntegrationCard
                key={item.integration.id}
                name={item.integration.name}
                kind={item.provider?.name || item.integration.provider}
                detail={item.integration.endpoint}
                health={history ? ciHealth(item.integration, history, Date.now(), supportsPoll) : 'unavailable'}
                lastSuccess={history ? ciLastSuccess(history) : 'unavailable'}
                lastError={history ? ciLastError(history) : 'unavailable'}
                test={
                  <TestButton
                    name={item.integration.name}
                    canAdmin={canAdmin}
                    disabledReason={
                      !supportsTest ? 'This provider has no connection test.'
                        : !item.integration.credentialConfigured ? 'Add credentials before testing.'
                          : running ? 'An operation is already running.' : undefined
                    }
                    onTest={() => test(item)}
                  />
                }
              />
            )
          })}
        </CardGrid>
      )}
    </Group>
  )
}

// ---- Source control ----

const SCM_LABEL: Record<string, string> = { github: 'GitHub', gitlab: 'GitLab', bitbucket: 'Bitbucket', generic: 'Generic' }

function SourceControlGroup({ canAdmin }: { canAdmin: boolean }) {
  const [connectors, setConnectors] = useState<Connector[] | null | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!canAdmin) return
    let live = true
    api.listConnectors().then(
      (list) => { if (live) setConnectors(list) },
      (caught) => { if (live) { setError(message(caught)); setConnectors([]) } },
    )
    return () => {
      live = false
    }
  }, [canAdmin])

  const status: GroupStatus = !canAdmin ? 'restricted' : connectors === null ? 'off' : 'on'
  return (
    <Group
      title="Source control"
      icon={GitBranch01}
      info="Git hosts a server-initiated scan can clone a private repository from. The token is write-only."
      status={status}
      manage={canAdmin && connectors !== null ? { to: '/settings/connectors', label: 'Manage connectors' } : undefined}
    >
      {!canAdmin ? (
        <EmptyState icon={Lock01} title="Administrator access required" hint="Only tenant administrators and integration administrators can see source-control connectors." />
      ) : connectors === undefined ? (
        <Spinner label="Loading connectors…" />
      ) : connectors === null ? (
        <EmptyState icon={GitBranch01} title="Connectors are not enabled on this deployment" hint="The server was built or configured without the connector store." />
      ) : (
        <>
          {error && <ErrorState message={error} />}
          {connectors.length === 0 && !error ? (
            <EmptyState icon={GitBranch01} title="No source-control connectors yet" hint="Add one from Manage connectors." />
          ) : (
            <CardGrid>
              {connectors.map((connector) => (
                <IntegrationCard
                  key={connector.id}
                  name={connector.name}
                  kind={SCM_LABEL[connector.provider] ?? connector.provider}
                  detail={`${connector.host} · ${connector.username}`}
                  health="unavailable"
                  lastSuccess="unavailable"
                  lastError="unavailable"
                  test={<p className="text-xs text-tertiary">No connection test for connectors yet. A failed clone shows on the scan.</p>}
                />
              ))}
            </CardGrid>
          )}
        </>
      )}
    </Group>
  )
}

// ---- Messaging ----

/** Health from the channel's newest deliveries (newest first, as the API returns them). */
export function channelHealth(channel: NotificationChannel, deliveries: NotificationDelivery[]): Health {
  if (!channel.enabled) return { label: 'Disabled', tone: 'neutral' }
  // The worker's own verdict wins over the delivery history: a paused channel sends nothing (#1464).
  if (channel.health?.state === 'paused') return { label: 'Paused', tone: 'danger' }
  const latest = deliveries.find((delivery) => delivery.state !== 'cancelled')
  if (!latest) return { label: 'No deliveries yet', tone: 'neutral' }
  if (latest.state === 'delivered') return { label: 'Healthy', tone: 'good' }
  if (latest.state === 'dead_letter') return { label: 'Failing', tone: 'danger' }
  if (latest.state === 'retrying') return { label: 'Retrying', tone: 'warning' }
  return { label: 'Pending', tone: 'neutral' }
}

function channelLastSuccess(deliveries: NotificationDelivery[]): CardFact {
  const delivery = deliveries.find((item) => item.state === 'delivered')
  return delivery ? { at: delivery.delivered_at ?? delivery.updated_at } : { at: null }
}

/**
 * The newer of the last delivery error and the channel's own health record. A paused channel's
 * failures can be older than the newest 50 deliveries, or their deliveries cancelled, so the
 * delivery page alone would show "None" for a channel that paused on http_404.
 */
export function channelLastError(channel: NotificationChannel, deliveries: NotificationDelivery[]): CardFact {
  const delivery = deliveries.find((item) => !!item.last_error)
  const fromDelivery: CardFact = delivery ? { at: delivery.updated_at, detail: delivery.last_error } : { at: null }
  const health = channel.health
  if (!health?.last_failure_code || !health.last_failure_at) return fromDelivery
  if (fromDelivery.at && new Date(fromDelivery.at) >= new Date(health.last_failure_at)) return fromDelivery
  return { at: health.last_failure_at, detail: health.last_failure_code }
}

interface ChannelItem {
  channel: NotificationChannel
  /** null when the delivery history could not be read. */
  deliveries: NotificationDelivery[] | null
}

function MessagingGroup({ canAdmin, capabilities }: { canAdmin: boolean; capabilities: CapabilityIndex }) {
  const off = disabledCapability(capabilities, 'notifications')
  const channelTypes = capabilities?.get('notifications.channel_types')?.values ?? []
  const [items, setItems] = useState<ChannelItem[] | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const loadDeliveries = useCallback(
    (channelId: string) => api.notificationDeliveryPage({ channel_id: channelId }).then((page) => page.items ?? [], () => null),
    [],
  )

  useEffect(() => {
    if (off || !canAdmin) return
    let live = true
    ;(async () => {
      try {
        const channels = await api.listNotificationChannels()
        const deliveries = await Promise.all(channels.map((channel) => loadDeliveries(channel.id)))
        if (live) setItems(channels.map((channel, index) => ({ channel, deliveries: deliveries[index] })))
      } catch (caught) {
        if (!live) return
        setError(message(caught))
        setItems([])
      }
    })()
    return () => {
      live = false
    }
  }, [off, canAdmin, loadDeliveries])

  async function test(item: ChannelItem) {
    setNotice(null)
    setError(null)
    try {
      const result = await api.testNotificationChannel(item.channel.id)
      setNotice(`Test delivery queued for ${item.channel.name} (${result.delivery_id}).`)
      const deliveries = await loadDeliveries(item.channel.id)
      setItems((current) => current?.map((entry) => entry.channel.id === item.channel.id ? { ...entry, deliveries } : entry))
    } catch (caught) {
      setError(message(caught))
    }
  }

  const status: GroupStatus = off ? 'off' : !canAdmin ? 'restricted' : 'on'
  return (
    <Group
      title="Messaging"
      icon={BellRinging01}
      info={`Notification channels that deliver alerts to people.${channelTypes.length > 0 ? ` This build delivers to: ${channelTypes.join(', ')}.` : ''}`}
      status={status}
      manage={status === 'on' ? { to: '/settings/alerting', label: 'Manage channels' } : undefined}
      links={status === 'on' ? [{ to: '/settings/templates', label: 'Message templates' }] : undefined}
    >
      {notice && <Notice tone="success">{notice}</Notice>}
      {off ? (
        <EmptyState icon={BellRinging01} title="Notifications are off" hint={capabilityHint(off)} />
      ) : !canAdmin ? (
        <EmptyState icon={Lock01} title="Administrator access required" hint="Only tenant administrators and integration administrators can see notification channels and their deliveries." />
      ) : items === undefined ? (
        <Spinner label="Loading notification channels…" />
      ) : (
        <>
          {error && <ErrorState message={error} />}
          {items.length === 0 && !error ? (
            <EmptyState icon={BellRinging01} title="No notification channels yet" hint="Add one from Manage channels." />
          ) : (
            <CardGrid>
              {items.map((item) => (
                <IntegrationCard
                  key={item.channel.id}
                  name={item.channel.name}
                  kind={item.channel.type}
                  detail={item.channel.destination}
                  health={item.deliveries ? channelHealth(item.channel, item.deliveries) : 'unavailable'}
                  lastSuccess={item.deliveries ? channelLastSuccess(item.deliveries) : 'unavailable'}
                  lastError={item.deliveries ? channelLastError(item.channel, item.deliveries) : 'unavailable'}
                  test={
                    <TestButton
                      name={item.channel.name}
                      canAdmin={canAdmin}
                      // The API refuses a test on a paused channel (409), as the Alerting page shows.
                      disabledReason={item.channel.health?.state === 'paused' ? 'Resume the channel on the Alerting page before sending a test.' : undefined}
                      onTest={() => test(item)}
                    />
                  }
                />
              ))}
            </CardGrid>
          )}
        </>
      )}
    </Group>
  )
}

// ---- SIEM ----

function SIEMGroup({ canAdmin }: { canAdmin: boolean }) {
  const [count, setCount] = useState<number | null | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!canAdmin) return
    let live = true
    api.listSIEMSinks().then(
      (sinks) => { if (live) setCount(sinks?.length ?? null) },
      (caught) => { if (live) setError(message(caught)) },
    )
    return () => { live = false }
  }, [canAdmin])

  return (
    <Group
      title="SIEM"
      icon={ShieldTick}
      info="Export audit and incident events to Splunk HEC, Elasticsearch, or Microsoft Sentinel. Stream status and connection tests are on the SIEM settings page."
      status={!canAdmin ? 'restricted' : error || count === undefined ? 'unknown' : count === null ? 'off' : 'available'}
      manage={canAdmin && count !== null && count !== undefined ? { to: '/settings/siem', label: 'Manage SIEM streams' } : undefined}
    >
      {!canAdmin ? (
        <EmptyState icon={Lock01} title="Administrator access required" hint="Only tenant administrators and integration administrators can see SIEM destinations and their status." />
      ) : error ? (
        <ErrorState message={error} />
      ) : count === undefined ? (
        <Spinner label="Loading SIEM streams…" />
      ) : count === null ? (
        <EmptyState icon={ShieldTick} title="SIEM streams are not enabled" hint="This server has no SIEM sink API." />
      ) : (
        <EmptyState icon={ShieldTick} title={count === 0 ? 'No SIEM destinations yet' : `${count} SIEM destination${count === 1 ? '' : 's'} configured`} hint="Manage destinations, stream status and connection tests on the SIEM settings page." />
      )}
    </Group>
  )
}

// ---- Groups with no console integration in this build ----

function UnavailableGroup({
  title,
  icon,
  info,
  capability,
}: {
  title: string
  icon: ComponentType<{ className?: string }>
  info: string
  capability: Capability | null
}) {
  // A capability switched off names its switch. Planned or unreported both mean there is nothing to
  // configure in this build. A server that reports it on is ahead of this console, so say that.
  const off = capability && !capability.enabled && !capability.planned && capability.switch ? capability : null
  const onServer = !!capability?.enabled && !capability.planned
  return (
    <Group title={title} icon={icon} info={info} status={off ? 'off' : 'planned'}>
      <EmptyState
        icon={icon}
        title={off ? `${title} is off` : onServer ? `${title} is on, but this console cannot show it yet` : `${title} is not available in this build yet`}
        hint={off ? capabilityHint(off) : undefined}
      />
    </Group>
  )
}

function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

function message(error: unknown) {
  return error instanceof Error ? error.message : 'An unexpected error occurred.'
}

export default IntegrationsHub
