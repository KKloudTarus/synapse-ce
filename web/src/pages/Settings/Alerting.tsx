import { useCallback, useEffect, useState } from 'react'
import { BellRinging01, Plus, Send01, Trash01 } from '@untitledui/icons'
import { api, AlertNotEnabledError, ApiError } from '../../lib/api'
import type {
  NotificationChannel,
  NotificationChannelType,
  NotificationDelivery,
  NotificationEventType,
  NotificationRule,
} from '../../lib/api'
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  Field,
  Input,
  Pill,
  Select,
  Spinner,
} from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { useFetch } from '../../hooks'

const EVENTS: { value: NotificationEventType; label: string }[] = [
  { value: 'vulnerability_action.created', label: 'Vulnerability risk action' },
  { value: 'quality_gate.failed', label: 'Quality gate failed' },
  { value: 'sla.approaching_deadline', label: 'SLA approaching deadline' },
  { value: 'fleet.agent.offline', label: 'Fleet agent offline' },
  { value: 'scan.completed', label: 'Scan completed' },
  { value: 'incident.created', label: 'Incident created' },
]
const stateTone: Record<string, string> = {
  delivered: 'text-success-primary',
  pending: 'text-tertiary',
  retrying: 'text-warning-primary',
  dead_letter: 'text-error-primary',
  cancelled: 'text-tertiary',
}

export function Alerting() {
  const { notify } = useToast()
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  const canAdmin = me?.role === 'admin' || me?.role === 'owner'
  const [channels, setChannels] = useState<
    NotificationChannel[] | null | undefined
  >(undefined)
  const [editingChannel, setEditingChannel] = useState<
    NotificationChannel | undefined
  >()
  const [editingRule, setEditingRule] = useState<NotificationRule | undefined>()
  const [historyVersion, setHistoryVersion] = useState(0)
  const [rules, setRules] = useState<NotificationRule[]>([])
  const [unsupported, setUnsupported] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const load = useCallback(async () => {
    setError(null)
    if (typeof api.listNotificationChannels !== 'function') {
      setUnsupported(true)
      setChannels([])
      return
    }
    try {
      const c = await api.listNotificationChannels()
      if (c === null) {
        setUnsupported(true)
        setChannels([])
        return
      }
      setUnsupported(false)
      setChannels(c)
      setRules((await api.listNotificationRules()) ?? [])
      setHistoryVersion((v) => v + 1)
    } catch (e) {
      setChannels([])
      setError(
        e instanceof Error ? e.message : 'Failed to load notification settings',
      )
    }
  }, [])
  useEffect(() => {
    void load()
  }, [load])
  return (
    <div className="space-y-6">
      <LegacyAlertTest canAdmin={canAdmin} />
      {unsupported ? (
        <EmptyState
          icon={BellRinging01}
          title="Notification framework is not enabled"
          hint="Contact your deployment administrator to enable notifications."
        />
      ) : (
        <>
          <ChannelCreate
            key={editingChannel?.id ?? 'new-channel'}
            initial={editingChannel}
            canAdmin={canAdmin}
            onCreated={() => {
              setEditingChannel(undefined)
              void load()
            }}
          />
          {error && <ErrorState message={error} />}{' '}
          {channels === undefined && (
            <Spinner label="Loading notification settings…" />
          )}
          {channels && (
            <ChannelList
              channels={channels}
              canAdmin={canAdmin}
              refresh={load}
              notify={notify}
              onEdit={setEditingChannel}
            />
          )}
          {channels && channels.length > 0 && (
            <RuleCreate
              channels={channels}
              canAdmin={canAdmin}
              key={editingRule?.id ?? 'new-rule'}
              initial={editingRule}
              onCreated={() => {
                setEditingRule(undefined)
                void load()
              }}
            />
          )}
          <RuleList
            onEdit={setEditingRule}
            rules={rules}
            channels={channels ?? []}
            canAdmin={canAdmin}
            refresh={load}
          />
          {canAdmin && channels !== undefined && (
            <DeliveryHistory key={historyVersion} channels={channels ?? []} />
          )}
        </>
      )}
    </div>
  )
}

function LegacyAlertTest({ canAdmin }: { canAdmin: boolean }) {
  const { notify } = useToast()
  const [busy, setBusy] = useState(false)
  const [available, setAvailable] = useState(true)
  const [result, setResult] = useState<{
    acknowledged: boolean
    error?: string
    outcome?: { delivered: number; failed: number; auditFailed: number }
  } | null>(null)
  async function send() {
    setBusy(true)
    setResult(null)
    try {
      const r = await api.testAlert()
      setResult(r)
      notify(
        r.acknowledged
          ? 'Legacy incident alert delivered.'
          : r.error || 'No legacy sink acknowledged the alert.',
        r.acknowledged ? 'success' : 'error',
      )
    } catch (e) {
      if (e instanceof AlertNotEnabledError) setAvailable(false)
      else notify(e instanceof Error ? e.message : 'Test failed', 'error')
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card title="Legacy incident webhook">
      <p className="text-sm text-secondary">
        Compatibility path configured with SYNAPSE_ALERT_WEBHOOK_*. New tenant
        rules below use the durable worker pipeline.
      </p>
      {!available && (
        <p className="mt-3 text-sm font-medium text-tertiary">
          Alerting is not enabled
        </p>
      )}
      {result && (
        <div className="mt-3 text-sm text-secondary">
          <p className="font-semibold text-primary">
            {result.acknowledged ? 'Acknowledged' : 'No acknowledgement'}
          </p>
          {result.error && <p>{result.error}</p>}
          {result.outcome && (
            <dl className="mt-2 flex gap-4">
              <div>
                <dt>Delivered</dt>
                <dd>{result.outcome.delivered}</dd>
              </div>
              <div>
                <dt>Failed</dt>
                <dd>{result.outcome.failed}</dd>
              </div>
              <div>
                <dt>Audit failed</dt>
                <dd>{result.outcome.auditFailed}</dd>
              </div>
            </dl>
          )}
        </div>
      )}
      <div className="mt-4">
        <Button
          variant="secondary"
          loading={busy}
          disabled={!canAdmin || !available}
          onClick={send}
        >
          <Send01 className="size-4" />
          Send test alert
        </Button>
      </div>
    </Card>
  )
}

function ChannelCreate({
  initial,
  canAdmin,
  onCreated,
}: {
  initial?: NotificationChannel
  canAdmin: boolean
  onCreated: () => void
}) {
  const [type, setType] = useState<NotificationChannelType>(
    initial?.type ?? 'webhook',
  )
  const [name, setName] = useState(initial?.name ?? '')
  const [url, setURL] = useState('')
  const [secret, setSecret] = useState('')
  const [recipients, setRecipients] = useState(
    initial?.recipients?.join(', ') ?? '',
  )
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const input = {
        name: name.trim(),
        type,
        enabled: initial?.enabled ?? true,
        revision: initial?.revision,
        url: type === 'email' ? undefined : url.trim(),
        secret: type === 'webhook' ? secret : undefined,
        recipients:
          type === 'email'
            ? recipients
                .split(',')
                .map((x) => x.trim())
                .filter(Boolean)
            : undefined,
      }
      if (initial) await api.updateNotificationChannel(initial.id, input)
      else await api.createNotificationChannel(input)
      setName('')
      setURL('')
      setSecret('')
      setRecipients('')
      onCreated()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Failed to create channel')
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card
      title={initial ? 'Edit notification channel' : 'Add notification channel'}
    >
      {initial && (
        <p className="mb-4 text-sm text-tertiary">
          Leave URL and secret blank to keep them. To replace a webhook
          destination, supply both a new URL and signing secret.
        </p>
      )}
      <form className="grid grid-cols-1 gap-4 md:grid-cols-2" onSubmit={submit}>
        <Field label="Type" htmlFor="notification-type">
          <Select
            id="notification-type"
            disabled={!!initial}
            value={type}
            onValueChange={(v) => setType(v as NotificationChannelType)}
            options={[
              { value: 'webhook', label: 'Signed webhook' },
              { value: 'slack', label: 'Slack incoming webhook' },
              { value: 'email', label: 'Email (SMTP)' },
            ]}
          />
        </Field>
        <Field label="Name" htmlFor="notification-name">
          <Input
            id="notification-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Security operations"
          />
        </Field>
        {type === 'email' ? (
          <Field
            label="Recipients"
            htmlFor="notification-recipients"
            hint="Comma-separated; each recipient is delivered independently."
          >
            <Input
              id="notification-recipients"
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              placeholder="security@example.com"
            />
          </Field>
        ) : (
          <Field
            label={type === 'slack' ? 'Slack webhook URL' : 'Webhook URL'}
            htmlFor="notification-url"
          >
            <Input
              id="notification-url"
              type="password"
              value={url}
              onChange={(e) => setURL(e.target.value)}
              placeholder="https://…"
              autoComplete="off"
            />
          </Field>
        )}
        {type === 'webhook' && (
          <Field
            label="HMAC secret"
            htmlFor="notification-secret"
            hint="At least 16 characters; write-only after save."
          >
            <Input
              id="notification-secret"
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              autoComplete="new-password"
            />
          </Field>
        )}
        <div className="flex items-end md:col-span-2">
          <div className="flex-1">
            {error && <ErrorState message={error} />}
          </div>
          <Button
            type="submit"
            loading={busy}
            disabled={
              !canAdmin ||
              !name.trim() ||
              (type === 'email'
                ? !recipients.trim()
                : !initial && !url.trim()) ||
              (type === 'webhook' &&
                (!initial || !!url || !!secret) &&
                (secret.length < 16 || !url.trim()))
            }
          >
            <Plus className="size-4" />
            {initial ? 'Save channel' : 'Add channel'}
          </Button>
          {initial && (
            <Button variant="secondary" onClick={onCreated}>
              Cancel
            </Button>
          )}
        </div>
      </form>
    </Card>
  )
}

function ChannelList({
  onEdit,
  channels,
  canAdmin,
  refresh,
  notify,
}: {
  onEdit: (channel: NotificationChannel) => void
  channels: NotificationChannel[]
  canAdmin: boolean
  refresh: () => void
  notify: (message: string, tone?: 'success' | 'error' | 'info') => void
}) {
  async function action(fn: () => Promise<void>) {
    try {
      await fn()
    } catch (e) {
      notify(e instanceof Error ? e.message : 'Channel action failed', 'error')
    }
  }
  if (channels.length === 0)
    return (
      <EmptyState
        icon={BellRinging01}
        title="No notification channels"
        hint="Add a signed webhook, Slack incoming webhook, or email destination."
      />
    )
  async function toggle(c: NotificationChannel) {
    await api.updateNotificationChannel(c.id, {
      name: c.name,
      type: c.type,
      enabled: !c.enabled,
      recipients: c.recipients,
      revision: c.revision,
    })
    refresh()
  }
  return (
    <Card title="Channels" bodyClass="p-0">
      <ul className="divide-y divide-secondary">
        {channels.map((c) => (
          <li
            key={c.id}
            className="flex flex-wrap items-center gap-3 px-5 py-4"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-primary">{c.name}</span>
                <Pill
                  className={
                    c.enabled ? 'text-success-primary' : 'text-tertiary'
                  }
                >
                  {c.enabled ? 'Enabled' : 'Disabled'}
                </Pill>
                <Pill>{c.type}</Pill>
              </div>
              <p className="truncate text-sm text-tertiary">{c.destination}</p>
            </div>
            <Button
              variant="secondary"
              disabled={!canAdmin}
              onClick={async () => {
                await action(async () => {
                  const r = await api.testNotificationChannel(c.id)
                  notify(`Test queued as ${r.delivery_id}.`, 'success')
                  refresh()
                })
              }}
            >
              <Send01 className="size-4" />
              Test
            </Button>
            <Button
              variant="secondary"
              disabled={!canAdmin}
              onClick={() => void action(() => toggle(c))}
            >
              {c.enabled ? 'Disable' : 'Enable'}
            </Button>
            <Button
              variant="secondary"
              disabled={!canAdmin}
              onClick={() => onEdit(c)}
            >
              Edit channel
            </Button>
            <Button
              variant="secondary"
              disabled={!canAdmin}
              aria-label={`Delete ${c.name}`}
              onClick={async () => {
                await action(async () => {
                  await api.deleteNotificationChannel(c.id, c.revision)
                  refresh()
                })
              }}
            >
              <Trash01 className="size-4" />
            </Button>
          </li>
        ))}
      </ul>
    </Card>
  )
}

function RuleCreate({
  initial,
  channels,
  canAdmin,
  onCreated,
}: {
  initial?: NotificationRule
  channels: NotificationChannel[]
  canAdmin: boolean
  onCreated: () => void
}) {
  const [name, setName] = useState(initial?.name ?? '')
  const [event, setEvent] = useState<NotificationEventType>(
    initial?.event_type ?? 'vulnerability_action.created',
  )
  const [selected, setSelected] = useState<string[]>(
    initial?.channel_ids ?? [channels[0]?.id].filter(Boolean),
  )
  const [engagements, setEngagements] = useState(
    initial?.engagement_ids?.join(', ') ?? '',
  )
  const [actions, setActions] = useState(
    initial?.action_types?.join(', ') ?? '',
  )
  const [error, setError] = useState<string | null>(null)
  const [severity, setSeverity] = useState(initial?.min_severity ?? 'high')
  const [leadHours, setLeadHours] = useState(
    String((initial?.lead_time_seconds ?? 86400) / 3600),
  )
  const [busy, setBusy] = useState(false)
  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const input = {
        name: name.trim(),
        enabled: initial?.enabled ?? true,
        event_type: event,
        channel_ids: selected,
        engagement_ids: engagements
          .split(',')
          .map((x) => x.trim())
          .filter(Boolean),
        action_types:
          event === 'vulnerability_action.created'
            ? actions
                .split(',')
                .map((x) => x.trim())
                .filter(Boolean)
            : undefined,
        min_severity:
          event === 'vulnerability_action.created' ||
          event === 'incident.created'
            ? severity
            : undefined,
        lead_time_seconds:
          event === 'sla.approaching_deadline'
            ? Number(leadHours) * 3600
            : undefined,
      }
      if (initial)
        await api.updateNotificationRule(initial.id, {
          ...input,
          revision: initial.revision,
        })
      else await api.createNotificationRule(input)
      setName('')
      onCreated()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save rule')
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card title={initial ? 'Edit routing rule' : 'Add routing rule'}>
      <form className="grid grid-cols-1 gap-4 md:grid-cols-2" onSubmit={submit}>
        <Field label="Name" htmlFor="notification-rule-name">
          <Input
            id="notification-rule-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="High risk to security team"
          />
        </Field>
        <Field label="Event" htmlFor="notification-event">
          <Select
            id="notification-event"
            value={event}
            onValueChange={(v) => setEvent(v as NotificationEventType)}
            options={EVENTS}
          />
        </Field>
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium text-secondary">
            Channels
          </legend>
          {channels.map((c) => (
            <label key={c.id} className="flex gap-2 text-sm text-secondary">
              <input
                type="checkbox"
                checked={selected.includes(c.id)}
                onChange={(e) =>
                  setSelected(
                    e.target.checked
                      ? [...selected, c.id]
                      : selected.filter((id) => id !== c.id),
                  )
                }
              />
              {c.name}
            </label>
          ))}
        </fieldset>
        <Field
          label="Engagement IDs (optional)"
          htmlFor="notification-engagements"
          hint="Comma-separated; leave blank for all engagements."
        >
          <Input
            id="notification-engagements"
            value={engagements}
            onChange={(e) => setEngagements(e.target.value)}
          />
        </Field>
        {event === 'vulnerability_action.created' && (
          <Field
            label="Action types (optional)"
            htmlFor="notification-actions"
            hint="new_exposure, escalation, withdrawal, reexposure, retest_required, risk_review"
          >
            <Input
              id="notification-actions"
              value={actions}
              onChange={(e) => setActions(e.target.value)}
            />
          </Field>
        )}
        {(event === 'vulnerability_action.created' ||
          event === 'incident.created') && (
          <Field label="Minimum severity" htmlFor="notification-severity">
            <Select
              id="notification-severity"
              value={severity}
              onValueChange={setSeverity}
              options={['critical', 'high', 'medium', 'low', 'info'].map(
                (v) => ({ value: v, label: v }),
              )}
            />
          </Field>
        )}
        {event === 'sla.approaching_deadline' && (
          <Field label="Lead time (hours)" htmlFor="notification-lead">
            <Input
              id="notification-lead"
              type="number"
              min="1"
              max="720"
              value={leadHours}
              onChange={(e) => setLeadHours(e.target.value)}
            />
          </Field>
        )}
        {error && <ErrorState message={error} />}
        <div className="flex justify-end gap-2 md:col-span-2">
          <Button
            type="submit"
            loading={busy}
            disabled={
              !canAdmin ||
              !name.trim() ||
              selected.length === 0 ||
              (event === 'sla.approaching_deadline' &&
                (!Number.isFinite(Number(leadHours)) ||
                  Number(leadHours) < 1 ||
                  Number(leadHours) > 720))
            }
          >
            <Plus className="size-4" />
            {initial ? 'Save rule' : 'Add rule'}
          </Button>
          {initial && (
            <Button variant="secondary" onClick={onCreated}>
              Cancel
            </Button>
          )}
        </div>
      </form>
    </Card>
  )
}

function RuleList({
  onEdit,
  rules,
  channels,
  canAdmin,
  refresh,
}: {
  onEdit: (rule: NotificationRule) => void
  rules: NotificationRule[]
  channels: NotificationChannel[]
  canAdmin: boolean
  refresh: () => void
}) {
  const { notify } = useToast()
  async function action(fn: () => Promise<void>) {
    try {
      await fn()
    } catch (e) {
      notify(e instanceof Error ? e.message : 'Rule action failed', 'error')
    }
  }
  if (rules.length === 0) return null
  const channelName = (id: string) =>
    channels.find((c) => c.id === id)?.name ?? id
  return (
    <Card title="Routing rules" bodyClass="p-0">
      <ul className="divide-y divide-secondary">
        {rules.map((r) => (
          <li
            key={r.id}
            className="flex flex-wrap items-center gap-3 px-5 py-4"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-primary">{r.name}</span>
                <Pill
                  className={
                    r.enabled ? 'text-success-primary' : 'text-tertiary'
                  }
                >
                  {r.enabled ? 'Enabled' : 'Disabled'}
                </Pill>
              </div>
              <p className="text-sm text-tertiary">
                {EVENTS.find((e) => e.value === r.event_type)?.label} →{' '}
                {r.channel_ids.map(channelName).join(', ')}
              </p>
            </div>
            <Button
              variant="secondary"
              disabled={!canAdmin}
              onClick={async () => {
                await action(async () => {
                  await api.updateNotificationRule(r.id, {
                    ...r,
                    enabled: !r.enabled,
                  })
                  refresh()
                })
              }}
            >
              {r.enabled ? 'Disable' : 'Enable'}
            </Button>
            <Button
              variant="secondary"
              disabled={!canAdmin}
              onClick={() => onEdit(r)}
            >
              Edit rule
            </Button>
            <Button
              variant="secondary"
              disabled={!canAdmin}
              aria-label={`Delete rule ${r.name}`}
              onClick={async () => {
                await action(async () => {
                  await api.deleteNotificationRule(r.id, r.revision)
                  refresh()
                })
              }}
            >
              <Trash01 className="size-4" />
            </Button>
          </li>
        ))}
      </ul>
    </Card>
  )
}

function DeliveryHistory({ channels }: { channels: NotificationChannel[] }) {
  const [items, setItems] = useState<NotificationDelivery[]>([])
  const [next, setNext] = useState<string>()
  const [channel, setChannel] = useState('all')
  const [event, setEvent] = useState('all')
  const [state, setState] = useState('all')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<NotificationDelivery>()
  const [attempts, setAttempts] = useState<
    import('../../lib/api').NotificationAttempt[]
  >([])
  const load = useCallback(
    async (cursor?: string) => {
      setBusy(true)
      setError(null)
      try {
        const page = await api.notificationDeliveryPage({
          channel_id: channel === 'all' ? undefined : channel,
          event_type: event === 'all' ? undefined : event,
          state: state === 'all' ? undefined : state,
          cursor,
        })
        setItems((old) => (cursor ? [...old, ...page.items] : page.items))
        setNext(page.next)
      } catch (e) {
        setError(
          e instanceof Error ? e.message : 'Could not load delivery history',
        )
      } finally {
        setBusy(false)
      }
    },
    [channel, event, state],
  )
  useEffect(() => {
    void load()
  }, [load])
  async function inspect(d: NotificationDelivery) {
    setError(null)
    setSelected(d)
    setAttempts([])
    try {
      setAttempts(await api.listNotificationAttempts(d.id))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load attempts')
    }
  }
  return (
    <Card
      title="Delivery history"
      actions={
        <Button variant="secondary" disabled={busy} onClick={() => void load()}>
          Refresh
        </Button>
      }
    >
      <div className="mb-4 grid gap-3 md:grid-cols-3">
        <Field label="Channel filter" htmlFor="history-channel">
          <Select
            id="history-channel"
            value={channel}
            onValueChange={setChannel}
            options={[
              { value: 'all', label: 'All channels' },
              ...channels.map((c) => ({ value: c.id, label: c.name })),
            ]}
          />
        </Field>
        <Field label="Event filter" htmlFor="history-event">
          <Select
            id="history-event"
            value={event}
            onValueChange={setEvent}
            options={[
              { value: 'all', label: 'All events' },
              { value: 'notification.test', label: 'Channel test' },
              ...EVENTS,
            ]}
          />
        </Field>
        <Field label="State filter" htmlFor="history-state">
          <Select
            id="history-state"
            value={state}
            onValueChange={setState}
            options={[
              { value: 'all', label: 'All states' },
              ...Object.keys(stateTone).map((s) => ({ value: s, label: s })),
            ]}
          />
        </Field>
      </div>
      {error && <ErrorState message={error} />}
      {busy && <Spinner label="Loading deliveries…" />}
      {!busy && items.length === 0 && (
        <p className="text-sm text-tertiary">
          No deliveries match these filters.
        </p>
      )}
      {items.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-secondary text-tertiary">
              <tr>
                <th className="p-3">Created</th>
                <th className="p-3">Channel / recipient</th>
                <th className="p-3">State</th>
                <th className="p-3">Attempts</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-secondary">
              {items.map((d) => (
                <tr key={d.id}>
                  <td className="p-3 text-secondary">
                    {new Date(d.created_at).toLocaleString()}
                  </td>
                  <td className="p-3 text-secondary">
                    {channels.find((c) => c.id === d.channel_id)?.name ??
                      d.channel_type}
                    {d.recipient && <p>{d.recipient}</p>}
                    <p className="text-xs text-tertiary">{d.id}</p>
                  </td>
                  <td className="p-3">
                    <Pill className={stateTone[d.state]}>{d.state}</Pill>
                    {d.last_error && (
                      <p className="text-xs text-error-primary">
                        {d.last_error}
                      </p>
                    )}
                    {d.next_attempt_at && (
                      <p className="text-xs text-tertiary">
                        Next: {new Date(d.next_attempt_at).toLocaleString()}
                      </p>
                    )}
                  </td>
                  <td className="p-3">
                    <Button variant="secondary" onClick={() => void inspect(d)}>
                      View {d.attempts} attempts
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {next && (
        <Button
          variant="secondary"
          disabled={busy}
          onClick={() => void load(next)}
        >
          Load more
        </Button>
      )}
      {selected && (
        <div className="mt-5 space-y-2 border-t border-secondary pt-4">
          <p className="text-sm font-semibold text-primary">
            Attempts for {selected.id}
          </p>
          {attempts.length === 0 ? (
            <p className="text-sm text-tertiary">No attempt has started.</p>
          ) : (
            attempts.map((a) => (
              <p key={a.id} className="text-sm text-secondary">
                #{a.number} ·{' '}
                {a.outcome === 'started'
                  ? 'Outcome unknown (worker may have stopped)'
                  : a.outcome}{' '}
                · {a.response_code ?? ''} {a.error_code ?? ''} ·{' '}
                {new Date(a.started_at).toLocaleString()}
              </p>
            ))
          )}
        </div>
      )}
    </Card>
  )
}

export default Alerting
