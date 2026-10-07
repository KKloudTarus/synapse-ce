import { useCallback, useEffect, useRef, useState } from 'react'
import { BellRinging01, Plus, Send01, Trash01 } from '@untitledui/icons'
import { api, AlertNotEnabledError, ApiError } from '../../lib/api'
import type {
  NotificationChannel,
  NotificationChannelType,
  NotificationDelivery,
  NotificationSourceFailure,
  NotificationEventSpec,
  NotificationEventType,
  NotificationLocale,
  NotificationRule,
  NotificationRuleFilter,
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
import { ConfirmDialog } from '../../components/synapse/ConfirmDialog'
import { TextAreaBase } from '@/components/base/textarea/textarea'
import { capabilityHint, disabledCapability, loadCapabilities, useCapabilities } from '../../lib/capabilities'
import type { Capability } from '../../lib/types'
import { useFetch } from '../../hooks'
import { canManageIntegrations, isAdminRole } from '../../lib/roles'
import { RuleTargetPicker } from './RuleTargetPicker'
import {
  CHANNEL_DESTINATIONS,
  CHANNEL_TYPE_ORDER,
  TELEGRAM_CHAT_PATTERN,
  channelTypeLabel,
  replaceDestinationHint,
} from './channelDestinations'
import { ChannelTemplateFields, RuleTemplatePreview } from './ChannelTemplateBinding'

// A new rule starts on the most common subscription when the catalog offers it.
const DEFAULT_RULE_EVENT = 'vulnerability_action.created'
// eventLabel names an event type from the server catalog, falling back to the raw type for one the
// catalog no longer declares.
function eventLabel(eventTypes: NotificationEventSpec[], type: string) {
  return eventTypes.find((e) => e.type === type)?.label ?? type
}
const stateTone: Record<string, string> = {
  delivered: 'text-success-primary',
  pending: 'text-tertiary',
  retrying: 'text-warning-primary',
  dead_letter: 'text-error-primary',
  cancelled: 'text-tertiary',
}

function redriveDestination(channel?: NotificationChannel, recipient?: string): string | undefined {
  if (!channel) return undefined
  if (channel.type !== 'email') return channel.destination
  const at = recipient?.lastIndexOf('@') ?? -1
  return recipient && at > 0 && at < recipient.length - 1
    ? recipient.slice(at + 1).toLowerCase()
    : 'Email recipient'
}

export function Alerting() {
  const { notify } = useToast()
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  // manage_integrations runs channels, rules and history; only administer adds a channel or
  // changes where one delivers (#1358).
  const canAdmin = isAdminRole(me?.role)
  const canManage = canManageIntegrations(me?.role)
  const [channels, setChannels] = useState<
    NotificationChannel[] | null | undefined
  >(undefined)
  const [editingChannel, setEditingChannel] = useState<
    NotificationChannel | undefined
  >()
  const [editingRule, setEditingRule] = useState<NotificationRule | undefined>()
  const [historyVersion, setHistoryVersion] = useState(0)
  const [rules, setRules] = useState<NotificationRule[]>([])
  const [eventTypes, setEventTypes] = useState<NotificationEventSpec[]>()
  const [catalogError, setCatalogError] = useState<string | null>(null)
  const [disabled, setDisabled] = useState<Capability | null>(null)
  const [channelTypes, setChannelTypes] = useState<string[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  // The catalog loads on its own so a failure there leaves channels and rules usable.
  const loadCatalog = useCallback(async () => {
    setCatalogError(null)
    try {
      setEventTypes(await api.listNotificationEventTypes())
    } catch (e) {
      setCatalogError(
        e instanceof Error ? e.message : 'Could not load notification event types',
      )
    }
  }, [])
  const load = useCallback(async () => {
    setError(null)
    // The capability catalog says whether the framework is on. A deployment that does not report
    // capabilities is assumed on, so a working framework is never hidden.
    const capabilities = await loadCapabilities()
    const off = disabledCapability(capabilities, 'notifications')
    if (off) {
      setDisabled(off)
      setChannels([])
      return
    }
    setDisabled(null)
    // An enabled notifications.channel_types is authoritative: the server leaves out the types the
    // operator switched off, and an empty list means every type is off. A server that does not
    // report it gets every known type.
    const types = capabilities?.get('notifications.channel_types')
    setChannelTypes(types?.enabled ? (types.values ?? []) : null)
    try {
      setChannels(await api.listNotificationChannels())
      void loadCatalog()
      setRules(await api.listNotificationRules())
      setHistoryVersion((v) => v + 1)
    } catch (e) {
      setChannels([])
      setError(
        e instanceof Error ? e.message : 'Failed to load notification settings',
      )
    }
  }, [loadCatalog])
  useEffect(() => {
    if (canManage) void load()
  }, [load, canManage])
  return (
    <div className="space-y-6">
      <LegacyAlertTest canAdmin={canManage} />
      {!me ? (
        <Spinner label="Loading permissions…" />
      ) : !canManage ? (
        <EmptyState
          icon={BellRinging01}
          title="Administrator access required"
          hint="Only tenant administrators and integration administrators can manage notification settings and delivery history."
        />
      ) : disabled ? (
        <EmptyState
          icon={BellRinging01}
          title="Notification framework is not enabled"
          hint={capabilityHint(disabled)}
        />
      ) : (
        <>
          <ChannelCreate
            key={editingChannel?.id ?? 'new-channel'}
            initial={editingChannel}
            canAdmin={canAdmin}
            canManage={canManage}
            types={channelTypes}
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
              types={channelTypes}
              canAdmin={canManage}
              refresh={load}
              notify={notify}
              onEdit={setEditingChannel}
            />
          )}
          {channels && channels.length > 0 && catalogError && (
            <Card title="Add routing rule">
              <ErrorState message={catalogError} />
              <div className="mt-3">
                <Button variant="secondary" onClick={() => void loadCatalog()}>
                  Retry
                </Button>
              </div>
            </Card>
          )}
          {channels &&
            channels.length > 0 &&
            !eventTypes &&
            !catalogError &&
            !error && <Spinner label="Loading event types…" />}
          {channels &&
            channels.length > 0 &&
            eventTypes &&
            !eventTypes.some((e) => !e.operator_only) && (
              <EmptyState
                icon={BellRinging01}
                title="No routable event types"
                hint="This deployment declares no event types that routing rules can match."
              />
            )}
          {channels &&
            channels.length > 0 &&
            eventTypes &&
            eventTypes.some((e) => !e.operator_only) && (
            <RuleCreate
              channels={channels}
              eventTypes={eventTypes}
              canAdmin={canManage}
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
            eventTypes={eventTypes ?? []}
            canAdmin={canManage}
            refresh={load}
          />
          {canManage && channels !== undefined && (
            <DeliveryHistory
              key={historyVersion}
              canAdmin={canAdmin}
              channels={channels ?? []}
              eventTypes={eventTypes ?? []}
            />
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
        Compatibility path configured with SYNAPSE_ALERT_WEBHOOK_*. It is
        deprecated and will be removed in 0.4.0. Use an Incident created rule
        below, which is delivered through the durable worker pipeline.
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

const CHANNEL_TYPES: { value: NotificationChannelType; label: string }[] =
  CHANNEL_TYPE_ORDER.map((value) => ({
    value,
    label: CHANNEL_DESTINATIONS[value].label,
  }))

const PROVIDERS_DISABLED_SWITCH = 'SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED'

/**
 * Whether the operator switched this channel type off deployment-wide. The server leaves such types
 * out of `notifications.channel_types`; `types` is null when it does not report the list, and then
 * nothing is known to be off.
 */
function operatorDisabled(type: string, types: string[] | null): boolean {
  return !!types && !types.includes(type)
}

function operatorDisabledHint(type: string): string {
  return `The operator disabled ${type} channels for this deployment (${PROVIDERS_DISABLED_SWITCH}), so this channel delivers nothing until it is turned back on.`
}

function ChannelCreate({
  initial,
  canAdmin,
  canManage,
  types,
  onCreated,
}: {
  initial?: NotificationChannel
  /** Holds administer: may add a channel and change a destination. */
  canAdmin: boolean
  /** Holds manage_integrations: may rename, enable or disable an existing channel. */
  canManage: boolean
  /** Channel types the server advertises; null means it does not say, so offer every known type. */
  types: string[] | null
  onCreated: () => void
}) {
  // An existing channel keeps its type in the list even if the server no longer offers it.
  const typeOptions = CHANNEL_TYPES.filter(
    (option) =>
      !types || types.includes(option.value) || option.value === initial?.type,
  )
  const [type, setType] = useState<NotificationChannelType>(
    initial?.type ?? typeOptions[0]?.value ?? 'webhook',
  )
  const [name, setName] = useState(initial?.name ?? '')
  const [url, setURL] = useState('')
  const [secret, setSecret] = useState('')
  // Telegram: the bot token is `secret`; the chat and optional forum topic sit beside it.
  const [chatId, setChatId] = useState('')
  const [threadId, setThreadId] = useState('')
  const [recipients, setRecipients] = useState(
    initial?.recipients?.join(', ') ?? '',
  )
  // The template binding (#1371) is not a destination, so manage_integrations may change it.
  const [templateId, setTemplateId] = useState(initial?.template_id ?? '')
  const [locale, setLocale] = useState<NotificationLocale | ''>(initial?.locale ?? '')
  const [customBody, setCustomBody] = useState(initial?.custom_body ?? false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Without administer the destination is read-only: the server refuses a new URL, secret or
  // recipient list from an integration_admin with 403, so the form never sends one.
  const destinationLocked = !canAdmin
  const spec = CHANNEL_DESTINATIONS[type]
  // A Telegram destination is all or nothing: a new chat or topic needs the token again, and the
  // server refuses a partial one. A rename of an existing channel sends none of the three.
  const telegramTouched = !!(secret.trim() || chatId.trim() || threadId.trim())
  const telegramValid =
    (!!initial && !telegramTouched) ||
    (!!secret.trim() &&
      TELEGRAM_CHAT_PATTERN.test(chatId.trim()) &&
      (!threadId.trim() || /^\d{1,10}$/.test(threadId.trim())))
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
        url:
          spec.kind === 'recipients' ||
          spec.kind === 'telegram' ||
          destinationLocked
            ? undefined
            : url.trim(),
        secret:
          (spec.kind === 'signed_url' || spec.kind === 'telegram') &&
          !destinationLocked
            ? spec.kind === 'telegram'
              ? secret.trim()
              : secret
            : undefined,
        chat_id:
          spec.kind === 'telegram' && !destinationLocked && chatId.trim()
            ? chatId.trim()
            : undefined,
        thread_id:
          spec.kind === 'telegram' && !destinationLocked && threadId.trim()
            ? Number(threadId.trim())
            : undefined,
        recipients:
          type !== 'email'
            ? undefined
            : destinationLocked
              ? initial?.recipients
              : recipients
                  .split(',')
                  .map((x) => x.trim())
                  .filter(Boolean),
        // Sent only when changed, so saving a rename never revalidates an existing binding.
        template_id:
          templateId !== (initial?.template_id ?? '') ? templateId : undefined,
        locale: locale !== (initial?.locale ?? '') ? locale : undefined,
        custom_body:
          type === 'webhook' && customBody !== (initial?.custom_body ?? false)
            ? customBody
            : undefined,
      }
      if (initial) await api.updateNotificationChannel(initial.id, input)
      else await api.createNotificationChannel(input)
      setName('')
      setURL('')
      setSecret('')
      setChatId('')
      setThreadId('')
      setRecipients('')
      onCreated()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Failed to create channel')
    } finally {
      setBusy(false)
    }
  }
  if (!initial && !canAdmin)
    return (
      <Card title="Add notification channel">
        <p className="text-sm text-tertiary">
          Only tenant administrators can add a channel or change where one
          delivers. You can rename, test, switch on or off, resume and delete
          existing channels, and edit routing rules.
        </p>
      </Card>
    )
  if (!initial && typeOptions.length === 0)
    return (
      <Card title="Add notification channel">
        <p className="text-sm text-tertiary">
          The operator has disabled every notification channel type with{' '}
          <code>{PROVIDERS_DISABLED_SWITCH}</code>, so no channel can be added.
        </p>
      </Card>
    )
  return (
    <Card
      title={initial ? 'Edit notification channel' : 'Add notification channel'}
    >
      {initial && operatorDisabled(initial.type, types) && (
        <p className="mb-4 text-sm text-warning-primary">
          {operatorDisabledHint(initial.type)} You can rename it or switch it
          off, but not switch it on or change its destination.
        </p>
      )}
      {initial && !destinationLocked && (
        <p className="mb-4 text-sm text-tertiary">
          {replaceDestinationHint(initial.type)}
        </p>
      )}
      {initial && destinationLocked && (
        <p className="mb-4 text-sm text-tertiary">
          Only tenant administrators can change this channel&apos;s
          destination. You can rename it here.
        </p>
      )}
      <form className="grid grid-cols-1 gap-4 md:grid-cols-2" onSubmit={submit}>
        <Field label="Type" htmlFor="notification-type">
          <Select
            id="notification-type"
            disabled={!!initial}
            value={type}
            onValueChange={(v) => setType(v as NotificationChannelType)}
            options={typeOptions}
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
              disabled={destinationLocked}
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              placeholder="security@example.com"
            />
          </Field>
        ) : spec.kind === 'telegram' ? (
          <>
            <Field
              label="Bot token"
              htmlFor="notification-bot-token"
              hint={
                initial
                  ? 'Write-only. Enter it again to change the bot, chat or topic.'
                  : 'Write-only after save.'
              }
            >
              <Input
                id="notification-bot-token"
                type="password"
                disabled={destinationLocked}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder="123456789:AA…"
                autoComplete="new-password"
              />
            </Field>
            <Field
              label="Chat ID"
              htmlFor="notification-chat-id"
              hint="A numeric chat ID (groups start with -100) or an @channel username."
            >
              <Input
                id="notification-chat-id"
                disabled={destinationLocked}
                value={chatId}
                onChange={(e) => setChatId(e.target.value)}
                placeholder={initial ? 'Unchanged' : '-1001234567890'}
                autoComplete="off"
              />
            </Field>
            <Field
              label="Topic ID (optional)"
              htmlFor="notification-thread-id"
              hint="Posts into one topic of a forum supergroup."
            >
              <Input
                id="notification-thread-id"
                inputMode="numeric"
                disabled={destinationLocked}
                value={threadId}
                onChange={(e) => setThreadId(e.target.value)}
                autoComplete="off"
              />
            </Field>
          </>
        ) : (
          <Field
            label={spec.urlLabel ?? 'Webhook URL'}
            htmlFor="notification-url"
            hint={spec.hint}
          >
            <Input
              id="notification-url"
              type="password"
              disabled={destinationLocked}
              value={url}
              onChange={(e) => setURL(e.target.value)}
              placeholder={spec.placeholder ?? 'https://…'}
              autoComplete="off"
            />
          </Field>
        )}
        {spec.kind === 'telegram' && spec.hint && (
          <p className="text-sm text-tertiary md:col-span-2">{spec.hint}</p>
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
              disabled={destinationLocked}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              autoComplete="new-password"
            />
          </Field>
        )}
        <ChannelTemplateFields
          type={type}
          templateId={templateId}
          locale={locale}
          onTemplateChange={(id) => {
            setTemplateId(id)
            // A custom body needs a bound template, so unbinding also opts out.
            if (!id) setCustomBody(false)
          }}
          onLocaleChange={setLocale}
          customBody={customBody}
          onCustomBodyChange={setCustomBody}
          disabled={!(initial ? canManage : canAdmin)}
        />
        <div className="flex items-end md:col-span-2">
          <div className="flex-1">
            {error && <ErrorState message={error} />}
          </div>
          <Button
            type="submit"
            loading={busy}
            disabled={
              !(initial ? canManage : canAdmin) ||
              !name.trim() ||
              (spec.kind === 'recipients'
                ? !recipients.trim()
                : spec.kind === 'telegram'
                  ? !telegramValid
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

const PAUSE_REASONS: Record<string, string> = {
  consecutive_permanent_failures: 'consecutive permanent failures',
}

function failureCount(n: number) {
  return `${n} consecutive permanent failure${n === 1 ? '' : 's'}`
}

/** Explains a channel's delivery health (#1464) in one line; nothing for a healthy channel. */
function ChannelHealthLine({ channel }: { channel: NotificationChannel }) {
  const health = channel.health
  if (!health) return null
  const last = health.last_failure_code ? (
    <>
      {' '}
      (last: <code>{health.last_failure_code}</code>)
    </>
  ) : null
  if (health.state === 'paused')
    return (
      <p className="text-sm text-error-primary">
        Paused
        {health.paused_at
          ? ` since ${new Date(health.paused_at).toLocaleString()}`
          : ''}{' '}
        after {failureCount(health.consecutive_failures)}
        {last}. Nothing is sent until an administrator resumes it; fix the
        destination first.
      </p>
    )
  if (health.consecutive_failures > 0)
    return (
      <p className="text-sm text-warning-primary">
        {failureCount(health.consecutive_failures)}
        {last}. A delivered message resets this.
      </p>
    )
  return null
}

/** The channel's append-only pause and resume history, loaded on demand. */
function ChannelHealthHistory({ channelId }: { channelId: string }) {
  const { data, error, loading } = useFetch(
    () => api.listNotificationChannelHealthEvents(channelId),
    { deps: [channelId] },
  )
  if (loading) return <Spinner label="Loading pause history…" />
  if (error) return <ErrorState message={error} />
  if (!data || data.length === 0)
    return <p className="text-sm text-tertiary">This channel has never been paused.</p>
  return (
    <ul className="space-y-1 text-sm text-secondary" aria-label="Pause history">
      {data.map((e) => (
        <li key={e.id}>
          {new Date(e.occurred_at).toLocaleString()} ·{' '}
          {e.action === 'paused'
            ? `Paused by the worker after ${failureCount(e.failures)}`
            : `Resumed by ${e.actor}`}
          {e.failure_code ? (
            <>
              {' '}
              (<code>{e.failure_code}</code>)
            </>
          ) : null}
        </li>
      ))}
    </ul>
  )
}

export function ChannelList({
  onEdit,
  channels,
  types,
  canAdmin,
  refresh,
  notify,
}: {
  onEdit: (channel: NotificationChannel) => void
  channels: NotificationChannel[]
  /** Channel types the server advertises; null means it does not say. */
  types: string[] | null
  canAdmin: boolean
  refresh: () => void
  notify: (message: string, tone?: 'success' | 'error' | 'info') => void
}) {
  const [historyFor, setHistoryFor] = useState<string | null>(null)
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
        hint="Add a signed webhook, Slack, Microsoft Teams, Telegram, Google Chat, Discord or email destination."
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
        {channels.map((c) => {
          const paused = c.health?.state === 'paused'
          // A channel of a type the operator switched off keeps its settings but delivers nothing,
          // and the server refuses to test it or switch it on, so say why instead of failing.
          const offByOperator = operatorDisabled(c.type, types)
          return (
          <li
            key={c.id}
            className="flex flex-wrap items-center gap-3 px-5 py-4"
          >
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-primary">{c.name}</span>
                <Pill
                  className={
                    c.enabled ? 'text-success-primary' : 'text-tertiary'
                  }
                >
                  {c.enabled ? 'Enabled' : 'Disabled'}
                </Pill>
                {paused && (
                  <Pill className="text-error-primary">
                    Paused:{' '}
                    {PAUSE_REASONS[c.health?.paused_reason ?? ''] ??
                      c.health?.paused_reason ??
                      'unknown reason'}
                  </Pill>
                )}
                <Pill>{channelTypeLabel(c.type)}</Pill>
                {offByOperator && (
                  <Pill className="text-warning-primary">
                    Disabled by operator
                  </Pill>
                )}
              </div>
              <p className="truncate text-sm text-tertiary">{c.destination}</p>
              {offByOperator && (
                <p className="text-sm text-warning-primary">
                  {operatorDisabledHint(c.type)}
                </p>
              )}
              <ChannelHealthLine channel={c} />
              {historyFor === c.id && (
                <div className="mt-2">
                  <ChannelHealthHistory channelId={c.id} />
                </div>
              )}
            </div>
            {paused && canAdmin && (
              <Button
                onClick={async () => {
                  await action(async () => {
                    await api.resumeNotificationChannel(c.id, c.revision)
                    notify(`${c.name} resumed. Deliveries start again from the next event.`, 'success')
                    refresh()
                  })
                }}
              >
                Resume
              </Button>
            )}
            <Button
              variant="secondary"
              aria-expanded={historyFor === c.id}
              onClick={() => setHistoryFor(historyFor === c.id ? null : c.id)}
            >
              History
            </Button>
            <Button
              variant="secondary"
              disabled={!canAdmin || paused || offByOperator}
              title={
                paused
                  ? 'Resume the channel before sending a test.'
                  : offByOperator
                    ? 'The operator disabled this channel type for the deployment.'
                    : undefined
              }
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
              disabled={!canAdmin || (offByOperator && !c.enabled)}
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
          )
        })}
      </ul>
    </Card>
  )
}

function teamCursor(cursor?: string): { offset: number; apiCursor?: string } {
  if (!cursor) return { offset: 0 }
  try {
    if (cursor.startsWith('api:')) return { offset: 0, apiCursor: cursor.slice(4) }
    if (cursor.startsWith('local:')) {
      const parsed = JSON.parse(cursor.slice(6)) as { offset?: number; apiCursor?: string }
      return { offset: Number(parsed.offset) || 0, apiCursor: parsed.apiCursor || undefined }
    }
  } catch {
    return { offset: 0 }
  }
  return { offset: 0, apiCursor: cursor }
}

/**
 * Blocking notice for incident.created rules while the deprecated deployment-wide webhook is set
 * (#1347). Both paths deliver every incident and are not deduplicated against each other, so the
 * administrator must acknowledge the overlap before the rule can be saved.
 */
function LegacyIncidentWebhookWarning({
  acknowledged,
  onAcknowledge,
  disabled,
}: {
  acknowledged: boolean
  onAcknowledge: (value: boolean) => void
  disabled: boolean
}) {
  return (
    <div
      role="alert"
      className="space-y-2 rounded-lg border border-warning-primary bg-warning-primary p-4 text-sm text-secondary md:col-span-2"
    >
      <p className="font-semibold text-warning-primary">
        The legacy incident webhook is also configured
      </p>
      <p>
        This deployment sets SYNAPSE_ALERT_WEBHOOK_URL. Every incident is sent
        to that webhook and to the channels this rule selects. The two paths
        are not deduplicated, so a receiver on both gets each incident twice.
        The legacy webhook is deprecated and will be removed in 0.4.0. Ask your
        deployment administrator to remove it once this rule is tested.
      </p>
      <label className="flex gap-2 font-medium text-primary">
        <input
          type="checkbox"
          checked={acknowledged}
          disabled={disabled}
          onChange={(e) => onAcknowledge(e.target.checked)}
        />
        I understand incidents will be delivered through both paths
      </label>
    </div>
  )
}

function RuleCreate({
  initial,
  channels,
  eventTypes,
  canAdmin,
  onCreated,
}: {
  initial?: NotificationRule
  channels: NotificationChannel[]
  eventTypes: NotificationEventSpec[]
  canAdmin: boolean
  onCreated: () => void
}) {
  // Operator-only events are sent on demand and never matched by rules, so the form omits them.
  const ruleEvents = eventTypes.filter((e) => !e.operator_only)
  const [name, setName] = useState(initial?.name ?? '')
  const [event, setEvent] = useState<NotificationEventType>(
    initial?.event_type ??
      (ruleEvents.find((e) => e.type === DEFAULT_RULE_EVENT) ?? ruleEvents[0])
        ?.type ??
      '',
  )
  // Each field below renders only when the catalog says this event type accepts its filter, so the
  // form cannot build a rule the server would reject or that could never match.
  const spec = eventTypes.find((e) => e.type === event)
  const allows = (filter: NotificationRuleFilter) =>
    spec?.filters.includes(filter) ?? false
  const [selected, setSelected] = useState<string[]>(
    initial?.channel_ids ?? [channels[0]?.id].filter(Boolean),
  )
  const [engagements, setEngagements] = useState<string[]>(initial?.engagement_ids ?? [])
  const [teams, setTeams] = useState<string[]>(initial?.team_ids ?? [])
  const [allTeams, setAllTeams] = useState(initial?.all_teams ?? false)
  const engagementCache = useRef<Promise<Array<{ id: string; name: string; client: string }>> | null>(null)
  const searchEngagements = useCallback(async (query: string, cursor: string | undefined, signal: AbortSignal) => {
    if (!engagementCache.current) {
      engagementCache.current = api.listEngagements().catch((err: unknown) => {
        engagementCache.current = null
        throw err
      })
    }
    const all = await engagementCache.current
    if (signal.aborted) throw new DOMException('The search was cancelled.', 'AbortError')
    const needle = query.trim().toLowerCase()
    const matches = all.filter((item) => {
      const haystack = `${item.name} ${item.id} ${item.client}`.toLowerCase()
      return needle === '' || haystack.includes(needle)
    })
    const start = cursor ? Number(cursor) || 0 : 0
    const page = matches.slice(start, start + 25)
    const next = start + 25 < matches.length ? String(start + 25) : undefined
    return { items: page.map((item) => ({ id: item.id, label: item.name || item.id })), next }
  }, [])
  const searchTeams = useCallback(async (query: string, cursor: string | undefined, signal: AbortSignal) => {
    const parsed = teamCursor(cursor)
    const page = await api.ownershipTeams(parsed.apiCursor, signal)
    if (signal.aborted) throw new DOMException('The search was cancelled.', 'AbortError')
    const needle = query.trim().toLowerCase()
    const matches = (page.items ?? [])
      .filter((team) => {
        const haystack = `${team.name} ${team.slug} ${team.id}`.toLowerCase()
        return needle === '' || haystack.includes(needle)
      })
      .map((team) => ({ id: team.id, label: team.name || team.slug || team.id, archived: team.archived }))
    const slice = matches.slice(parsed.offset, parsed.offset + 25)
    const nextOffset = parsed.offset + 25
    const next = nextOffset < matches.length
      ? `local:${JSON.stringify({ offset: nextOffset, apiCursor: parsed.apiCursor ?? '' })}`
      : page.next
        ? `api:${page.next}`
        : undefined
    return { items: slice, next }
  }, [])
  const [actions, setActions] = useState(
    initial?.action_types?.join(', ') ?? '',
  )
  const [error, setError] = useState<string | null>(null)
  const [severity, setSeverity] = useState(
    initial ? initial.min_severity || 'any' : 'high',
  )
  const [leadHours, setLeadHours] = useState(
    String((initial?.lead_time_seconds ?? 86400) / 3600),
  )
  const [busy, setBusy] = useState(false)
  // #1347: while the deprecated SYNAPSE_ALERT_WEBHOOK_URL is set, an incident.created rule delivers
  // in addition to the legacy webhook. The capability catalog carries only a boolean, never the URL.
  // A deployment that does not report capabilities shows no warning, matching the catalog contract.
  const capabilities = useCapabilities()
  const legacyWebhook =
    capabilities?.get('legacy_alert_webhook')?.enabled === true
  const legacyAckRequired = legacyWebhook && event === 'incident.created'
  const [legacyAck, setLegacyAck] = useState(false)
  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      if (allows('team_ids') && !allTeams && teams.length === 0) {
        throw new Error('Choose at least one team or select all teams.')
      }
      if (legacyAckRequired && !legacyAck) {
        throw new Error(
          'Acknowledge that the legacy incident webhook also delivers this event.',
        )
      }
      const input = {
        name: name.trim(),
        enabled: initial?.enabled ?? true,
        event_type: event,
        channel_ids: selected,
        // A saved engagement scope on an event without engagements is cleared rather than resent.
        engagement_ids: allows('engagement_ids') ? engagements : [],
        team_ids: allows('team_ids') && !allTeams ? teams : undefined,
        all_teams: allows('team_ids') ? allTeams : undefined,
        action_types: allows('action_types')
          ? actions
              .split(',')
              .map((x) => x.trim())
              .filter(Boolean)
          : undefined,
        min_severity:
          allows('min_severity') && severity !== 'any' ? severity : undefined,
        lead_time_seconds: allows('lead_time_seconds')
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
            onValueChange={setEvent}
            options={[
              ...ruleEvents.map((e) => ({ value: e.type, label: e.label })),
              // Keep a saved rule's type selectable even if the catalog stopped offering it.
              ...(event && !ruleEvents.some((e) => e.type === event)
                ? [{ value: event, label: eventLabel(eventTypes, event) }]
                : []),
            ]}
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
        <RuleTemplatePreview
          channels={channels.filter((c) => selected.includes(c.id))}
          eventType={event}
        />
        {allows('engagement_ids') && (
          <RuleTargetPicker
            label="Engagements (optional)"
            hint="Leave unselected to match every engagement. A saved engagement that is missing from this directory stays on the rule until you remove it."
            selected={engagements}
            onChange={setEngagements}
            disabled={!canAdmin}
            search={searchEngagements}
          />
        )}
        {allows('action_types') && (
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
        {allows('team_ids') && (
          <fieldset className="space-y-3 md:col-span-2">
            <legend className="text-sm font-medium text-secondary">Affected teams</legend>
            <label className="flex gap-2 text-sm text-secondary">
              <input
                type="checkbox"
                checked={allTeams}
                onChange={(e) => setAllTeams(e.target.checked)}
              />
              All teams in this tenant
            </label>
            <RuleTargetPicker
              label="Team IDs"
              hint="Notify when any listed team gains or loses ownership, or its finding's assignee changes. Archived teams stay selected until you remove them."
              selected={teams}
              onChange={setTeams}
              disabled={!canAdmin || allTeams}
              search={searchTeams}
            />
          </fieldset>
        )}
        {allows('min_severity') && (
          <Field label="Minimum severity" htmlFor="notification-severity">
            <Select
              id="notification-severity"
              value={severity}
              onValueChange={setSeverity}
              options={[
                { value: 'any', label: 'Any severity (including unknown)' },
                ...['critical', 'high', 'medium', 'low', 'info'].map((v) => ({
                  value: v,
                  label: v,
                })),
              ]}
            />
          </Field>
        )}
        {allows('lead_time_seconds') && (
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
        {legacyAckRequired && (
          <LegacyIncidentWebhookWarning
            acknowledged={legacyAck}
            onAcknowledge={setLegacyAck}
            disabled={!canAdmin}
          />
        )}
        {error && <ErrorState message={error} />}
        <div className="flex justify-end gap-2 md:col-span-2">
          <Button
            type="submit"
            loading={busy}
            disabled={
              !canAdmin ||
              !name.trim() ||
              !event ||
              selected.length === 0 ||
              (legacyAckRequired && !legacyAck) ||
              (allows('lead_time_seconds') &&
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
  eventTypes,
  canAdmin,
  refresh,
}: {
  onEdit: (rule: NotificationRule) => void
  rules: NotificationRule[]
  channels: NotificationChannel[]
  eventTypes: NotificationEventSpec[]
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
                {eventLabel(eventTypes, r.event_type)} →{' '}
                {r.channel_ids.map(channelName).join(', ')}
              </p>
              {r.engagement_ids && r.engagement_ids.length > 0 && (
                <p className="text-sm text-tertiary">Engagements: {r.engagement_ids.join(', ')}</p>
              )}
              {r.event_type === 'finding.ownership_changed' && (
                <p className="text-sm text-tertiary">
                  {r.all_teams ? 'All teams in this tenant' : `Teams: ${r.team_ids?.join(', ') ?? ''}`}
                </p>
              )}
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

function DeliveryHistory({
  canAdmin,
  channels,
  eventTypes,
}: {
  canAdmin: boolean
  channels: NotificationChannel[]
  eventTypes: NotificationEventSpec[]
}) {
  const { notify } = useToast()
  const historyRequest = useRef(0)
  const attemptRequest = useRef(0)
  const redriveInFlight = useRef(false)
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])
  const [items, setItems] = useState<NotificationDelivery[]>([])
  const [next, setNext] = useState<string>()
  const [channel, setChannel] = useState('all')
  const [event, setEvent] = useState('all')
  const [state, setState] = useState('all')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [attemptsBusy, setAttemptsBusy] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<NotificationDelivery>()
  const [redriveTarget, setRedriveTarget] = useState<NotificationDelivery>()
  const [redriveReason, setRedriveReason] = useState('')
  const [redriveBusy, setRedriveBusy] = useState(false)
  const [redriveError, setRedriveError] = useState<string | null>(null)
  const [attempts, setAttempts] = useState<
    import('../../lib/api').NotificationAttempt[]
  >([])
  const load = useCallback(
    async (cursor?: string) => {
      const request = ++historyRequest.current
      setBusy(true)
      setError(null)
      try {
        if (state === 'quarantined') {
          setItems([])
          setNext(undefined)
          return
        }
        const page = await api.notificationDeliveryPage({
          channel_id: channel === 'all' ? undefined : channel,
          event_type: event === 'all' ? undefined : event,
          state: state === 'all' ? undefined : state,
          from: from ? new Date(from).toISOString() : undefined,
          to: to ? new Date(to).toISOString() : undefined,
          cursor,
        })
        if (!mounted.current || request !== historyRequest.current) return
        setItems((old) => (cursor ? [...old, ...page.items] : page.items))
        setNext(page.next)
      } catch (e) {
        if (!mounted.current || request !== historyRequest.current) return
        setError(
          e instanceof Error ? e.message : 'Could not load delivery history',
        )
      } finally {
        if (mounted.current && request === historyRequest.current) setBusy(false)
      }
    },
    [channel, event, state, from, to],
  )
  const reloadHistory = useRef(load)
  useEffect(() => {
    reloadHistory.current = load
    void load()
  }, [load])
  async function inspect(d: NotificationDelivery) {
    const request = ++attemptRequest.current
    setError(null)
    setSelected(d)
    setAttempts([])
    setAttemptsBusy(true)
    try {
      const records = await api.listNotificationAttempts(d.id)
      if (mounted.current && request === attemptRequest.current) setAttempts(records)
    } catch (e) {
      if (mounted.current && request === attemptRequest.current)
        setError(e instanceof Error ? e.message : 'Could not load attempts')
    } finally {
      if (mounted.current && request === attemptRequest.current) setAttemptsBusy(false)
    }
  }
  async function confirmRedrive() {
    if (!canAdmin || !redriveTarget || redriveInFlight.current) return
    const reason = redriveReason.trim()
    if (!reason || Array.from(reason).length > 500) {
      setRedriveError('Enter a reason of 1 to 500 characters.')
      return
    }
    redriveInFlight.current = true
    const selectionRequest = attemptRequest.current
    setRedriveBusy(true)
    setRedriveError(null)
    try {
      const updated = await api.redriveNotificationDelivery(
        redriveTarget.id,
        reason,
        redriveTarget.redrive_fence,
      )
      if (!mounted.current) return
      setRedriveTarget(undefined)
      setRedriveReason('')
      await reloadHistory.current()
      if (!mounted.current) return
      if (selectionRequest === attemptRequest.current && selected?.id === updated.id) await inspect(updated)
      if (mounted.current) notify('Redrive queued. Delivery will run asynchronously.', 'success')
    } catch (e) {
      if (!mounted.current) return
      setRedriveError(
        e instanceof Error ? e.message : 'Could not queue this delivery for redrive',
      )
      if (e instanceof ApiError && e.status === 409) void reloadHistory.current()
    } finally {
      redriveInFlight.current = false
      if (mounted.current) setRedriveBusy(false)
    }
  }
  const redriveChannel = redriveTarget
    ? channels.find((channel) => channel.id === redriveTarget.channel_id)
    : undefined
  const safeRedriveDestination = redriveDestination(redriveChannel, redriveTarget?.recipient)
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
              // Operator-only events such as channel tests also leave deliveries, so all are listed.
              ...eventTypes.map((e) => ({ value: e.type, label: e.label })),
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
              { value: 'quarantined', label: 'Quarantined sources' },
            ]}
          />
        </Field>
        <Field label="Created from" htmlFor="history-from">
          <Input
            id="history-from"
            type="datetime-local"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
          />
        </Field>
        <Field label="Created until" htmlFor="history-to">
          <Input
            id="history-to"
            type="datetime-local"
            value={to}
            onChange={(e) => setTo(e.target.value)}
          />
        </Field>
      </div>
      {error && <ErrorState message={error} />}
      {busy && <Spinner label="Loading deliveries…" />}
      {!busy && state !== 'quarantined' && items.length === 0 && (
        <p className="text-sm text-tertiary">
          No deliveries match these filters.
        </p>
      )}
      {state !== 'quarantined' && items.length > 0 && (
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
                    {canAdmin && d.state === 'dead_letter' && (
                      <Button
                        variant="secondary"
                        onClick={() => {
                          setRedriveTarget(d)
                          setRedriveReason('')
                          setRedriveError(null)
                        }}
                      >
                        Redrive
                      </Button>
                    )}
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
      {(state === 'all' || state === 'quarantined') && channel === 'all' && (
        <QuarantinedSources event={event} from={from} to={to} />
      )}
      {state === 'quarantined' && channel !== 'all' && (
        <p className="text-sm text-tertiary">Quarantined sources have no channel. Select All channels to view them.</p>
      )}
      {selected && (
        <div className="mt-5 space-y-2 border-t border-secondary pt-4">
          <p className="text-sm font-semibold text-primary">
            Attempts for {selected.id}
          </p>
          {attemptsBusy ? (
            <Spinner label="Loading attempts…" />
          ) : attempts.length === 0 ? (
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
      <ConfirmDialog
        open={redriveTarget !== undefined}
        title="Redrive notification delivery?"
        confirmLabel="Queue redrive"
        tone="brand"
        busy={redriveBusy}
        error={redriveError}
        onCancel={() => {
          if (redriveBusy) return
          setRedriveTarget(undefined)
          setRedriveError(null)
        }}
        onConfirm={() => void confirmRedrive()}
        description={
          <div className="space-y-3">
            <p>
              {redriveChannel?.name ??
                redriveTarget?.channel_type}{' '}
              · {redriveTarget?.channel_type}
              {safeRedriveDestination && (
                <span>
                  {' '}· destination: {safeRedriveDestination}
                </span>
              )}
            </p>
            <p>
              This retries the same delivery to its original channel configuration
              and keeps the existing attempt history. If the receiver accepted an
              earlier request before its acknowledgement was lost, this may send
              a duplicate.
            </p>
            <label className="block space-y-1.5 text-sm text-secondary">
              <span>Reason for redrive</span>
              <TextAreaBase
                aria-label="Reason for redrive"
                aria-required="true"
                maxLength={1000}
                rows={3}
                value={redriveReason}
                onChange={(event) => setRedriveReason(event.currentTarget.value)}
                placeholder="Describe what changed before retrying"
              />
              <span className="block text-xs text-tertiary">
                {Array.from(redriveReason.trim()).length}/500 characters
              </span>
            </label>
          </div>
        }
      />
    </Card>
  )
}

export function QuarantinedSources({ event, from, to }: { event: string; from: string; to: string }) {
  const requestID = useRef(0)
  const [items, setItems] = useState<NotificationSourceFailure[]>([])
  const [nextOffset, setNextOffset] = useState<number>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const load = useCallback(async (offset = 0) => {
    const request = ++requestID.current
    setBusy(true)
    setError(null)
    try {
      const page = await api.notificationSourceFailurePage({
        event_type: event === 'all' ? undefined : event,
        from: from ? new Date(from).toISOString() : undefined,
        to: to ? new Date(to).toISOString() : undefined,
        offset,
      })
      if (request !== requestID.current) return
      setItems((old) => offset ? [...old, ...page.items] : page.items)
      setNextOffset(page.next_offset)
    } catch (e) {
      if (request === requestID.current)
        setError(e instanceof Error ? e.message : 'Could not load quarantined sources')
    } finally {
      if (request === requestID.current) setBusy(false)
    }
  }, [event, from, to])
  useEffect(() => { void load() }, [load])
  return (
    <section className="mt-6 border-t border-secondary pt-4" aria-label="Quarantined sources">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-primary">Quarantined sources</h3>
        <Button variant="secondary" disabled={busy} onClick={() => void load()}>Refresh</Button>
      </div>
      <p className="mb-3 text-sm text-secondary">These captured events failed validation before any delivery was queued. Their payloads are hidden.</p>
      {error && <ErrorState message={error} />}
      {busy && <Spinner label="Loading quarantined sources…" />}
      {!busy && items.length === 0 && !error && <p className="text-sm text-tertiary">No quarantined sources match these filters.</p>}
      {items.length > 0 && <div className="overflow-x-auto"><table className="w-full text-left text-sm">
        <thead className="border-b border-secondary text-tertiary"><tr><th className="p-3">Quarantined</th><th className="p-3">Event / source</th><th className="p-3">Reason</th></tr></thead>
        <tbody className="divide-y divide-secondary">{items.map((item) => <tr key={`${item.source_kind}:${item.source_id}`}>
          <td className="p-3 text-secondary">{new Date(item.processed_at).toLocaleString()}</td>
          <td className="p-3 text-secondary">{item.event_type}<p className="text-xs text-tertiary">{item.source_kind}: {item.source_id}</p></td>
          <td className="p-3"><Pill className="text-error-primary">Quarantined</Pill><p className="text-xs text-error-primary">{item.failed_reason === 'event_data_too_large' ? 'Event data exceeds 16 KiB' : 'Invalid event'}</p></td>
        </tr>)}</tbody>
      </table></div>}
      {nextOffset !== undefined && <Button variant="secondary" disabled={busy} onClick={() => void load(nextOffset)}>Load more quarantined sources</Button>}
    </section>
  )
}

export default Alerting
