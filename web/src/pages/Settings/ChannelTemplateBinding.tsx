import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import type {
  NotificationChannel,
  NotificationChannelType,
  NotificationLocale,
  NotificationTemplateFamily,
  NotificationTemplateOption,
  NotificationTemplateResolution,
} from '../../lib/api'
import { Field, Select } from '../../components/ui'

/**
 * The template family each channel type renders (#1371). It mirrors
 * notification.FamilyForChannelType on the server.
 */
export const CHANNEL_FAMILY: Record<NotificationChannelType, NotificationTemplateFamily> = {
  webhook: 'webhook',
  slack: 'chat',
  email: 'email',
  teams: 'chat',
  telegram: 'chat',
  google_chat: 'chat',
  discord: 'chat',
}

// Radix Select refuses an empty item value, so the unset choices use sentinels that map to ''.
const NO_TEMPLATE = 'none'
const TENANT_DEFAULT = 'default'

function templateLabel(t: NotificationTemplateOption): string {
  const event = t.event_type === '*' ? 'all events' : t.event_type
  const locale = t.locale === '*' ? 'any locale' : t.locale
  return `${t.name} (${event}, ${locale})`
}

/**
 * The template and locale selects of the channel form. The template list comes from the template
 * API filtered to the channel's family and to active templates, the only ones the server binds.
 * When templates are not configured the list fails to load and only the locale select shows.
 */
export function ChannelTemplateFields({
  type,
  templateId,
  locale,
  onTemplateChange,
  onLocaleChange,
  customBody = false,
  onCustomBodyChange,
  disabled,
}: {
  type: NotificationChannelType
  templateId: string
  locale: NotificationLocale | ''
  onTemplateChange: (id: string) => void
  onLocaleChange: (locale: NotificationLocale | '') => void
  /** Webhook channels: send the bound template's body as a custom JSON body (#1376). */
  customBody?: boolean
  onCustomBodyChange?: (on: boolean) => void
  disabled?: boolean
}) {
  const family = CHANNEL_FAMILY[type]
  const [templates, setTemplates] = useState<NotificationTemplateOption[] | null>(null)
  useEffect(() => {
    let live = true
    setTemplates(null)
    // Started inside a promise so a deployment without the template API degrades to no list.
    Promise.resolve()
      .then(() => api.listBindableNotificationTemplates(family))
      .then((items) => {
        if (live) setTemplates(items)
      })
      .catch(() => {
        if (live) setTemplates([])
      })
    return () => {
      live = false
    }
  }, [family])
  // A bound template that is no longer active stays selectable so saving the form keeps it.
  const options = [
    { value: NO_TEMPLATE, label: 'No binding (tenant and built-in templates)' },
    ...(templates ?? []).map((t) => ({ value: t.id, label: templateLabel(t) })),
    ...(templateId && templates && !templates.some((t) => t.id === templateId)
      ? [{ value: templateId, label: `${templateId} (not active)` }]
      : []),
  ]
  return (
    <>
      <Field
        label="Message template"
        htmlFor="notification-template"
        hint={`Renders before the tenant ${family} templates. A template for one event only binds while every rule routing here is for that event.`}
      >
        <Select
          id="notification-template"
          disabled={disabled || templates === null}
          value={templateId || NO_TEMPLATE}
          onValueChange={(v) => onTemplateChange(v === NO_TEMPLATE ? '' : v)}
          options={options}
        />
      </Field>
      <Field label="Locale" htmlFor="notification-locale" hint="The language this channel renders in.">
        <Select
          id="notification-locale"
          disabled={disabled}
          value={locale || TENANT_DEFAULT}
          onValueChange={(v) =>
            onLocaleChange(v === TENANT_DEFAULT ? '' : (v as NotificationLocale))
          }
          options={[
            { value: TENANT_DEFAULT, label: 'Tenant default' },
            { value: 'en', label: 'English' },
            { value: 'vi', label: 'Vietnamese' },
          ]}
        />
      </Field>
      {type === 'webhook' && onCustomBodyChange && (
        <label className="flex items-start gap-2 text-sm text-secondary md:col-span-2">
          <input
            type="checkbox"
            checked={customBody}
            disabled={disabled || !templateId}
            onChange={(e) => onCustomBodyChange(e.target.checked)}
          />
          <span>
            Send the template body as a custom JSON body instead of the event envelope. The
            request carries <code>X-Synapse-Body: custom</code> and the signature covers the body
            as sent. {!templateId && 'Bind a webhook template first.'}
          </span>
        </label>
      )}
    </>
  )
}

const TIER_LABEL: Record<NotificationTemplateResolution['tier'], string> = {
  channel: 'channel binding',
  tenant_event: 'tenant template for this event',
  tenant_wildcard: 'tenant template for all events',
  builtin: 'built-in template',
  fallback: 'default rendering',
}

export function describeResolution(r: NotificationTemplateResolution): string {
  const tier = TIER_LABEL[r.tier] ?? r.tier
  if (r.template) {
    const version = r.version ? ` v${r.version}` : ''
    return `${r.template.name}${version} (${tier}, ${r.locale})`
  }
  return `${tier[0].toUpperCase()}${tier.slice(1)} (${r.locale})`
}

type PreviewState =
  | { state: 'loading' }
  | { state: 'ready'; resolution: NotificationTemplateResolution }
  | { state: 'error' }

/**
 * Shows, for each channel selected on the rule form, which template the event type will render
 * with. The server resolves it (GET …/channels/{id}/template-resolution) with the resolver the
 * send-time renderer uses, so the console never re-implements the tiers. Nothing shows when the
 * deployment has no template API.
 */
export function RuleTemplatePreview({
  channels,
  eventType,
}: {
  channels: NotificationChannel[]
  eventType: string
}) {
  const [previews, setPreviews] = useState<Record<string, PreviewState>>({})
  const key = channels.map((c) => `${c.id}:${c.revision}`).join(',')
  useEffect(() => {
    if (!eventType || channels.length === 0) {
      setPreviews({})
      return
    }
    let live = true
    setPreviews(Object.fromEntries(channels.map((c) => [c.id, { state: 'loading' } as PreviewState])))
    for (const channel of channels) {
      Promise.resolve()
        .then(() => api.previewNotificationTemplateResolution(channel.id, eventType))
        .then((resolution) => {
          if (live) setPreviews((p) => ({ ...p, [channel.id]: { state: 'ready', resolution } }))
        })
        .catch(() => {
          if (live) setPreviews((p) => ({ ...p, [channel.id]: { state: 'error' } }))
        })
    }
    return () => {
      live = false
    }
    // channels is summarized by key so a parent re-render does not refetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, eventType])
  const entries = channels.filter((c) => previews[c.id] && previews[c.id].state !== 'error')
  if (entries.length === 0) return null
  return (
    <div className="space-y-1 md:col-span-2" data-testid="rule-template-preview">
      <p className="text-sm font-medium text-secondary">Templates used</p>
      <ul className="space-y-1 text-sm text-tertiary">
        {entries.map((c) => {
          const preview = previews[c.id]
          if (preview.state !== 'ready')
            return <li key={c.id}>{c.name}: resolving…</li>
          const r = preview.resolution
          return (
            <li key={c.id}>
              {c.name}: {describeResolution(r)}
              {r.binding_skipped === 'event_not_covered' && (
                <span className="text-warning-primary">
                  {' '}
                  The bound template does not cover this event, so saving this rule is refused.
                </span>
              )}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
