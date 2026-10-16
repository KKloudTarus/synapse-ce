import { Eye, RefreshCw } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Markdown } from '../../../components/synapse/Markdown'
import { SeverityBadge } from '../../../components/synapse/SeverityBadge'
import { Button, Card, EmptyState, ErrorState, Field, Select, Spinner } from '../../../components/ui'
import { api, ApiError, type NotificationChannel, type NotificationEventSpec, type NotificationTemplateFamily, type NotificationTemplatePreview, type NotificationTemplatePreviewEvent } from '../../../lib/api'
import { errorMessage, eventLabel, isForbidden } from './shared'

const PREVIEW_DEBOUNCE_MS = 350
const FIXTURE_VALUE = '__fixture__'

const CHANNEL_FAMILY: Partial<Record<NotificationChannel['type'], NotificationTemplateFamily>> = {
  webhook: 'webhook',
  slack: 'chat',
  email: 'email',
  teams: 'chat',
  telegram: 'chat',
  google_chat: 'chat',
  discord: 'chat',
  mattermost: 'chat',
  rocket_chat: 'chat',
  pagerduty: 'pager',
  jsm: 'pager',
  slack_bot: 'chat',
}

function errorCopy(error: unknown): string {
  if (isForbidden(error)) return 'You do not have permission to preview this message or the selected event.'
  if (error instanceof ApiError && error.status === 429) return 'Preview requests are temporarily rate limited. Wait a moment and try again.'
  return errorMessage(error)
}

function emailDocument(html: string): string {
  // The iframe is additionally sandboxed without allow-scripts. The policy stops remote content
  // from loading even if an upstream formatter accidentally emits a URL-bearing element.
  return `<!doctype html><meta name="color-scheme" content="light"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"><body style="color: #101828; background: #fff">${html}</body>`
}

function eventOption(event: NotificationTemplatePreviewEvent): string {
  const when = event.occurred_at ? new Date(event.occurred_at).toLocaleString() : 'unknown time'
  return [when, event.severity, event.subject_kind].filter(Boolean).join(' · ')
}

/**
 * A live render of the editor's current fields. Requests are intentionally delayed and each
 * response is tied to a monotonically increasing request token, so an earlier draft, channel, or
 * sample event can never replace the current preview.
 */
export function PreviewPanel({
  templateId,
  templateEventType,
  family,
  fields,
  catalog,
}: {
  templateId?: string
  templateEventType: string
  family: NotificationTemplateFamily
  fields: Record<string, string>
  catalog: NotificationEventSpec[]
}) {
  const [channels, setChannels] = useState<NotificationChannel[] | undefined>()
  const [channelsError, setChannelsError] = useState<string | null>(null)
  const [channelID, setChannelID] = useState('')
  const [sampleEventType, setSampleEventType] = useState(() => templateEventType === '*' ? catalog[0]?.type ?? '' : templateEventType)
  const [events, setEvents] = useState<NotificationTemplatePreviewEvent[] | undefined>()
  const [eventsError, setEventsError] = useState<string | null>(null)
  const [eventID, setEventID] = useState(FIXTURE_VALUE)
  const [preview, setPreview] = useState<NotificationTemplatePreview | null>(null)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [loadingPreview, setLoadingPreview] = useState(false)
  const [sendingTest, setSendingTest] = useState(false)
  const [testNotice, setTestNotice] = useState<string | null>(null)
  const [refreshEpoch, setRefreshEpoch] = useState(0)
  const requestGeneration = useRef(0)

  const channelsForFamily = useMemo(
    () => (channels ?? []).filter((channel) => channel.enabled && CHANNEL_FAMILY[channel.type] === family),
    [channels, family],
  )
  const previewEventTypes = useMemo(
    () => (templateEventType === '*' ? catalog : catalog.filter((item) => item.type === templateEventType)),
    [catalog, templateEventType],
  )

  useEffect(() => {
    let live = true
    setChannels(undefined)
    setChannelsError(null)
    api.listNotificationChannels().then(
      (items) => {
        if (!live) return
        setChannels(items)
      },
      (error) => {
        if (!live) return
        setChannels([])
        setChannelsError(errorCopy(error))
      },
    )
    return () => {
      live = false
    }
  }, [])

  useEffect(() => {
    if (!channelsForFamily.some((channel) => channel.id === channelID)) setChannelID(channelsForFamily[0]?.id ?? '')
  }, [channelID, channelsForFamily])

  useEffect(() => {
    if (!previewEventTypes.some((item) => item.type === sampleEventType)) setSampleEventType(previewEventTypes[0]?.type ?? '')
  }, [previewEventTypes, sampleEventType])

  useEffect(() => {
    let live = true
    setEvents(undefined)
    setEventsError(null)
    setEventID(FIXTURE_VALUE)
    if (!sampleEventType) {
      setEvents([])
      return () => {
        live = false
      }
    }
    api.listNotificationTemplatePreviewEvents(sampleEventType).then(
      (items) => {
        if (live) setEvents(items)
      },
      (error) => {
        if (!live) return
        setEvents([])
        setEventsError(errorCopy(error))
      },
    )
    return () => {
      live = false
    }
  }, [sampleEventType])

  useEffect(() => {
    const requestID = ++requestGeneration.current
    setPreview(null)
    setPreviewError(null)
    if (!channelID || !sampleEventType) {
      setLoadingPreview(false)
      return
    }
    setLoadingPreview(true)
    const timeout = window.setTimeout(() => {
      void api
        .previewNotificationTemplate({
          channel_id: channelID,
          event_type: sampleEventType,
          event_id: eventID === FIXTURE_VALUE ? undefined : eventID,
          template_id: templateId,
          fields,
        })
        .then(
          (next) => {
            if (requestGeneration.current !== requestID) return
            setPreview(next)
          },
          (error) => {
            if (requestGeneration.current !== requestID) return
            setPreviewError(errorCopy(error))
          },
        )
        .finally(() => {
          if (requestGeneration.current === requestID) setLoadingPreview(false)
        })
    }, PREVIEW_DEBOUNCE_MS)
    return () => {
      window.clearTimeout(timeout)
    }
  }, [channelID, eventID, fields, refreshEpoch, sampleEventType, templateId])

  const channelOptions = channelsForFamily.map((channel) => ({ value: channel.id, label: `${channel.name} (${channel.type})` }))
  const sampleOptions = previewEventTypes.map((event) => ({ value: event.type, label: eventLabel(catalog, event.type) }))
  const storedEventOptions = [{ value: FIXTURE_VALUE, label: 'Published fixture (safe sample)' }, ...(events ?? []).map((event) => ({ value: event.id, label: eventOption(event) }))]

  async function sendFixtureTest() {
    if (!channelID || !sampleEventType || sendingTest) return
    setSendingTest(true)
    setTestNotice(null)
    try {
      const result = await api.sendNotificationTemplatePreviewTest({
        channel_id: channelID,
        event_type: sampleEventType,
        template_id: templateId,
        fields,
      })
      setTestNotice(`Fixture test queued (${result.delivery_id}).`)
    } catch (error) {
      setTestNotice(error instanceof ApiError && (error.status === 429 || error.status === 503)
        ? 'Test sends are temporarily rate limited. Wait a moment and try again.'
        : `Could not queue fixture test: ${errorCopy(error)}`)
    } finally {
      setSendingTest(false)
    }
  }

  return (
    <Card
      title={<span className="inline-flex items-center gap-2"><Eye className="size-4" /> Live preview</span>}
      actions={
        channelID && sampleEventType ? (
          <Button type="button" variant="ghost" className="px-2 py-1.5 text-xs" onClick={() => setRefreshEpoch((value) => value + 1)} aria-label="Refresh preview">
            <RefreshCw className="size-4" /> Refresh
          </Button>
        ) : undefined
      }
    >
      {channels === undefined ? (
        <Spinner label="Loading channels…" className="py-4" />
      ) : channelsError ? (
        <ErrorState message={`Could not load channels: ${channelsError}`} />
      ) : channelOptions.length === 0 ? (
        <EmptyState icon={Eye} title="No enabled channel for this template" hint="Create or enable a channel in this family to preview the current draft." />
      ) : previewEventTypes.length === 0 ? (
        <EmptyState icon={Eye} title="No event sample is available" hint="The event catalog is loading or does not include an event this template can render." />
      ) : !channelID || !sampleEventType ? (
        <Spinner label="Preparing preview controls…" className="py-4" />
      ) : (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Channel" htmlFor="template-preview-channel">
              <Select id="template-preview-channel" ariaLabel="Preview channel" className="w-full min-w-0 [&>span:first-child]:truncate" value={channelID} onValueChange={setChannelID} options={channelOptions} />
            </Field>
            <Field label="Event" htmlFor="template-preview-event">
              <Select id="template-preview-event" ariaLabel="Preview event" value={sampleEventType} onValueChange={setSampleEventType} options={sampleOptions} />
            </Field>
          </div>
          <Field label="Sample" htmlFor="template-preview-sample" hint="Fixtures never expose tenant event data. Recent events require view permission.">
            <Select id="template-preview-sample" ariaLabel="Preview sample" ariaDescribedBy="template-preview-sample-hint" value={eventID} onValueChange={setEventID} options={storedEventOptions} disabled={events === undefined} />
          </Field>
          {eventsError && <p className="text-sm text-warning-primary">Recent events are unavailable: {eventsError}. You can still preview the published fixture.</p>}
          {loadingPreview && <Spinner label="Rendering the current draft…" className="py-4" />}
          {previewError && <ErrorState message={`Could not render preview: ${previewError}`} />}
          {preview?.suppressed && <PreviewNotice title="Delivery is suppressed" detail="Current notification policy or source state prevents this event from sending to the selected channel." />}
          {preview && !preview.suppressed && preview.fallback && <PreviewNotice title="Provider fallback would be used" detail="The rendered template has no sendable content for this channel, so delivery would use the provider fallback message." />}
          {preview && !preview.suppressed && <RenderedPreview preview={preview} />}
          <div className="flex flex-wrap items-center gap-3 border-t border-secondary pt-4">
            <Button type="button" variant="secondary" loading={sendingTest} disabled={loadingPreview} onClick={() => void sendFixtureTest()}>
              Send fixture test
            </Button>
            <p className="text-xs text-tertiary">Test sends always use the published fixture, even when this preview uses a recent event.</p>
          </div>
          {testNotice && <p role="status" className={testNotice.startsWith('Could not') || testNotice.startsWith('Test sends are') ? 'text-sm text-error-primary' : 'text-sm text-success-primary'}>{testNotice}</p>}
        </div>
      )}
    </Card>
  )
}

function PreviewNotice({ title, detail }: { title: string; detail: string }) {
  return (
    <div role="status" className="rounded-lg border border-warning/30 bg-warning/10 p-3 text-sm text-warning-primary">
      <p className="font-semibold">{title}</p>
      <p className="mt-1">{detail}</p>
    </div>
  )
}

function RenderedPreview({ preview }: { preview: NotificationTemplatePreview }) {
  const emailHTML = preview.channel.family === 'email' ? preview.formatted?.html_body : undefined
  if (emailHTML) {
    return (
      <div className="space-y-2" aria-label="Email preview">
        {preview.formatted?.subject && <p className="font-semibold text-primary">{preview.formatted.subject}</p>}
        <iframe title="Email preview" sandbox="" srcDoc={emailDocument(emailHTML)} className="min-h-64 w-full rounded-lg border border-secondary bg-white" />
      </div>
    )
  }
  if (preview.webhook) {
    return (
      <div className="space-y-2 rounded-lg border border-secondary bg-secondary p-4" aria-label="Webhook preview">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">{preview.webhook.content_type}</p>
        <pre className="overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs text-primary">{preview.webhook.body}</pre>
      </div>
    )
  }
  const message = preview.message
  const fields = Object.entries(message?.fields ?? {})
  if (fields.length === 0) return <PreviewNotice title="No rendered content" detail="The selected channel did not return a displayable message." />
  const severity = message?.severity
  const knownSeverity = severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low' || severity === 'info' ? severity : undefined
  const chat = preview.channel.family === 'chat'
  return (
    <div className="space-y-3 rounded-lg border border-secondary bg-secondary p-4" aria-label="Rendered message preview">
      {chat ? (
        <>
          <div className="flex flex-wrap items-start justify-between gap-2">
            {message?.fields.title && <div role="heading" aria-level={3}><Markdown className="font-semibold text-primary">{message.fields.title}</Markdown></div>}
            {knownSeverity && <span aria-label={`Severity: ${knownSeverity}`}><SeverityBadge severity={knownSeverity} size="sm" /></span>}
          </div>
          {message?.fields.body && <Markdown className="text-sm text-primary">{message.fields.body}</Markdown>}
        </>
      ) : fields.map(([name, value]) => (
        <div key={name}>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">{name}</p>
          <Markdown className={name === 'title' || name === 'subject' || name === 'summary' ? 'mt-1 font-semibold text-primary' : 'mt-1 text-sm text-primary'}>{value}</Markdown>
        </div>
      ))}
      {severity && (!chat || !knownSeverity) && <p className="text-xs text-secondary">Severity: {severity}</p>}
      {(preview.message?.links ?? []).map((link, index) => safeConsoleLink(link.url) ? (
        <a key={`${index}:${link.url}`} href={link.url} target="_blank" rel="noopener noreferrer" className="block break-words text-sm text-brand-primary underline">{link.label}</a>
      ) : null)}
      {preview.class && <p className="text-xs text-tertiary">Effective data class: {preview.class}</p>}
    </div>
  )
}

function safeConsoleLink(href: string): boolean {
  try {
    const url = new URL(href)
    return url.protocol === 'https:' && !url.username && !url.password
  } catch {
    return false
  }
}

export { PREVIEW_DEBOUNCE_MS, emailDocument }
