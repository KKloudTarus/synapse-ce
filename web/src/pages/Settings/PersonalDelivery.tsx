import { useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../../lib/api'
import type {
  NotificationEngagementSetting,
  NotificationEventSpec,
  NotificationPersonalDefault,
} from '../../lib/api'
import { Button, Card, ErrorState, Field, Select, Spinner } from '../../components/ui'
import { UserPicker } from '../Ownership/UserPicker'

const CHANNEL_LABEL: Record<NotificationPersonalDefault['channel'], string> = {
  email: 'Email',
  slack: 'Slack DM',
  teams: 'Microsoft Teams',
}
const CHANNEL_ORDER: NotificationPersonalDefault['channel'][] = ['email', 'slack', 'teams']

function label(eventTypes: NotificationEventSpec[], event: string): string {
  if (event === 'notification.destination_changed') return 'Destination changed (admins)'
  if (event === 'notification.channel_paused') return 'Channel paused (admins)'
  return eventTypes.find((e) => e.type === event)?.label ?? event
}

/**
 * Personal delivery settings an integration administrator manages (#1415, #1418): what each
 * person gets by email, Slack or Teams until they choose themselves, and who leads each engagement
 * for rules that notify the engagement lead.
 */
export function PersonalDelivery({
  canManage,
  eventTypes,
}: {
  canManage: boolean
  eventTypes: NotificationEventSpec[]
}) {
  return (
    <>
      <PersonalDefaults canManage={canManage} eventTypes={eventTypes} />
      <EngagementLeads canManage={canManage} />
    </>
  )
}

function PersonalDefaults({ canManage, eventTypes }: { canManage: boolean; eventTypes: NotificationEventSpec[] }) {
  const [items, setItems] = useState<NotificationPersonalDefault[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  useEffect(() => {
    let live = true
    Promise.resolve()
      .then(() => api.listPersonalDefaults())
      .then((rows) => live && setItems(Array.isArray(rows) ? rows : []))
      .catch((e: unknown) => {
        if (!live) return
        // A deployment without the personal inbox has no defaults to show.
        if (e instanceof ApiError && e.status === 404) setItems([])
        else setError(e instanceof Error ? e.message : 'Could not load personal defaults')
      })
    return () => {
      live = false
    }
  }, [])
  async function toggle(item: NotificationPersonalDefault) {
    const key = `${item.event_type}:${item.channel}`
    setBusy(key)
    setError(null)
    try {
      const saved = await api.savePersonalDefault({ event_type: item.event_type, channel: item.channel, enabled: !item.enabled, revision: item.revision })
      setItems((rows) => rows?.map((row) => (row.event_type === item.event_type && row.channel === item.channel ? { ...row, ...saved, builtin: false } : row)) ?? null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save the default')
    } finally {
      setBusy(null)
    }
  }
  if (items !== null && items.length === 0 && !error) return null
  const events = Array.from(new Set((items ?? []).map((i) => i.event_type)))
  return (
    <Card title="Personal delivery defaults">
      <p className="mb-3 text-sm text-tertiary">
        What people get about their own work until they choose in their inbox settings. A person&apos;s
        choice always wins, and a mandatory notice always reaches the inbox. Email, Slack and Teams
        need a verified contact in the person&apos;s profile.
      </p>
      {error && <ErrorState message={error} />}
      {items === null ? (
        <Spinner />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-tertiary">
                <th className="py-2 pr-4 font-medium">Event</th>
                {CHANNEL_ORDER.map((channel) => (
                  <th key={channel} className="py-2 pr-4 font-medium">
                    {CHANNEL_LABEL[channel]}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event} className="border-t border-secondary">
                  <td className="py-2 pr-4 text-primary">{label(eventTypes, event)}</td>
                  {CHANNEL_ORDER.map((channel) => {
                    const item = items.find((i) => i.event_type === event && i.channel === channel)
                    if (!item) return <td key={channel} />
                    return (
                      <td key={channel} className="py-2 pr-4">
                        <input
                          type="checkbox"
                          aria-label={`${label(eventTypes, event)} by ${CHANNEL_LABEL[channel]}`}
                          checked={item.enabled}
                          disabled={!canManage || busy !== null}
                          onChange={() => void toggle(item)}
                        />
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

function EngagementLeads({ canManage }: { canManage: boolean }) {
  const [engagements, setEngagements] = useState<Array<{ id: string; name: string }> | null>(null)
  const [engagement, setEngagement] = useState('')
  const [setting, setSetting] = useState<NotificationEngagementSetting | null>(null)
  const [lead, setLead] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)
  // The engagement shown now. A load or save answers for the engagement it was made for, so a reply
  // that arrives after the administrator chose another one is dropped instead of being shown, or
  // saved again, as the new one's settings.
  const current = useRef('')
  current.current = engagement
  useEffect(() => {
    let live = true
    Promise.resolve()
      .then(() => api.listEngagements())
      .then((rows) => live && setEngagements((Array.isArray(rows) ? rows : []).map((e) => ({ id: e.id, name: e.name || e.id }))))
      .catch(() => live && setEngagements([]))
    return () => {
      live = false
    }
  }, [])
  useEffect(() => {
    if (!engagement) return
    let live = true
    setSetting(null)
    setSaved(false)
    setError(null)
    api
      .getNotificationEngagementSetting(engagement)
      .then((s) => {
        if (!live || current.current !== engagement) return
        setSetting(s)
        setLead(s.lead_user_id ?? '')
      })
      .catch((e: unknown) => live && setError(e instanceof Error ? e.message : 'Could not load the engagement'))
    return () => {
      live = false
    }
  }, [engagement])
  async function save(next: string) {
    if (!setting || setting.engagement_id !== engagement) return
    const target = engagement
    setBusy(true)
    setError(null)
    setSaved(false)
    try {
      const stored = await api.updateNotificationEngagementSetting(target, {
        external_notifications: setting.external_notifications,
        revision: setting.revision,
        lead_user_id: next,
      })
      if (current.current !== target) return
      setSetting(stored)
      setLead(stored.lead_user_id ?? '')
      setSaved(true)
    } catch (e) {
      if (current.current !== target) return
      setError(e instanceof Error ? e.message : 'Could not save the engagement lead')
    } finally {
      if (current.current === target) setBusy(false)
    }
  }
  if (engagements !== null && engagements.length === 0) return null
  return (
    <Card title="Engagement leads">
      <p className="mb-3 text-sm text-tertiary">
        Rules that notify &quot;the engagement lead&quot; reach the person chosen here.
      </p>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Field label="Engagement" htmlFor="engagement-lead-engagement">
          <Select
            id="engagement-lead-engagement"
            value={engagement}
            placeholder="Choose an engagement"
            // A save in flight belongs to the engagement shown; switching waits for it.
            disabled={busy}
            onValueChange={(id) => {
              setBusy(false)
              setEngagement(id)
            }}
            options={(engagements ?? []).map((e) => ({ value: e.id, label: e.name }))}
          />
        </Field>
        {engagement && setting && (
          <div className="space-y-2">
            <UserPicker label="Lead" team="" allowAll value={lead} onChange={setLead} disabled={!canManage || busy} />
            <div className="flex gap-2">
              <Button type="button" loading={busy} disabled={!canManage || lead === (setting.lead_user_id ?? '')} onClick={() => void save(lead)}>
                Save lead
              </Button>
              {setting.lead_user_id && (
                <Button type="button" variant="secondary" disabled={!canManage || busy} onClick={() => void save('')}>
                  Clear lead
                </Button>
              )}
            </div>
            {saved && <p role="status" className="text-sm text-success-primary">Engagement lead saved.</p>}
          </div>
        )}
      </div>
      {error && <ErrorState message={error} />}
    </Card>
  )
}
