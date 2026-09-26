import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, type InboxItem, type InboxPreference } from '../../lib/api'

function safePath(path: string) {
  return path.startsWith('/') && !path.startsWith('//') && !path.includes('://') && !path.includes('\\')
}

export function InboxPage() {
  const [items, setItems] = useState<InboxItem[] | null>(null)
  const [next, setNext] = useState<string>()
  const [unreadOnly, setUnreadOnly] = useState(false)
  const [preferences, setPreferences] = useState<InboxPreference[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const generation = useRef(0)

  const load = useCallback(async (cursor?: string, unread = unreadOnly) => {
    const current = ++generation.current
    setLoading(true)
    setError('')
    try {
      const [page, prefs] = await Promise.all([api.inboxPage(cursor, unread), cursor ? Promise.resolve(null) : api.inboxPreferences()])
      if (current !== generation.current) return
      setItems((existing) => cursor ? [...(existing ?? []), ...(page.items ?? [])] : (page.items ?? []))
      setNext(page.next)
      if (prefs) setPreferences(prefs.items ?? [])
    } catch (err) {
      if (current !== generation.current) return
      if (!cursor) setItems([])
      setError(err instanceof Error ? err.message : 'Could not load notifications')
    } finally {
      if (current === generation.current) setLoading(false)
    }
  }, [unreadOnly])

  useEffect(() => { void load(undefined, unreadOnly) }, [load, unreadOnly])

  async function readOne(item: InboxItem) {
    setError('')
    try {
      await api.markInboxRead(item.id)
      setItems((current) => current?.map((row) => row.id === item.id ? { ...row, read_at: row.read_at ?? new Date().toISOString() } : row) ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not mark the notification read')
    }
  }

  async function readAll() {
    setError('')
    try {
      await api.markInboxAllRead()
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not mark notifications read')
    }
  }

  async function save(item: InboxPreference, state: InboxPreference['state']) {
    setError('')
    try {
      const saved = await api.saveInboxPreference({ event_type: item.event_type, channel: item.channel, state, revision: item.revision })
      setPreferences((current) => current.map((row) => row.event_type === item.event_type && row.channel === item.channel ? { ...row, ...saved } : row))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save preference')
      await load()
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-primary">Notifications</h1>
          <p className="mt-1 text-sm text-secondary">Messages addressed to you. Other people in this tenant cannot open this list.</p>
        </div>
        <button type="button" onClick={() => void readAll()} className="rounded-lg border border-secondary px-3 py-2 text-sm text-primary">Mark all read</button>
      </header>
      {error && <p role="alert" className="rounded-lg border border-error-primary p-3 text-sm text-error-primary">{error}</p>}
      <label className="flex items-center gap-2 text-sm text-secondary">
        <input type="checkbox" checked={unreadOnly} onChange={(event) => setUnreadOnly(event.target.checked)} />
        Unread only
      </label>
      {items === null || (loading && items.length === 0) ? <p role="status" className="text-secondary">Loading notifications…</p> : items.length === 0 ? <p className="rounded-lg border border-secondary p-4 text-secondary">No notifications.</p> : (
        <ul className="divide-y divide-secondary rounded-xl border border-secondary bg-primary">
          {items.map((item) => (
            <li key={item.id} className="space-y-1 px-4 py-3">
              <p className="font-medium text-primary">{item.title}</p>
              <p className="text-sm text-secondary">{item.summary}</p>
              <div className="flex flex-wrap gap-3 text-sm">
                {safePath(item.link_path) ? <Link className="text-brand-primary underline" to={item.link_path} onClick={() => void readOne(item)}>Open</Link> : <span className="text-tertiary">No linked page</span>}
                {!item.read_at && <button type="button" className="text-primary underline" onClick={() => void readOne(item)}>Mark read</button>}
              </div>
            </li>
          ))}
        </ul>
      )}
      {next && <button type="button" disabled={loading} onClick={() => void load(next)} className="text-sm text-brand-primary underline disabled:opacity-50">Load more</button>}
      <section aria-labelledby="notification-preferences" className="space-y-3">
        <h2 id="notification-preferences" className="text-lg font-semibold text-primary">Delivery preferences</h2>
        <ul className="space-y-3">
          {preferences.map((item) => (
            <li key={`${item.event_type}:${item.channel}`} className="rounded-xl border border-secondary p-4">
              <p className="font-medium text-primary">{item.event_type} · {item.channel}</p>
              {item.reason && <p className="text-sm text-secondary">{item.reason}</p>}
              {item.available && !item.mandatory ? (
                <label className="mt-2 block text-sm text-secondary">
                  Delivery
                  <select className="mt-1 w-full rounded-lg border border-primary bg-primary px-3 py-2 text-primary" aria-label={`${item.event_type} ${item.channel}`} value={item.state} onChange={(event) => void save(item, event.target.value as InboxPreference['state'])}>
                    <option value="inherit">Use the default</option>
                    <option value="enabled">Enabled</option>
                    <option value="disabled">Disabled</option>
                  </select>
                </label>
              ) : <p className="mt-2 text-sm text-secondary">{item.mandatory ? 'In-app delivery is required.' : 'This channel cannot be turned on.'}</p>}
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}
