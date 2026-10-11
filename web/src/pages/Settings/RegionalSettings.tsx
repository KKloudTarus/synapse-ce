import { useMemo, useState, type FormEvent } from 'react'
import { Globe01 } from '@untitledui/icons'
import { Button, Card, ErrorState, Field, Input, Select, Spinner } from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import type { TenantLocale, TenantSettings } from '../../lib/api'

const LOCALE_LABELS: Record<TenantLocale, string> = {
  en: 'English',
  vi: 'Tiếng Việt (Vietnamese)',
}

// Suggestions for the time zone field. The server is the authority (time.LoadLocation); the
// browser list only helps the administrator type a valid IANA name.
function timeZoneSuggestions(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] }
  try {
    const zones = intl.supportedValuesOf?.('timeZone') ?? []
    return zones.includes('UTC') ? zones : ['UTC', ...zones]
  } catch {
    return ['UTC']
  }
}

// Same shape the server accepts (tenancy.LoadTimeZone): an IANA name, not "Local" and not an
// offset such as +07:00, which browsers accept but the server refuses.
const TIME_ZONE_SHAPE = /^[A-Za-z0-9_+/-]{1,64}$/

/** The current time in zone, or null when the zone is not an IANA name the browser knows. */
function previewTime(zone: string): string | null {
  const name = zone.trim()
  if (!TIME_ZONE_SHAPE.test(name) || name === 'Local') return null
  try {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: zone.trim(),
      // dateStyle/timeStyle cannot be combined with timeZoneName, so the fields are spelled out.
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      timeZoneName: 'short',
    }).format(new Date())
  } catch {
    return null
  }
}

export function RegionalSettings() {
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  const canAdmin = me?.role === 'admin' || me?.role === 'owner'
  const { data, loading, error, refetch } = useFetch(() => api.getTenantSettings(), { deps: [] })
  const [saved, setSaved] = useState<TenantSettings | null>(null)
  // Lives here, not in the form: a 409 reloads the settings, which remounts the form.
  const [saveError, setSaveError] = useState<string | null>(null)

  const current = saved ?? data
  if (loading && !current) return <Spinner label="Loading language and time zone…" />
  if (error && !current) return <ErrorState message={error} />
  if (!current) return null

  return (
    // Keyed by revision so the form starts from the stored values. Copying them into state after
    // mount left the language select showing its placeholder for a saved `vi`.
    <RegionalSettingsForm
      key={current.revision}
      current={current}
      canAdmin={canAdmin}
      showReadOnlyNote={!canAdmin && !!me}
      saveError={saveError}
      setSaveError={setSaveError}
      onSaved={setSaved}
      onConflict={() => {
        setSaved(null)
        refetch()
      }}
    />
  )
}

function RegionalSettingsForm({
  current,
  canAdmin,
  showReadOnlyNote,
  saveError,
  setSaveError,
  onSaved,
  onConflict,
}: {
  current: TenantSettings
  canAdmin: boolean
  showReadOnlyNote: boolean
  saveError: string | null
  setSaveError: (message: string | null) => void
  onSaved: (next: TenantSettings) => void
  onConflict: () => void
}) {
  const { notify } = useToast()
  const zones = useMemo(timeZoneSuggestions, [])
  const [locale, setLocale] = useState<TenantLocale>(current.defaultLocale)
  const [timeZone, setTimeZone] = useState(current.timeZone)
  const [saving, setSaving] = useState(false)

  const preview = previewTime(timeZone)
  const dirty = locale !== current.defaultLocale || timeZone.trim() !== current.timeZone

  async function submit(event: FormEvent) {
    event.preventDefault()
    setSaveError(null)
    if (!preview) {
      setSaveError(`"${timeZone}" is not a time zone name. Use an IANA name such as Asia/Ho_Chi_Minh.`)
      return
    }
    setSaving(true)
    try {
      const next = await api.saveTenantSettings({
        defaultLocale: locale,
        timeZone: timeZone.trim(),
        revision: current.revision,
      })
      onSaved(next)
      notify('Language and time zone saved.', 'success')
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        onConflict()
        setSaveError('Another administrator changed these settings. The latest values are loaded; review them and save again.')
      } else {
        setSaveError(e instanceof Error ? e.message : 'Failed to save the settings.')
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title="Language and time zone" titleClassName="flex items-center gap-2">
      <p className="text-sm text-secondary">
        Notification messages and digests for this tenant use this language, and show dates and times
        in this time zone. Daylight saving follows the zone automatically.
      </p>
      {showReadOnlyNote && (
        <p className="mt-3 text-sm text-tertiary">Only tenant administrators can change these settings.</p>
      )}
      <form className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2" onSubmit={submit}>
        <Field label="Default language" htmlFor="tenant-locale">
          <Select
            id="tenant-locale"
            ariaLabel="Default language"
            value={locale}
            disabled={!canAdmin || saving}
            onValueChange={(v) => setLocale(v as TenantLocale)}
            options={current.locales.map((value) => ({ value, label: LOCALE_LABELS[value] ?? value }))}
          />
        </Field>
        <Field label="Time zone" hint="An IANA name, for example Asia/Ho_Chi_Minh or Europe/Berlin." htmlFor="tenant-time-zone">
          <Input
            id="tenant-time-zone"
            list="tenant-time-zone-options"
            autoComplete="off"
            spellCheck={false}
            value={timeZone}
            disabled={!canAdmin || saving}
            onChange={(e) => setTimeZone(e.target.value)}
          />
        </Field>
        <datalist id="tenant-time-zone-options">
          {zones.map((zone) => (
            <option key={zone} value={zone} />
          ))}
        </datalist>
        <p className="flex items-center gap-2 text-sm text-tertiary md:col-span-2" aria-live="polite">
          <Globe01 className="size-4 shrink-0" aria-hidden />
          {preview ? `Current time there: ${preview}` : 'Not a known time zone name.'}
        </p>
        {saveError && (
          <div className="md:col-span-2">
            <ErrorState message={saveError} />
          </div>
        )}
        <div className="flex items-center gap-3 md:col-span-2">
          <Button type="submit" loading={saving} disabled={!canAdmin || !dirty}>
            Save
          </Button>
          {current.updatedAt && (
            <span className="text-xs text-quaternary">
              Last changed {new Date(current.updatedAt).toLocaleString()}
            </span>
          )}
        </div>
      </form>
    </Card>
  )
}
