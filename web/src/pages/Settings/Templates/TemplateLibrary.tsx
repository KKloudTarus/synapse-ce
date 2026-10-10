import { BellRinging01, Copy01, FileCode02, Plus, RefreshCw01 } from '@untitledui/icons'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Button, Card, EmptyState, ErrorState, InfoNote, Pill, Select, Spinner } from '../../../components/ui'
import {
  api,
  TEMPLATE_FAMILIES,
  TEMPLATE_STATUSES,
  type BuiltinNotificationTemplate,
  type NotificationEventSpec,
  type NotificationTemplate,
  type NotificationTemplateFamily,
  type NotificationTemplateStatus,
} from '../../../lib/api'
import {
  ANY_EVENT,
  FAMILY_INFO,
  FAMILY_LABEL,
  LOCALE_LABEL,
  PermissionDenied,
  StatusBadge,
  errorMessage,
  eventLabel,
  formatDateTime,
  isForbidden,
  useTemplateAccess,
} from './shared'

const ALL = 'all'

/** State handed to the editor when a built-in is cloned; the editor pre-fills a new draft from it. */
export interface TemplateCloneState {
  clone: BuiltinNotificationTemplate
}

/**
 * Settings → Templates (#1373): the built-in defaults, read-only with "clone to customize", and the
 * tenant's custom templates grouped by event type, then channel family.
 */
export function TemplateLibrary() {
  const access = useTemplateAccess()

  if (access.state === 'loading') return <Spinner label="Loading message templates…" />
  if (access.state === 'error') {
    return (
      <div className="space-y-3">
        <ErrorState message={`Could not load your permissions: ${access.message}`} />
        <Button variant="secondary" onClick={access.retry}>
          <RefreshCw01 className="size-4" /> Retry
        </Button>
      </div>
    )
  }
  if (access.state === 'denied') return <PermissionDenied />
  if (access.state === 'off') return <EmptyState icon={BellRinging01} title="Notifications are off" hint={access.hint} />
  return <Library />
}

function Library() {
  const navigate = useNavigate()
  const [catalog, setCatalog] = useState<NotificationEventSpec[]>([])
  const [builtins, setBuiltins] = useState<BuiltinNotificationTemplate[] | undefined>(undefined)
  const [builtinsError, setBuiltinsError] = useState<string | null>(null)
  const [templates, setTemplates] = useState<NotificationTemplate[] | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)
  const [forbidden, setForbidden] = useState(false)
  const [eventFilter, setEventFilter] = useState(ALL)
  const [familyFilter, setFamilyFilter] = useState(ALL)
  const [statusFilter, setStatusFilter] = useState(ALL)
  const [generation, setGeneration] = useState(0)
  const reload = useCallback(() => setGeneration((value) => value + 1), [])

  useEffect(() => {
    let live = true
    setBuiltins(undefined)
    setBuiltinsError(null)
    // The catalog only names event types; the list still renders raw types when it fails.
    api.listNotificationEventTypes().then(
      (items) => live && setCatalog(items),
      () => undefined,
    )
    api.listBuiltinNotificationTemplates().then(
      (items) => live && setBuiltins(items),
      (caught) => {
        if (!live) return
        setBuiltinsError(errorMessage(caught))
        setBuiltins([])
      },
    )
    return () => {
      live = false
    }
  }, [generation])

  useEffect(() => {
    let live = true
    setTemplates(undefined)
    setError(null)
    api
      .listNotificationTemplates({
        event_type: eventFilter === ALL ? undefined : eventFilter,
        family: familyFilter === ALL ? undefined : (familyFilter as NotificationTemplateFamily),
        status: statusFilter === ALL ? undefined : (statusFilter as NotificationTemplateStatus),
      })
      .then(
        (items) => live && setTemplates(items),
        (caught) => {
          if (!live) return
          if (isForbidden(caught)) setForbidden(true)
          setError(errorMessage(caught))
          setTemplates([])
        },
      )
    return () => {
      live = false
    }
  }, [eventFilter, familyFilter, statusFilter, generation])

  const groups = useMemo(() => groupTemplates(templates ?? []), [templates])
  const filtered = eventFilter !== ALL || familyFilter !== ALL || statusFilter !== ALL

  if (forbidden) return <PermissionDenied />

  const eventOptions = [
    { value: ALL, label: 'All events' },
    { value: ANY_EVENT, label: 'Any event (*)' },
    ...catalog.map((spec) => ({ value: spec.type, label: spec.label || spec.type })),
  ]

  function clone(builtin: BuiltinNotificationTemplate) {
    const state: TemplateCloneState = { clone: builtin }
    navigate('/settings/templates/new', { state })
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-3xl text-sm text-secondary">
          Message templates decide the wording of notifications. Each template is keyed by event type, channel
          family and language; the active one replaces the built-in default for that key.
        </p>
        <div className="flex gap-2">
          <Button variant="secondary" onClick={reload}>
            <RefreshCw01 className="size-4" /> Refresh
          </Button>
          <Link
            to="/settings/templates/new"
            className="inline-flex items-center gap-2 rounded-lg bg-brand-solid px-3.5 py-2 text-sm font-semibold text-primary_on-brand shadow-xs hover:bg-brand-solid_hover"
          >
            <Plus className="size-4" /> New template
          </Link>
        </div>
      </div>

      <Card
        title={
          <span className="inline-flex items-center gap-1.5">
            Built-in defaults
            <InfoNote label="About built-in defaults">
              Synapse ships one default per event type, channel family and language. They are read-only; clone one
              to start a custom template from the exact text in use.
            </InfoNote>
          </span>
        }
      >
        <BuiltinList builtins={builtins} error={builtinsError} catalog={catalog} onClone={clone} />
      </Card>

      <Card
        title={
          <span className="inline-flex items-center gap-1.5">
            Custom templates
            <InfoNote label="About custom templates">
              A draft does not render until it is activated. Saving creates a new version; activating a version makes
              it render and archives any other active template with the same key.
            </InfoNote>
          </span>
        }
      >
        <div className="mb-4 grid gap-3 sm:grid-cols-3">
          <Select ariaLabel="Filter by event" value={eventFilter} onValueChange={setEventFilter} options={eventOptions} />
          <Select
            ariaLabel="Filter by channel family"
            value={familyFilter}
            onValueChange={setFamilyFilter}
            options={[{ value: ALL, label: 'All families' }, ...TEMPLATE_FAMILIES.map((family) => ({ value: family, label: FAMILY_LABEL[family] }))]}
          />
          <Select
            ariaLabel="Filter by status"
            value={statusFilter}
            onValueChange={setStatusFilter}
            options={[{ value: ALL, label: 'All statuses' }, ...TEMPLATE_STATUSES.map((status) => ({ value: status, label: status[0].toUpperCase() + status.slice(1) }))]}
          />
        </div>
        {templates === undefined ? (
          <Spinner label="Loading templates…" />
        ) : error ? (
          <div className="space-y-3">
            <ErrorState message={`Could not load templates: ${error}`} />
            <Button variant="secondary" onClick={reload}>
              <RefreshCw01 className="size-4" /> Retry
            </Button>
          </div>
        ) : groups.length === 0 ? (
          <EmptyState
            icon={FileCode02}
            title={filtered ? 'No templates match these filters' : 'No custom templates yet'}
            hint={
              filtered
                ? 'Clear a filter to see more templates.'
                : 'Notifications use the built-in defaults. Create a template, or clone a built-in, to change the wording.'
            }
          />
        ) : (
          <div className="space-y-6">
            {groups.map((group) => (
              <section key={group.eventType} aria-label={eventLabel(catalog, group.eventType)} className="space-y-3">
                <h3 className="text-sm font-semibold text-primary">
                  {eventLabel(catalog, group.eventType)}{' '}
                  {group.eventType !== ANY_EVENT && <span className="font-mono text-xs font-normal text-tertiary">{group.eventType}</span>}
                </h3>
                {group.families.map(({ family, items }) => (
                  <div key={family} className="space-y-2">
                    <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-tertiary">
                      {FAMILY_LABEL[family]}
                      <InfoNote label={`About the ${FAMILY_LABEL[family]} family`}>{FAMILY_INFO[family]}</InfoNote>
                    </div>
                    <ul className="divide-y divide-secondary rounded-lg border border-secondary">
                      {items.map((template) => (
                        <TemplateRow key={template.id} template={template} />
                      ))}
                    </ul>
                  </div>
                ))}
              </section>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

function TemplateRow({ template }: { template: NotificationTemplate }) {
  return (
    <li className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
      <div className="min-w-0 space-y-1">
        <Link to={`/settings/templates/${encodeURIComponent(template.id)}`} className="text-sm font-semibold text-brand-secondary hover:underline">
          {template.name}
        </Link>
        <div className="flex flex-wrap items-center gap-2 text-xs text-tertiary">
          <StatusBadge status={template.status} />
          <Pill>{LOCALE_LABEL[template.locale] ?? template.locale}</Pill>
          <span>
            Latest v{template.latest_version}
            {template.active_version > 0 ? ` · renders v${template.active_version}` : ' · never activated'}
          </span>
        </div>
      </div>
      <span className="text-xs text-tertiary">Updated {formatDateTime(template.updated_at)}</span>
    </li>
  )
}

function BuiltinList({
  builtins,
  error,
  catalog,
  onClone,
}: {
  builtins: BuiltinNotificationTemplate[] | undefined
  error: string | null
  catalog: NotificationEventSpec[]
  onClone: (builtin: BuiltinNotificationTemplate) => void
}) {
  if (builtins === undefined) return <Spinner label="Loading built-in defaults…" />
  if (error) return <ErrorState message={`Could not load the built-in defaults: ${error}`} />
  if (builtins.length === 0) {
    return (
      <EmptyState
        icon={FileCode02}
        title="Built-in defaults are not available in this build yet"
        hint="They ship with the default template set (#1366). Until then notifications use the fixed wording, and you can still write a custom template from scratch."
      />
    )
  }
  return (
    <ul className="divide-y divide-secondary rounded-lg border border-secondary">
      {builtins.map((builtin) => {
        const label = `${eventLabel(catalog, builtin.event_type)} · ${FAMILY_LABEL[builtin.family]} · ${LOCALE_LABEL[builtin.locale] ?? builtin.locale}`
        return (
          <li key={`${builtin.event_type}/${builtin.family}/${builtin.locale}`} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
            <div className="min-w-0">
              <p className="text-sm font-medium text-primary">{label}</p>
              <p className="text-xs text-tertiary">Read-only built-in default</p>
            </div>
            <Button variant="secondary" aria-label={`Clone ${label}`} onClick={() => onClone(builtin)}>
              <Copy01 className="size-4" /> Clone to customize
            </Button>
          </li>
        )
      })}
    </ul>
  )
}

interface TemplateGroup {
  eventType: string
  families: Array<{ family: NotificationTemplateFamily; items: NotificationTemplate[] }>
}

/** Groups by event type (`*` first, then alphabetical), then by family in catalog order. */
export function groupTemplates(templates: NotificationTemplate[]): TemplateGroup[] {
  const byEvent = new Map<string, NotificationTemplate[]>()
  for (const template of templates) {
    const list = byEvent.get(template.event_type) ?? []
    list.push(template)
    byEvent.set(template.event_type, list)
  }
  const eventTypes = [...byEvent.keys()].sort((a, b) => (a === ANY_EVENT ? -1 : b === ANY_EVENT ? 1 : a.localeCompare(b)))
  return eventTypes.map((eventType) => {
    const items = byEvent.get(eventType) ?? []
    return {
      eventType,
      families: TEMPLATE_FAMILIES.map((family) => ({
        family,
        items: items.filter((item) => item.family === family).sort((a, b) => a.name.localeCompare(b.name)),
      })).filter((entry) => entry.items.length > 0),
    }
  })
}

export default TemplateLibrary
