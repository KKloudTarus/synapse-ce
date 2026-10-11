import { ArrowLeft, BellRinging01, CheckCircle, FileCode02, RefreshCw01, Archive } from '@untitledui/icons'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom'
import { TextArea } from '../../../components/base/textarea/textarea'
import { Button, Card, EmptyState, ErrorState, Field, InfoNote, Input, Select, Spinner } from '../../../components/ui'
import {
  api,
  ApiError,
  TEMPLATE_FAMILIES,
  TEMPLATE_FAMILY_FIELDS,
  TEMPLATE_FIELD_MAX_BYTES,
  TEMPLATE_LOCALES,
  TEMPLATE_VERSION_PAGE,
  templateValidationError,
  type NotificationEventSpec,
  type NotificationTemplateDetail,
  type NotificationTemplateFamily,
  type NotificationTemplateLocale,
  type NotificationTemplateVersion,
} from '../../../lib/api'
import type { TemplateCloneState } from './TemplateLibrary'
import { VariablePicker } from './VariablePicker'
import { VersionHistory } from './VersionHistory'
import {
  ANY_EVENT,
  FAMILY_INFO,
  FAMILY_LABEL,
  FIELD_LABEL,
  LOCALE_LABEL,
  PermissionDenied,
  StatusBadge,
  errorMessage,
  eventLabel,
  isForbidden,
  templateVariables,
  useTemplateAccess,
} from './shared'

type FieldErrors = Record<string, string>

interface EditorLocationState extends Partial<TemplateCloneState> {
  notice?: string
}

export const STALE_MESSAGE =
  'This template changed since you opened it: someone else saved, activated or archived it. The latest state has been reloaded and your unsaved text is kept; review it and try again.'

/** Settings → Templates → a template: create a draft, save versions, activate, roll back, archive. */
export function TemplateEditor() {
  const access = useTemplateAccess()
  const { id } = useParams()

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
  // Keyed by the template so moving from "new" to the created template starts a fresh form.
  return <Editor key={id ?? 'new'} id={id} />
}

function familyFields(family: NotificationTemplateFamily, source: Record<string, string> | undefined): Record<string, string> {
  return Object.fromEntries(TEMPLATE_FAMILY_FIELDS[family].map((field) => [field, source?.[field] ?? '']))
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).length
}

/**
 * The inline text of an engine rejection: the line or the JSON path of a custom webhook body (#1376)
 * first, then the stable code, then the message.
 */
export function formatValidation(error: { error: string; code?: string; line?: number; path?: string }): string {
  const prefix = [error.line ? `Line ${error.line}` : '', error.path ?? '', error.code ?? ''].filter(Boolean).join(' · ')
  return prefix ? `${prefix}: ${error.error}` : error.error
}

function Editor({ id }: { id: string | undefined }) {
  const creating = id === undefined
  const navigate = useNavigate()
  const location = useLocation()
  const locationState = (location.state ?? null) as EditorLocationState | null
  const clone = creating ? locationState?.clone : undefined

  const [catalog, setCatalog] = useState<NotificationEventSpec[] | undefined>(undefined)
  const [catalogError, setCatalogError] = useState<string | null>(null)
  const [detail, setDetail] = useState<NotificationTemplateDetail | undefined>(undefined)
  const [versions, setVersions] = useState<NotificationTemplateVersion[]>([])
  const [hasOlder, setHasOlder] = useState(false)
  const [loadingOlder, setLoadingOlder] = useState(false)
  const [olderError, setOlderError] = useState<string | null>(null)
  const [loadError, setLoadError] = useState<{ message: string; status: number } | null>(null)
  const [forbidden, setForbidden] = useState(false)
  const [generation, setGeneration] = useState(0)

  const initialFamily = clone?.family ?? 'chat'
  const [name, setName] = useState(clone ? `Custom ${clone.event_type} ${clone.family} (${clone.locale})` : '')
  const [eventType, setEventType] = useState(clone?.event_type ?? ANY_EVENT)
  const [family, setFamily] = useState<NotificationTemplateFamily>(initialFamily)
  const [locale, setLocale] = useState<NotificationTemplateLocale>(clone?.locale ?? 'en')
  const [fields, setFields] = useState<Record<string, string>>(() => familyFields(initialFamily, clone?.fields))
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(locationState?.notice ?? (clone ? 'Cloned from the built-in default. Save to create your draft.' : null))
  const [busy, setBusy] = useState<string | null>(null)

  const fieldRefs = useRef<Record<string, HTMLTextAreaElement | null>>({})
  const lastFocused = useRef<string | null>(null)
  const historyGeneration = useRef(0)

  useEffect(() => {
    let live = true
    api.listNotificationEventTypes().then(
      (items) => live && setCatalog(items),
      (caught) => {
        if (!live) return
        setCatalogError(errorMessage(caught))
        setCatalog([])
      },
    )
    return () => {
      live = false
    }
  }, [])

  /** Loads the template and its versions. `keepText` leaves the text being edited alone (a 409). */
  const load = useCallback(
    async (keepText: boolean) => {
      if (id === undefined) return
      try {
        const [loaded, history] = await Promise.all([api.getNotificationTemplate(id), api.listNotificationTemplateVersions(id)])
        setDetail(loaded)
        showVersions(history)
        setLoadError(null)
        if (!keepText) {
          setName(loaded.name)
          setEventType(loaded.event_type)
          setFamily(loaded.family)
          setLocale(loaded.locale)
          setFields(familyFields(loaded.family, loaded.latest?.fields))
        }
      } catch (caught) {
        if (isForbidden(caught)) return setForbidden(true)
        setLoadError({ message: errorMessage(caught), status: caught instanceof ApiError ? caught.status : 0 })
      }
    },
    [id],
  )

  useEffect(() => {
    void load(false)
  }, [load, generation])

  /**
   * Replaces the history with its newest page; older pages load on demand. Replacing the history
   * starts a new generation, so an older page requested for the previous history is dropped when it
   * answers instead of being appended to the new one.
   */
  function showVersions(page: NotificationTemplateVersion[]) {
    historyGeneration.current += 1
    setVersions(page)
    setHasOlder(page.length === TEMPLATE_VERSION_PAGE)
    setOlderError(null)
    setLoadingOlder(false)
  }

  async function refreshVersions(templateId: string) {
    try {
      showVersions(await api.listNotificationTemplateVersions(templateId))
    } catch {
      // The mutation succeeded; the history stays as it was until the next load.
    }
  }

  async function loadOlder() {
    if (!detail || versions.length === 0) return
    const generation = historyGeneration.current
    setLoadingOlder(true)
    setOlderError(null)
    try {
      const page = await api.listNotificationTemplateVersions(detail.id, versions[versions.length - 1].version)
      if (generation !== historyGeneration.current) return
      setVersions((current) => [...current, ...page.filter((v) => !current.some((known) => known.version === v.version))])
      setHasOlder(page.length === TEMPLATE_VERSION_PAGE)
    } catch (caught) {
      if (generation === historyGeneration.current) setOlderError(errorMessage(caught))
    } finally {
      if (generation === historyGeneration.current) setLoadingOlder(false)
    }
  }

  const variables = useMemo(() => templateVariables(catalog ?? [], eventType), [catalog, eventType])
  const fieldNames = TEMPLATE_FAMILY_FIELDS[family]
  const savedFields = detail ? familyFields(detail.family, detail.latest?.fields) : undefined
  const dirty = creating || !detail || name.trim() !== detail.name || fieldNames.some((field) => (fields[field] ?? '') !== (savedFields?.[field] ?? ''))

  if (forbidden) return <PermissionDenied />
  if (!creating && loadError && !detail) {
    if (loadError.status === 404) {
      return (
        <EmptyState
          icon={FileCode02}
          title="Template not found"
          hint="It may belong to another tenant or the link is wrong."
          action={<BackLink />}
        />
      )
    }
    return (
      <div className="space-y-3">
        <BackLink />
        <ErrorState message={`Could not load the template: ${loadError.message}`} />
        <Button variant="secondary" onClick={() => setGeneration((value) => value + 1)}>
          <RefreshCw01 className="size-4" /> Retry
        </Button>
      </div>
    )
  }
  if (!creating && !detail) return <Spinner label="Loading template…" />

  function changeFamily(next: NotificationTemplateFamily) {
    setFamily(next)
    setFields((current) => familyFields(next, current))
    setFieldErrors({})
  }

  function changeField(field: string, value: string) {
    setFields((current) => ({ ...current, [field]: value }))
    setFieldErrors((current) => {
      if (!(field in current)) return current
      const rest = { ...current }
      delete rest[field]
      return rest
    })
  }

  function insertVariable(token: string) {
    const target = lastFocused.current && fieldNames.includes(lastFocused.current) ? lastFocused.current : fieldNames[0]
    const element = fieldRefs.current[target]
    const current = fields[target] ?? ''
    // Before any field was focused the cursor position means nothing, so the token goes at the end.
    const focused = lastFocused.current === target && element
    const start = focused ? element.selectionStart ?? current.length : current.length
    const end = focused ? element.selectionEnd ?? start : start
    const next = current.slice(0, start) + token + current.slice(end)
    changeField(target, next)
    const caret = start + token.length
    window.setTimeout(() => {
      element?.focus()
      element?.setSelectionRange(caret, caret)
    }, 0)
  }

  function validateLocally(): boolean {
    const errors: FieldErrors = {}
    if (name.trim() === '') errors.name = 'Enter a name.'
    for (const field of fieldNames) {
      if (byteLength(fields[field] ?? '') > TEMPLATE_FIELD_MAX_BYTES) errors[field] = `At most ${TEMPLATE_FIELD_MAX_BYTES / 1024} KiB.`
    }
    const blank = fieldNames.every((field) => (fields[field] ?? '').trim() === '')
    setFieldErrors(errors)
    setFormError(blank ? 'Write at least one field.' : null)
    return Object.keys(errors).length === 0 && !blank
  }

  /** Routes a failed mutation to the field it names, the stale-revision reload, or the form. */
  async function handleError(caught: unknown) {
    const validation = templateValidationError(caught)
    if (validation) {
      if (validation.field && fieldNames.includes(validation.field)) {
        setFieldErrors({ [validation.field]: formatValidation(validation) })
        setFormError(null)
      } else {
        setFormError(formatValidation(validation))
      }
      return
    }
    if (caught instanceof ApiError && caught.status === 409) {
      await load(true)
      setFormError(STALE_MESSAGE)
      return
    }
    if (isForbidden(caught)) return setForbidden(true)
    setFormError(errorMessage(caught))
  }

  function sentFields(): Record<string, string> {
    return Object.fromEntries(fieldNames.filter((field) => (fields[field] ?? '') !== '').map((field) => [field, fields[field]]))
  }

  async function save() {
    setNotice(null)
    if (!validateLocally()) return
    setBusy('save')
    try {
      if (creating) {
        const created = await api.createNotificationTemplate({ name: name.trim(), event_type: eventType, family, locale, fields: sentFields() })
        const state: EditorLocationState = { notice: 'Draft created as version 1. Activate it to make it render.' }
        navigate(`/settings/templates/${encodeURIComponent(created.id)}`, { replace: true, state })
        return
      }
      if (!detail) return
      const trimmed = name.trim()
      const updated = await api.updateNotificationTemplate(detail.id, {
        name: trimmed !== detail.name ? trimmed : undefined,
        fields: sentFields(),
        revision: detail.revision,
      })
      setDetail(updated)
      setName(updated.name)
      await refreshVersions(detail.id)
      setNotice(`Saved version ${updated.latest_version}. What renders does not change until you activate it.`)
    } catch (caught) {
      await handleError(caught)
    } finally {
      setBusy(null)
    }
  }

  async function change(action: 'activate' | 'rollback' | 'archive', version?: number) {
    if (!detail) return
    setNotice(null)
    setFormError(null)
    setFieldErrors({})
    setBusy(action === 'rollback' ? `rollback-${version}` : action)
    try {
      const updated =
        action === 'activate'
          ? await api.activateNotificationTemplate(detail.id, { revision: detail.revision, version: detail.latest_version })
          : action === 'rollback'
            ? await api.rollbackNotificationTemplate(detail.id, { revision: detail.revision, version: version ?? 0 })
            : await api.archiveNotificationTemplate(detail.id, { revision: detail.revision })
      setDetail(updated)
      await refreshVersions(detail.id)
      const archivedOther = updated.archived_template_id
        ? ' The template that was active for the same event, family and language has been archived.'
        : ''
      setNotice(
        action === 'archive'
          ? 'Archived. Messages for this key fall back to the next template, then the built-in default.'
          : `Version ${updated.active_version} now renders.${archivedOther}`,
      )
    } catch (caught) {
      await handleError(caught)
    } finally {
      setBusy(null)
    }
  }

  const eventOptions = [
    { value: ANY_EVENT, label: 'Any event (*)' },
    ...(catalog ?? []).map((spec) => ({ value: spec.type, label: spec.label || spec.type })),
    // A cloned key shows while the catalog loads, and when the catalog no longer lists its event.
    ...(eventType !== ANY_EVENT && !(catalog ?? []).some((spec) => spec.type === eventType) ? [{ value: eventType, label: eventType }] : []),
  ]
  const latestRenders = detail?.status === 'active' && detail.active_version === detail.latest_version

  return (
    <div className="space-y-6">
      <BackLink />
      <header className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold text-primary">{creating ? 'New template' : detail?.name}</h2>
        {detail && <StatusBadge status={detail.status} />}
        {detail && (
          <span className="text-xs text-tertiary">
            Latest v{detail.latest_version}
            {detail.active_version > 0 ? ` · renders v${detail.active_version}` : ' · never activated'}
          </span>
        )}
      </header>

      {notice && (
        <p role="status" className="rounded-lg border border-success/30 bg-success/10 px-4 py-2 text-sm text-success-primary">
          {notice}
        </p>
      )}
      {formError && <ErrorState message={formError} />}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Card title="Template">
          <form
            className="space-y-5"
            onSubmit={(event) => {
              event.preventDefault()
              void save()
            }}
          >
            <div className="space-y-1.5">
              <Field label="Name" htmlFor="template-name">
                <Input
                  id="template-name"
                  value={name}
                  maxLength={200}
                  aria-invalid={fieldErrors.name ? true : undefined}
                  aria-describedby={fieldErrors.name ? 'template-name-error' : undefined}
                  onChange={(event) => {
                    setName(event.target.value)
                    setFieldErrors(({ name: _drop, ...rest }) => rest)
                  }}
                />
              </Field>
              {fieldErrors.name && (
                <p id="template-name-error" className="text-sm text-error-primary">
                  {fieldErrors.name}
                </p>
              )}
            </div>

            {creating ? (
              <div className="grid gap-4 sm:grid-cols-3">
                <Field label="Event" htmlFor="template-event" hint="A template for any event (*) is used when no event-specific template matches.">
                  <Select id="template-event" ariaLabel="Event" value={eventType} onValueChange={setEventType} options={eventOptions} />
                </Field>
                <Field label="Channel family" htmlFor="template-family" hint="Channels of one family render the same fields.">
                  <Select
                    id="template-family"
                    ariaLabel="Channel family"
                    value={family}
                    onValueChange={(value) => changeFamily(value as NotificationTemplateFamily)}
                    options={TEMPLATE_FAMILIES.map((value) => ({ value, label: FAMILY_LABEL[value] }))}
                  />
                </Field>
                <Field label="Language" htmlFor="template-locale" hint="Any language (*) is used when no template for the channel's language exists.">
                  <Select
                    id="template-locale"
                    ariaLabel="Language"
                    value={locale}
                    onValueChange={(value) => setLocale(value as NotificationTemplateLocale)}
                    options={TEMPLATE_LOCALES.map((value) => ({ value, label: LOCALE_LABEL[value] }))}
                  />
                </Field>
              </div>
            ) : (
              <dl className="grid gap-4 text-sm sm:grid-cols-3">
                <KeyFact label="Event" value={eventLabel(catalog ?? [], eventType)} />
                <KeyFact label="Channel family" value={FAMILY_LABEL[family]} info={FAMILY_INFO[family]} />
                <KeyFact label="Language" value={LOCALE_LABEL[locale] ?? locale} />
                <p className="text-xs text-tertiary sm:col-span-3">The event, family and language are fixed after creation.</p>
              </dl>
            )}
            {catalogError && <p className="text-sm text-warning-primary">Could not load the event catalog: {catalogError}</p>}

            {fieldNames.map((field) => (
              <TextArea
                key={field}
                label={FIELD_LABEL[field] ?? field}
                rows={field === 'body' || field === 'description' ? 8 : 2}
                value={fields[field] ?? ''}
                onChange={(value) => changeField(field, value)}
                onFocus={() => {
                  lastFocused.current = field
                }}
                isInvalid={Boolean(fieldErrors[field])}
                hint={fieldErrors[field]}
                textAreaRef={(element) => {
                  fieldRefs.current[field] = element
                }}
                textAreaClassName="font-mono"
              />
            ))}

            <div className="flex flex-wrap gap-2">
              <Button type="submit" loading={busy === 'save'} disabled={busy !== null || !dirty}>
                {creating ? 'Create draft' : 'Save new version'}
              </Button>
              {!creating && detail && (
                <>
                  <Button
                    type="button"
                    variant="secondary-color"
                    loading={busy === 'activate'}
                    disabled={busy !== null || dirty || latestRenders}
                    title={dirty ? 'Save your changes first; activation renders a saved version.' : latestRenders ? 'The latest version already renders.' : undefined}
                    onClick={() => void change('activate')}
                  >
                    <CheckCircle className="size-4" /> Activate v{detail.latest_version}
                  </Button>
                  {detail.status !== 'archived' && (
                    <Button type="button" variant="ghost" loading={busy === 'archive'} disabled={busy !== null} onClick={() => void change('archive')}>
                      <Archive className="size-4" /> Archive
                    </Button>
                  )}
                </>
              )}
            </div>
          </form>
        </Card>

        <div className="space-y-6">
          <Card>
            <VariablePicker eventType={eventType} variables={variables} disabled={busy !== null} onInsert={insertVariable} />
          </Card>
        </div>
      </div>

      {!creating && detail && (
        <Card
          title={
            <span className="inline-flex items-center gap-1.5">
              Version history
              <InfoNote label="About versions">
                Versions are append-only. Rolling back activates an earlier version; it never rewrites one.
              </InfoNote>
            </span>
          }
        >
          <VersionHistory
            detail={detail}
            versions={versions}
            fieldNames={TEMPLATE_FAMILY_FIELDS[detail.family]}
            busy={busy}
            hasOlder={hasOlder}
            loadingOlder={loadingOlder}
            olderError={olderError}
            onLoadOlder={() => void loadOlder()}
            loadVersion={(version) => api.getNotificationTemplateVersion(detail.id, version)}
            onRollback={(version) => change('rollback', version)}
          />
        </Card>
      )}
    </div>
  )
}

function KeyFact({ label, value, info }: { label: string; value: string; info?: string }) {
  return (
    <div>
      <dt className="flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider text-tertiary">
        {label}
        {info && <InfoNote label={`About ${label.toLowerCase()}`}>{info}</InfoNote>}
      </dt>
      <dd className="mt-1 text-primary">{value}</dd>
    </div>
  )
}

function BackLink() {
  return (
    <Link to="/settings/templates" className="inline-flex items-center gap-1.5 text-sm font-semibold text-brand-secondary hover:underline">
      <ArrowLeft className="size-4" /> All templates
    </Link>
  )
}

export default TemplateEditor
