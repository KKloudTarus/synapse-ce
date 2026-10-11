import { RefreshCw01, ReverseLeft } from '@untitledui/icons'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Badge } from '../../../components/base/badges/badges'
import { ConfirmDialog } from '../../../components/synapse/ConfirmDialog'
import { Button, ErrorState, InfoNote, Select, Spinner } from '../../../components/ui'
import type { NotificationTemplateDetail, NotificationTemplateVersion } from '../../../lib/api'
import { FIELD_LABEL, errorMessage, formatDateTime } from './shared'
import { diffFields, type DiffLine, type DiffRow, type FieldDiff } from './versionDiff'

export interface VersionHistoryProps {
  detail: NotificationTemplateDetail
  /** Newest first, as the API pages them. */
  versions: NotificationTemplateVersion[]
  fieldNames: string[]
  busy: string | null
  hasOlder: boolean
  loadingOlder: boolean
  olderError: string | null
  onLoadOlder: () => void
  /** Reads one saved version that is not in the loaded pages. */
  loadVersion: (version: number) => Promise<NotificationTemplateVersion>
  onRollback: (version: number) => Promise<void>
}

/** The version that renders now, or 0 when none does (a draft, or an archived template). */
function renderingVersion(detail: NotificationTemplateDetail): number {
  return detail.status === 'active' ? detail.active_version : 0
}

/** The version a version's changes are measured against. Versions are numbered 1, 2, 3… without gaps. */
function predecessor(version: number): number {
  return version > 1 ? version - 1 : version
}

/**
 * The pair compared when the history opens: what renders against the latest when they differ,
 * otherwise the latest against the version before it. It reads the template, not the loaded pages,
 * so a rendering version older than the first page is still the baseline.
 */
export function defaultComparison(detail: NotificationTemplateDetail): { from: number; to: number } {
  const to = detail.latest_version
  const rendering = renderingVersion(detail)
  if (rendering > 0 && rendering !== to) return { from: rendering, to }
  return { from: predecessor(to), to }
}

/**
 * Settings → Templates → a template → Version history (#1375): every version with who saved it and
 * when, a side-by-side diff of any two, and a rollback that is confirmed before it changes what renders.
 */
export function VersionHistory({ detail, versions, fieldNames, busy, hasOlder, loadingOlder, olderError, onLoadOlder, loadVersion, onRollback }: VersionHistoryProps) {
  const [pair, setPair] = useState(() => defaultComparison(detail))
  const [confirming, setConfirming] = useState<number | null>(null)
  // Versions read one by one for a comparison, outside the loaded pages. Saved versions never
  // change, so they stay valid; they never move the paging cursor, which follows `versions` only.
  const [fetched, setFetched] = useState<Map<number, NotificationTemplateVersion>>(() => new Map())
  const [fetchErrors, setFetchErrors] = useState<Record<number, string>>({})
  const requested = useRef(new Set<number>())

  // A save or an activation moves the latest or the rendering version: compare the new state.
  const latest = detail.latest_version
  const rendering = renderingVersion(detail)
  useEffect(() => {
    setPair(defaultComparison(detail))
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only a new latest or rendering version resets the pair
  }, [latest, rendering])

  // Every version the page knows: the loaded pages, the ones read for a comparison, and the latest
  // and active versions the template itself carries, which are authoritative whatever is paged.
  const known = useMemo(() => {
    const map = new Map<number, NotificationTemplateVersion>(fetched)
    for (const v of versions) map.set(v.version, v)
    for (const v of [detail.latest, detail.active]) if (v) map.set(v.version, v)
    return map
  }, [versions, fetched, detail.latest, detail.active])

  // A compared version that is not known yet is read on its own, never silently replaced.
  useEffect(() => {
    for (const number of [pair.from, pair.to]) {
      if (number < 1 || known.has(number) || requested.current.has(number) || fetchErrors[number]) continue
      requested.current.add(number)
      // Promise.resolve().then turns a synchronous throw into a rejection handled below.
      Promise.resolve().then(() => loadVersion(number)).then(
        (version) => setFetched((current) => new Map(current).set(version.version, version)),
        (caught) => {
          requested.current.delete(number)
          setFetchErrors((current) => ({ ...current, [number]: errorMessage(caught) }))
        },
      )
    }
  }, [pair.from, pair.to, known, fetchErrors, loadVersion])

  const from = known.get(pair.from)
  const to = known.get(pair.to)
  const diffs = useMemo(() => (from && to ? diffFields(fieldNames, from.fields, to.fields) : []), [fieldNames, from, to])

  if (versions.length === 0) return <p className="text-sm text-tertiary">No versions reported.</p>

  const options = [...known.keys()].sort((a, b) => b - a).map((number) => ({ value: String(number), label: versionLabel(detail, number) }))
  const target = confirming === null ? undefined : known.get(confirming)
  // The rollback baseline is what renders now, else the latest: both come with the template.
  const current = rendering > 0 ? (detail.active ?? known.get(rendering)) : (detail.latest ?? known.get(latest))
  const missing = [pair.from, pair.to].filter((number) => !known.has(number))
  const failed = missing.find((number) => fetchErrors[number])

  function retryMissing() {
    setFetchErrors((current) => {
      const rest = { ...current }
      for (const number of missing) delete rest[number]
      return rest
    })
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,18rem)_minmax(0,1fr)]">
      <div className="space-y-3">
        {/* A long history scrolls inside the card, so the comparison and "Load older" stay in reach. */}
        <ol className="max-h-[36rem] divide-y divide-secondary overflow-y-auto pr-1" aria-label="Template versions">
          {versions.map((version) => {
            const renders = version.version === rendering
            const isLatest = version.version === latest
            const selected = version.version === pair.to
            return (
              <li key={version.version} className={`space-y-2 px-2 py-2.5 ${selected ? 'rounded-lg bg-secondary' : ''}`}>
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2 text-sm font-medium text-primary">
                    v{version.version}
                    {renders && (
                      <Badge type="pill-color" size="sm" color="success">
                        Renders
                      </Badge>
                    )}
                    {isLatest && (
                      <Badge type="pill-color" size="sm" color="gray">
                        Latest
                      </Badge>
                    )}
                  </div>
                  <p className="text-xs text-tertiary">
                    {formatDateTime(version.created_at)} · {version.created_by}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button
                    type="button"
                    variant="ghost"
                    className="px-2 py-1 text-xs"
                    aria-pressed={selected}
                    onClick={() => setPair({ from: predecessor(version.version), to: version.version })}
                  >
                    {version.version === 1 ? 'View v1' : `Changes in v${version.version}`}
                  </Button>
                  {!renders && !isLatest && (
                    <Button
                      type="button"
                      variant="secondary"
                      className="px-2.5 py-1 text-xs"
                      loading={busy === `rollback-${version.version}`}
                      disabled={busy !== null}
                      onClick={() => setConfirming(version.version)}
                    >
                      <ReverseLeft className="size-3.5" /> Roll back to v{version.version}
                    </Button>
                  )}
                </div>
              </li>
            )
          })}
        </ol>
        {olderError && <ErrorState message={`Could not load older versions: ${olderError}`} />}
        {hasOlder && (
          <Button type="button" variant="secondary" loading={loadingOlder} disabled={loadingOlder} onClick={onLoadOlder}>
            {olderError ? <RefreshCw01 className="size-4" /> : null}
            {olderError ? 'Retry' : 'Load older versions'}
          </Button>
        )}
      </div>

      <section aria-label="Compare versions" className="min-w-0 space-y-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="space-y-1 text-xs font-semibold uppercase tracking-wider text-tertiary">
            <span className="block">From</span>
            <Select ariaLabel="Compare from" size="sm" value={String(pair.from)} onValueChange={(value) => setPair((p) => ({ ...p, from: Number(value) }))} options={options} />
          </label>
          <label className="space-y-1 text-xs font-semibold uppercase tracking-wider text-tertiary">
            <span className="block">To</span>
            <Select ariaLabel="Compare to" size="sm" value={String(pair.to)} onValueChange={(value) => setPair((p) => ({ ...p, to: Number(value) }))} options={options} />
          </label>
          <InfoNote label="About the comparison">
            Lines removed from the first version are on the left, lines added in the second on the right. Pick the same version twice to read
            it on its own.
          </InfoNote>
        </div>
        {from && to ? (
          <div className="space-y-5">
            {diffs.map((diff) => (
              <FieldDiffView key={diff.field} diff={diff} from={pair.from} to={pair.to} />
            ))}
          </div>
        ) : failed !== undefined ? (
          <div className="space-y-3">
            <ErrorState message={`Could not load v${failed}: ${fetchErrors[failed]}`} />
            <Button type="button" variant="secondary" onClick={retryMissing}>
              <RefreshCw01 className="size-4" /> Retry
            </Button>
          </div>
        ) : (
          <Spinner label={`Loading v${missing.join(' and v')}…`} />
        )}
      </section>

      {target && (
        <ConfirmDialog
          open
          tone="brand"
          title={`Roll back to v${target.version}?`}
          description={<RollbackSummary detail={detail} target={target} current={current} fieldNames={fieldNames} />}
          confirmLabel={`Roll back to v${target.version}`}
          busy={busy === `rollback-${target.version}`}
          onCancel={() => setConfirming(null)}
          onConfirm={() => {
            void onRollback(target.version).finally(() => setConfirming(null))
          }}
        />
      )}
    </div>
  )
}

function versionLabel(detail: NotificationTemplateDetail, version: number): string {
  const tags = [version === renderingVersion(detail) ? 'renders' : '', version === detail.latest_version ? 'latest' : ''].filter(Boolean)
  return tags.length > 0 ? `v${version} (${tags.join(', ')})` : `v${version}`
}

/** What the rollback changes: which version stops rendering and which fields differ from it. */
function RollbackSummary({
  detail,
  target,
  current,
  fieldNames,
}: {
  detail: NotificationTemplateDetail
  target: NotificationTemplateVersion
  current: NotificationTemplateVersion | undefined
  fieldNames: string[]
}) {
  const rendering = renderingVersion(detail)
  const changed = current ? diffFields(fieldNames, current.fields, target.fields).filter((d) => d.changed).map((d) => FIELD_LABEL[d.field] ?? d.field) : []
  return (
    <div className="space-y-2">
      <p>
        {rendering > 0
          ? `Messages will render v${target.version} instead of v${rendering}.`
          : `The template becomes active and messages will render v${target.version}.`}
        {detail.status === 'archived' ? ' Rolling back un-archives it.' : ''}
        {rendering === 0 ? ' Another template active for the same event, family and language is archived.' : ''}
      </p>
      {current && (
        <p>
          {changed.length > 0 ? `Fields that differ from v${current.version}: ${changed.join(', ')}.` : `v${target.version} has the same text as v${current.version}.`}
        </p>
      )}
      <p>No version is deleted or rewritten, and the editor keeps the latest text. You can roll back again at any time.</p>
    </div>
  )
}

function FieldDiffView({ diff, from, to }: { diff: FieldDiff; from: number; to: number }) {
  const label = FIELD_LABEL[diff.field] ?? diff.field
  const viewing = from === to
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <h4 className="text-sm font-semibold text-primary">{label}</h4>
        {!viewing && (
          <Badge type="pill-color" size="sm" color={diff.changed ? 'warning' : 'gray'}>
            {diff.changed ? 'Changed' : 'Unchanged'}
          </Badge>
        )}
      </div>
      {diff.rows.length === 0 ? (
        <p className="text-sm text-tertiary">Empty in {viewing ? `v${to}` : 'both versions'}.</p>
      ) : !viewing && !diff.changed ? (
        <p className="text-sm text-tertiary">
          The same {diff.rows.length === 1 ? 'line' : `${diff.rows.length} lines`} in v{from} and v{to}.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-secondary">
          <table className="w-full min-w-[36rem] table-fixed border-collapse font-mono text-xs">
            <caption className="sr-only">{viewing ? `${label} in v${to}` : `${label}: changes from v${from} to v${to}`}</caption>
            <thead className="bg-secondary text-left text-[11px] font-semibold text-tertiary">
              <tr>
                <th scope="col" className="px-3 py-1.5">
                  v{from}
                </th>
                {!viewing && (
                  <th scope="col" className="border-l border-secondary px-3 py-1.5">
                    v{to}
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {diff.rows.map((row, index) => (
                <tr key={index} className="align-top">
                  <DiffCell line={row.left} side="left" kind={row.kind} />
                  {!viewing && <DiffCell line={row.right} side="right" kind={row.kind} />}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/** One side of a row. Removed and added lines also carry a sign and screen-reader text, not just color. */
function DiffCell({ line, side, kind }: { line: DiffLine | undefined; side: 'left' | 'right'; kind: DiffRow['kind'] }) {
  const border = side === 'right' ? 'border-l border-secondary' : ''
  if (!line) return <td className={`${border} bg-secondary/30`} />
  const marked = kind !== 'same'
  const tone = !marked ? 'text-secondary' : side === 'left' ? 'bg-error-primary/10 text-primary' : 'bg-success-primary/10 text-primary'
  const sign = !marked ? ' ' : side === 'left' ? '−' : '+'
  return (
    <td className={`${border} ${tone} px-0 py-0`}>
      <div className="flex">
        <span className="w-10 shrink-0 select-none px-2 py-0.5 text-right text-quaternary" aria-hidden="true">
          {line.number}
        </span>
        <span className="w-4 shrink-0 select-none py-0.5" aria-hidden="true">
          {sign}
        </span>
        <span className="min-w-0 whitespace-pre-wrap break-words py-0.5 pr-3">
          {marked && <span className="sr-only">{side === 'left' ? 'Removed: ' : 'Added: '}</span>}
          {line.text || ' '}
        </span>
      </div>
    </td>
  )
}
