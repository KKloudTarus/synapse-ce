import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle } from '@untitledui/icons'
import { api, ApiError } from '../../lib/api'
import { Button, EmptyState, ErrorState, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'

type ReviewItem = {
  engagement_id: string
  finding_id: string
  legacy_assignee: string
  reason: 'ambiguous' | 'unmatched' | 'legacy_label' | string
}

type ReviewCursor = { engagement_id: string; finding_id: string }

const REASONS: Record<string, string> = {
  ambiguous: 'Several users share this exact name. Open the finding and choose one person.',
  unmatched: 'No user in this tenant has this exact name. The label is unchanged and is not a recipient.',
  legacy_label: 'This label is not a user ID. Open the finding and choose the person again.',
}

export function AssigneeReview() {
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  const canAdmin = me?.role === 'admin' || me?.role === 'owner'
  const [items, setItems] = useState<ReviewItem[] | null>(null)
  const [next, setNext] = useState<ReviewCursor | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [denied, setDenied] = useState(false)
  const [loading, setLoading] = useState(false)

  const load = useCallback(async (cursor?: ReviewCursor) => {
    setLoading(true)
    setError(null)
    try {
      const page = await api.assigneeReview(cursor)
      const rows = Array.isArray(page?.items) ? (page.items as ReviewItem[]) : []
      setItems((prev) => (cursor ? [...(prev ?? []), ...rows] : rows))
      setNext(page?.next?.engagement_id && page?.next?.finding_id ? page.next : null)
      setDenied(false)
    } catch (err) {
      if (!cursor) setItems([])
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) setDenied(true)
      else setError(err instanceof Error ? err.message : 'Could not load assignee review')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (canAdmin) void load()
  }, [canAdmin, load])

  return (
    <section className="space-y-4" aria-labelledby="assignee-review-heading">
      <header>
        <h2 id="assignee-review-heading" className="text-lg font-semibold text-primary">
          Assignee review
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-secondary">
          Findings whose legacy assignee label could not be bound to one user. The label and any manual ownership lock stay as they are. Personal notification routing skips these rows until someone chooses a user.
        </p>
      </header>
      {!me ? (
        <Spinner label="Loading permissions…" />
      ) : !canAdmin || denied ? (
        <EmptyState
          icon={AlertTriangle}
          title="Administrator access required"
          hint="Only a tenant administrator can read unresolved assignee labels."
        />
      ) : error ? (
        <ErrorState message={error} />
      ) : items === null || (loading && items.length === 0) ? (
        <Spinner label="Loading unresolved assignees…" />
      ) : items.length === 0 ? (
        <EmptyState icon={AlertTriangle} title="No unresolved assignees" hint="Every non-empty legacy label on this tenant is bound to one user, or there is nothing to review." />
      ) : (
        <>
          <ul className="divide-y divide-secondary rounded-xl border border-secondary bg-primary">
            {items.map((item) => (
              <li key={`${item.engagement_id}:${item.finding_id}`} className="space-y-1 px-4 py-3">
                <p className="font-medium text-primary">
                  {item.legacy_assignee} <span className="font-normal text-tertiary">({item.finding_id})</span>
                </p>
                <p className="text-sm text-secondary">{REASONS[item.reason] ?? 'This label is not a canonical user.'}</p>
                <Link
                  className="text-sm text-brand-primary underline"
                  to={`/engagements/${encodeURIComponent(item.engagement_id)}/findings#finding-${encodeURIComponent(item.finding_id)}`}
                >
                  Open finding
                </Link>
              </li>
            ))}
          </ul>
          {next && (
            <Button variant="secondary" disabled={loading} onClick={() => void load(next)}>
              {loading ? 'Loading…' : 'Load more'}
            </Button>
          )}
        </>
      )}
    </section>
  )
}
