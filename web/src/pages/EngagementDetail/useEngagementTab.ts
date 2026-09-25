import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { isTab, type Tab } from './tabs'

/**
 * Keeps the active tab and the URL in step.
 *
 * The `:tabSlug` route segment is the source of truth, so /engagements/:id/<tab> deep links land on
 * the right tab and a tab change is a replace rather than a new history entry.
 */
export function useEngagementTab(id: string, tabSlug: string | undefined, hash: string) {
  const navigate = useNavigate()
  const [tab, setTabState] = useState<Tab>(() => (isTab(tabSlug) ? tabSlug : 'overview'))

  useEffect(() => {
    if (isTab(tabSlug)) setTabState(tabSlug)
    else if (!tabSlug) setTabState('overview')
  }, [tabSlug])

  const setTab = useCallback(
    (next: Tab) => {
      setTabState(next)
      const base = `/engagements/${encodeURIComponent(id)}`
      // Keep the hash: a #finding-<id> deep link switches to the Findings tab and the hash is what
      // FindingsTab scrolls to.
      navigate(`${next === 'overview' ? base : `${base}/${next}`}${hash}`, { replace: true })
    },
    [hash, id, navigate],
  )

  return { tab, setTab }
}
