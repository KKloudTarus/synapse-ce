import { Activity } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { ProjectActivityView } from '../components/codequality/ProjectActivityView'
import { Button, Card, EmptyState, ErrorState } from '../components/ui'
import { api } from '../lib/api'
import type { ProjectAnalysis, ProjectAnalysisCursor } from '../lib/types'
import { useProjectRouteContext } from './CodeQualityProject'

type LoadState =
  | { status: 'loading' }
  | { status: 'loaded' }
  | { status: 'error'; message: string }

export function ProjectActivityPage() {
  const { projectKey, analysisRevision } = useProjectRouteContext()
  const [state, setState] = useState<LoadState>({ status: 'loading' })
  const [analyses, setAnalyses] = useState<ProjectAnalysis[]>([])
  const [cursor, setCursor] = useState<ProjectAnalysisCursor | null>(null)
  const [loadingOlder, setLoadingOlder] = useState(false)
  const [olderError, setOlderError] = useState<string | null>(null)
  const requestToken = useRef<symbol | null>(null)
  const olderRequestToken = useRef<symbol | null>(null)

  function loadFirstPage() {
    const token = Symbol()
    requestToken.current = token
    olderRequestToken.current = null
    setLoadingOlder(false)
    setOlderError(null)
    setState({ status: 'loading' })
    api.projectAnalyses(projectKey)
      .then((page) => {
        if (requestToken.current !== token) return
        setAnalyses(page.items)
        setCursor(page.next)
        setState({ status: 'loaded' })
      })
      .catch((e) => {
        if (requestToken.current === token) setState({ status: 'error', message: e instanceof Error ? e.message : 'Failed to load activity' })
      })
  }

  async function loadOlder() {
    if (!cursor || loadingOlder || olderRequestToken.current) return
    const generation = requestToken.current
    if (!generation) return
    const token = Symbol()
    olderRequestToken.current = token
    setLoadingOlder(true)
    setOlderError(null)
    try {
      const page = await api.projectAnalyses(projectKey, cursor)
      if (requestToken.current !== generation || olderRequestToken.current !== token) return
      setAnalyses((current) => [...current, ...page.items])
      setCursor(page.next)
    } catch (e) {
      if (requestToken.current === generation && olderRequestToken.current === token) {
        setOlderError(e instanceof Error ? e.message : 'Failed to load older analyses')
      }
    } finally {
      if (requestToken.current === generation && olderRequestToken.current === token) {
        olderRequestToken.current = null
        setLoadingOlder(false)
      }
    }
  }

  useEffect(() => {
    loadFirstPage()
    return () => {
      requestToken.current = null
      olderRequestToken.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectKey, analysisRevision])

  if (state.status === 'loading') {
    return <Card title="Activity"><EmptyState icon={Activity} title="Loading activity" hint="Fetching immutable analysis history." /></Card>
  }
  if (state.status === 'error') {
    return (
      <div className="space-y-3">
        <ErrorState message={state.message} />
        <Button variant="secondary" onClick={loadFirstPage}>Retry activity</Button>
      </div>
    )
  }
  return (
    <div className="space-y-3">
      <ProjectActivityView analyses={analyses} hasOlder={cursor !== null} loadingOlder={loadingOlder} onLoadOlder={loadOlder} />
      {olderError && <ErrorState message={olderError} />}
    </div>
  )
}
