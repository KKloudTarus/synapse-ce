import { Activity } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { ProjectActivityView } from '../../components/codequality/ProjectActivityView'
import { Button, Card, EmptyState, ErrorState } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { ProjectAnalysis, ProjectAnalysisCursor } from '../../lib/types'
import { useProjectRouteContext } from './CodeQualityProject'

export function ProjectActivityPage() {
  const { projectKey, analysisRevision } = useProjectRouteContext()
  const [analyses, setAnalyses] = useState<ProjectAnalysis[]>([])
  const [cursor, setCursor] = useState<ProjectAnalysisCursor | null>(null)
  const [loadingOlder, setLoadingOlder] = useState(false)
  const [olderError, setOlderError] = useState<string | null>(null)
  const olderRequestToken = useRef<symbol | null>(null)

  const { data: firstPage, loading, error, refetch: loadFirstPage } = useFetch(
    () => api.projectAnalyses(projectKey),
    { deps: [projectKey, analysisRevision] },
  )

  useEffect(() => {
    if (firstPage) {
      setAnalyses(firstPage.items)
      setCursor(firstPage.next)
      olderRequestToken.current = null
      setLoadingOlder(false)
      setOlderError(null)
    }
  }, [firstPage])

  async function loadOlder() {
    if (!cursor || loadingOlder || olderRequestToken.current) return
    const token = Symbol()
    olderRequestToken.current = token
    setLoadingOlder(true)
    setOlderError(null)
    try {
      const page = await api.projectAnalyses(projectKey, cursor)
      if (olderRequestToken.current !== token) return
      setAnalyses((current) => [...current, ...page.items])
      setCursor(page.next)
    } catch (e) {
      if (olderRequestToken.current === token) {
        setOlderError(e instanceof Error ? e.message : 'Failed to load older analyses')
      }
    } finally {
      if (olderRequestToken.current === token) {
        olderRequestToken.current = null
        setLoadingOlder(false)
      }
    }
  }

  if (loading) {
    return <Card title="Activity"><EmptyState icon={Activity} title="Loading activity" hint="Fetching immutable analysis history." /></Card>
  }
  if (error) {
    return (
      <div className="space-y-3">
        <ErrorState message={error} />
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
