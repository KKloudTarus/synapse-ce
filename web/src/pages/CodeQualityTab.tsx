import { useEffect, useState } from 'react'
import { Gauge } from 'lucide-react'
import { api } from '../lib/api'
import type { CodeQualityView } from '../lib/types'
import { Card, EmptyState, ErrorState, Spinner } from '../components/ui'
import { CodeQualityReportView } from '../components/codequality/CodeQualityReportView'

// CodeQualityTab loads the engagement-scoped report; rendering is shared with Project shells.
export function CodeQualityTab({ engagementId }: { engagementId: string }) {
  const [view, setView] = useState<CodeQualityView | undefined>(undefined)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    setView(undefined)
    setErr(null)
    api
      .codeQuality(engagementId)
      .then(setView)
      .catch((e) => setErr(e instanceof Error ? e.message : 'Failed to load code quality'))
  }, [engagementId])

  if (err) return <ErrorState message={err} />
  if (view === undefined) return <Spinner label="Analyzing code quality…" />

  return (
    <CodeQualityReportView
      report={view.report}
      empty={
        <Card title="Analysis">
          <EmptyState
            icon={Gauge}
            title="Code Quality unavailable"
            hint={view.reason || 'Code Quality requires an in-scope local source directory; this engagement has none.'}
          />
        </Card>
      }
    />
  )
}
