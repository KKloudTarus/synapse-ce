import { BarChart01 } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { CodeQualityView } from '../../lib/types'
import { Card, EmptyState, ErrorState, Spinner } from '../../components/ui'
import { CodeQualityReportView } from '../../components/codequality/CodeQualityReportView'
import { useFetch } from '../../hooks'

// CodeQualityTab loads the latest stored engagement-scoped report; rendering is shared with Project shells.
export function CodeQualityTab({ engagementId }: { engagementId: string }) {
  const { data: view, loading, error } = useFetch<CodeQualityView>(
    () => api.codeQuality(engagementId),
    { deps: [engagementId] },
  )

  if (error) return <ErrorState message={error} />
  if (loading || !view) return <Spinner label="Loading latest code quality result…" />

  return (
    <CodeQualityReportView
      report={view.report}
      empty={
        <Card title="Analysis">
          <EmptyState
            icon={BarChart01}
            title="Code Quality unavailable"
            hint={view.reason || 'Run an Engagement scan with Code quality enabled to generate a stored report.'}
          />
        </Card>
      }
    />
  )
}
