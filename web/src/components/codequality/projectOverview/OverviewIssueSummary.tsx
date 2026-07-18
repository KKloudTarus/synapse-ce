import type { ProjectOverviewIssueSummary } from '../../../lib/projectOverview'
import { countMetricDisplay } from '../../../lib/projectOverviewPresentation'
import { Card } from '../../ui'

export function OverviewIssueSummary({ summary }: { summary: ProjectOverviewIssueSummary }) {
  const newCode = countMetricDisplay(summary.newCodeTotal)
  const accepted = countMetricDisplay(summary.acceptedOverallTotal)
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <SummaryItem label="New Code issues" display={newCode} />
      <SummaryItem label="Accepted issues (Overall Code)" display={accepted} />
    </div>
  )
}

function SummaryItem({ label, display }: { label: string; display: { value: string; label: string; reason: string | null } }) {
  return (
    <Card>
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-foreground">{label}</h2>
          <p className="mt-1 text-xs text-mutedfg">{display.reason ?? display.label}</p>
        </div>
        <div className="font-mono text-3xl font-semibold tabular-nums">{display.value}</div>
      </div>
    </Card>
  )
}
