import { projectAnalysisLandmarks } from '../../lib/projectAnalysisNavigation'
import { formatOverviewPercentage } from '../../lib/projectOverviewPresentation'
import type { ProjectAnalysis } from '../../lib/types'
import { Card } from '../ui'

export function ProjectCoverageDetail({ coverage }: { coverage: ProjectAnalysis['coverage'] }) {
  return (
    <Card
      title="Coverage"
      titleId={projectAnalysisLandmarks.coverage}
      titleTabIndex={-1}
      titleClassName="scroll-mt-6 rounded-sm focus:outline-none focus:ring-2 focus:ring-brand/60"
    >
      {coverage === null ? (
        <p className="text-sm text-mutedfg">No coverage report was supplied for this analysis.</p>
      ) : coverage.totalLines === 0 ? (
        <p className="text-sm text-mutedfg">No executable lines were found in this analysis.</p>
      ) : (
        <div className="space-y-4">
          <div className="font-mono text-4xl font-semibold tabular-nums text-foreground">
            {formatOverviewPercentage(100 * coverage.coveredLines / coverage.totalLines)}
          </div>
          <dl className="grid gap-3 sm:grid-cols-3">
            <CoverageCount label="Covered lines" value={coverage.coveredLines} />
            <CoverageCount label="Uncovered lines" value={coverage.totalLines - coverage.coveredLines} />
            <CoverageCount label="Executable lines" value={coverage.totalLines} />
          </dl>
        </div>
      )}
    </Card>
  )
}

function CoverageCount({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex flex-col rounded-lg border border-border bg-bg px-4 py-3">
      <dt className="order-2 text-xs text-mutedfg">{label}</dt>
      <dd className="order-1 font-mono text-xl font-semibold tabular-nums text-foreground">{value.toLocaleString()}</dd>
    </div>
  )
}
