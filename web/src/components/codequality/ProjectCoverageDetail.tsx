import { projectAnalysisLandmarks } from '../../lib/projectAnalysisNavigation'
import { formatOverviewPercentage } from '../../lib/projectOverviewPresentation'
import type { ProjectAnalysis } from '../../lib/types'
import { Card, cn } from '../ui'

export function ProjectCoverageDetail({ coverage }: { coverage: ProjectAnalysis['coverage'] }) {
  if (coverage === null) {
    return (
      <Card
        title="Coverage"
        titleId={projectAnalysisLandmarks.coverage}
        titleTabIndex={-1}
        titleClassName="scroll-mt-6 rounded-sm focus:outline-none focus:ring-2 focus:ring-brand/60"
      >
        <p className="text-sm text-tertiary">No coverage report was supplied for this analysis.</p>
      </Card>
    )
  }

  if (coverage.totalLines === 0) {
    return (
      <Card
        title="Coverage"
        titleId={projectAnalysisLandmarks.coverage}
        titleTabIndex={-1}
        titleClassName="scroll-mt-6 rounded-sm focus:outline-none focus:ring-2 focus:ring-brand/60"
      >
        <p className="text-sm text-tertiary">No executable lines were found in this analysis.</p>
      </Card>
    )
  }

  const coveragePct = (100 * coverage.coveredLines) / coverage.totalLines
  const uncoveredLines = coverage.totalLines - coverage.coveredLines

  return (
    <Card
      title="Coverage breakdown"
      titleId={projectAnalysisLandmarks.coverage}
      titleTabIndex={-1}
      titleClassName="scroll-mt-6 rounded-sm focus:outline-none focus:ring-2 focus:ring-brand/60"
    >
      <div className="space-y-4">
        {/* Top Progress & Big Number */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-baseline gap-3">
            <span className="font-mono text-4xl font-bold tabular-nums text-primary">
              {formatOverviewPercentage(coveragePct)}
            </span>
            <span className="text-xs font-semibold text-tertiary">Overall Line Coverage</span>
          </div>

          <div className="flex items-center gap-4 text-xs font-medium">
            <div className="flex items-center gap-1.5">
              <span className="size-2.5 rounded-full bg-success-primary" />
              <span className="text-secondary">Covered: {coverage.coveredLines.toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="size-2.5 rounded-full bg-error-primary" />
              <span className="text-secondary">Uncovered: {uncoveredLines.toLocaleString()}</span>
            </div>
          </div>
        </div>

        {/* Visual Dual Progress Bar */}
        <div className="h-2.5 w-full rounded-full bg-secondary overflow-hidden flex shadow-2xs">
          <div
            className="h-full bg-success-primary transition-all"
            style={{ width: `${Math.max(0, Math.min(100, coveragePct))}%` }}
          />
          <div
            className="h-full bg-error-primary transition-all"
            style={{ width: `${Math.max(0, Math.min(100, 100 - coveragePct))}%` }}
          />
        </div>

        {/* Stat Cards according to Design Reference */}
        <dl className="grid gap-3 sm:grid-cols-3 pt-1">
          <CoverageStatCard
            label="Covered lines"
            value={coverage.coveredLines}
            tone="success"
          />
          <CoverageStatCard
            label="Uncovered lines"
            value={uncoveredLines}
            tone={uncoveredLines > 0 ? 'error' : 'neutral'}
          />
          <CoverageStatCard
            label="Executable lines"
            value={coverage.totalLines}
            tone="neutral"
          />
        </dl>
      </div>
    </Card>
  )
}

function CoverageStatCard({
  label,
  value,
  tone = 'neutral',
}: {
  label: string
  value: number
  tone?: 'success' | 'error' | 'neutral'
}) {
  return (
    <div
      className={cn(
        'rounded-xl border bg-primary p-4 shadow-xs flex flex-col justify-between',
        tone === 'success'
          ? 'border-success-primary/30 bg-success-primary/5'
          : tone === 'error'
            ? 'border-error-primary/30 bg-error-primary/5'
            : 'border-secondary',
      )}
    >
      <dt className="text-sm font-semibold text-secondary mb-2">{label}</dt>
      <dd
        className={cn(
          'font-mono text-3xl font-bold tabular-nums truncate',
          tone === 'success'
            ? 'text-success-primary'
            : tone === 'error'
              ? 'text-error-primary'
              : 'text-primary',
        )}
      >
        {value.toLocaleString()}
      </dd>
    </div>
  )
}
