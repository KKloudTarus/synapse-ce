import type { ProjectOverviewLens } from '../../../lib/projectOverview'
import { metricCardsForLens, type CodeLens } from '../../../lib/projectOverviewPresentation'
import { OverviewMetricCard } from './OverviewMetricCard'

export function OverviewMetricGrid({ lens, metrics }: { lens: CodeLens; metrics: ProjectOverviewLens }) {
  const lensLabel = lens === 'overall' ? 'Overall Code' : 'New Code'
  return (
    <section aria-labelledby="overview-metrics-heading">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 id="overview-metrics-heading" className="text-lg font-semibold">Quality metrics</h2>
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {metricCardsForLens(metrics).map((card) => (
          <OverviewMetricCard key={card.key} card={card} lensLabel={lensLabel} />
        ))}
      </div>
    </section>
  )
}
