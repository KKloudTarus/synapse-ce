import { LayoutGrid01 } from '@untitledui/icons'
import { EmptyState, ErrorState } from '../../components/ui'
import type { Finding, ScanJob, ScanResult, Severity } from '../../lib/types'
import type { Tab } from './index'
import { CompositionProvenanceCard } from './components/OverviewComposition'
import { ScanHealth } from './components/OverviewHealth'
import { RiskAnalysisZone } from './components/OverviewRisk'

// Re-export presentation pieces so existing imports keep resolving.
export { TABS, TabBar } from './components/OverviewTabBar'
export type { TabCounts } from './components/OverviewTabBar'
export { ScanHealth, HealthStat } from './components/OverviewHealth'
export {
  RiskAnalysisZone,
  FindingsActivityGauge,
  VulnDistribution,
  AttentionCard,
  CountBadge,
  remediationTargets,
} from './components/OverviewRisk'
export type { RemTarget } from './components/OverviewRisk'
export { CompositionProvenanceCard, CompTile, CardEmpty } from './components/OverviewComposition'

export function OverviewTab({
  findings,
  findingsError,
  scanError,
  scan,
  job,
  onSelectSeverity,
  onGoTab,
}: {
  findings: Finding[] | null
  /** Set when the findings request failed, so the risk zone does not read as "no findings". */
  findingsError?: string | null
  /** Set when the latest-scan request failed, which is not the same as no scan having been run. */
  scanError?: string | null
  scan: ScanResult | null
  job: ScanJob | null
  onSelectSeverity: (s: Severity | 'all') => void
  onGoTab: (t: Tab) => void
}) {
  if (scanError) return <ErrorState message={scanError} />
  if (!scan) {
    return (
      <EmptyState
        icon={LayoutGrid01}
        title="No scan yet"
        hint="Run a scan above to see risk analysis, remediation priorities, and software composition."
      />
    )
  }
  const open = findings ?? []
  return (
    <div className="space-y-4">
      {/* Zone 1: Health + Quality + Provenance Strip */}
      <ScanHealth scan={scan} job={job} />

      {/* Zone 2: Risk Analysis & Remediation Priorities */}
      {findingsError ? <ErrorState message={findingsError} /> : null}
      <RiskAnalysisZone
        findings={open}
        scan={scan}
        loading={findings === null}
        onSelectSeverity={onSelectSeverity}
        onGoTab={onGoTab}
      />

      {/* Zone 3: Composition & Provenance */}
      <CompositionProvenanceCard scan={scan} onGoTab={onGoTab} />
    </div>
  )
}
