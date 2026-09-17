import { ArrowRight, GitBranch01 as BranchIcon, GitPullRequest as PullRequestIcon, Minus, TrendDown01, TrendUp01 } from '@untitledui/icons'
import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Card, EmptyState, ErrorState, Spinner, cn } from '../../components/ui'
import { QualityGateBanner } from '../../components/codequality/projectOverview/QualityGateBanner'
import { api } from '../../lib/api'
import { useFetch } from '../../hooks'
import type { PercentageMetric, ProjectOverview, ProjectOverviewLens, RatingMetric } from '../../lib/projectOverview'
import { formatOverviewPercentage } from '../../lib/projectOverviewPresentation'
import { useProjectRouteContext } from './CodeQualityProject'

/** One selectable comparison target: a branch or a pull request, both resolving to an analysed branch. */
interface CompareTarget {
  /** Stable option value and the branch the overview is fetched for. */
  branch: string
  label: string
  kind: 'default' | 'long_lived' | 'short_lived' | 'pull_request'
}

type Direction = 'better' | 'worse' | 'same'

/** A single metric compared across the two sides, with the direction the change moved quality. */
interface MetricRow {
  key: string
  label: string
  base: string
  head: string
  direction: Direction
}

const GRADE_RANK: Record<string, number> = { A: 1, B: 2, C: 3, D: 4, E: 5 }

function ratingDisplay(metric: RatingMetric): string {
  return metric.availability === 'available' && metric.grade ? metric.grade : '—'
}

function percentDisplay(metric: PercentageMetric): string {
  return metric.availability === 'available' && metric.value !== null ? formatOverviewPercentage(metric.value) : '—'
}

/** ratingDirection: a lower grade letter is better (A best, E worst), so a head grade below the base improved. */
function ratingDirection(base: RatingMetric, head: RatingMetric): Direction {
  if (base.grade == null || head.grade == null) return 'same'
  const b = GRADE_RANK[base.grade]
  const h = GRADE_RANK[head.grade]
  if (h < b) return 'better'
  if (h > b) return 'worse'
  return 'same'
}

/** percentDirection: for a metric where higher is better (coverage, hotspots reviewed) pass higherIsBetter=true;
 * for duplications, where lower is better, pass false. */
function percentDirection(base: PercentageMetric, head: PercentageMetric, higherIsBetter: boolean): Direction {
  if (base.value == null || head.value == null) return 'same'
  if (head.value === base.value) return 'same'
  const rose = head.value > base.value
  return rose === higherIsBetter ? 'better' : 'worse'
}

function metricRows(base: ProjectOverviewLens, head: ProjectOverviewLens): MetricRow[] {
  return [
    { key: 'security', label: 'Security', base: ratingDisplay(base.security), head: ratingDisplay(head.security), direction: ratingDirection(base.security, head.security) },
    { key: 'reliability', label: 'Reliability', base: ratingDisplay(base.reliability), head: ratingDisplay(head.reliability), direction: ratingDirection(base.reliability, head.reliability) },
    { key: 'maintainability', label: 'Maintainability', base: ratingDisplay(base.maintainability), head: ratingDisplay(head.maintainability), direction: ratingDirection(base.maintainability, head.maintainability) },
    { key: 'coverage', label: 'Coverage', base: percentDisplay(base.coverage), head: percentDisplay(head.coverage), direction: percentDirection(base.coverage, head.coverage, true) },
    { key: 'duplications', label: 'Duplications', base: percentDisplay(base.duplications), head: percentDisplay(head.duplications), direction: percentDirection(base.duplications, head.duplications, false) },
    { key: 'hotspots', label: 'Hotspots reviewed', base: percentDisplay(base.securityHotspotsReviewed), head: percentDisplay(head.securityHotspotsReviewed), direction: percentDirection(base.securityHotspotsReviewed, head.securityHotspotsReviewed, true) },
  ]
}

export function ProjectComparisonPage() {
  const { projectKey, project } = useProjectRouteContext()
  const defaultBranch = project.sourceBinding.ref || 'main'
  const [searchParams, setSearchParams] = useSearchParams()

  const { data: branchList } = useFetch(() => api.projectBranches(projectKey), { deps: [projectKey], enabled: !!projectKey })
  // Analyses are the only source of pull-request identity (a PR analysis runs on its short-lived branch, and
  // the CI context carries the PR number and target). One page is enough to surface the recent PRs.
  const { data: analysisPage } = useFetch(() => api.projectAnalyses(projectKey), { deps: [projectKey], enabled: !!projectKey })

  const targets = useMemo<CompareTarget[]>(() => {
    const byBranch = new Map<string, CompareTarget>()
    byBranch.set(defaultBranch, { branch: defaultBranch, label: `${defaultBranch} (default)`, kind: 'default' })
    for (const b of branchList ?? []) {
      if (!b?.name || byBranch.has(b.name)) continue
      byBranch.set(b.name, { branch: b.name, label: b.kind === 'short_lived' ? `${b.name} · short-lived` : b.name, kind: b.kind })
    }
    // Overlay pull requests: a PR's branch is relabelled with its PR number and target, so it reads as a PR.
    const seenPR = new Set<string>()
    for (const a of analysisPage?.items ?? []) {
      const pr = a.ci?.pullRequest
      if (!pr || seenPR.has(pr)) continue
      seenPR.add(pr)
      const branch = a.ci?.branch || a.sourceRef
      if (!branch) continue
      const target = a.ci?.targetBranch ? ` → ${a.ci.targetBranch}` : ''
      byBranch.set(branch, { branch, label: `PR #${pr}${target}`, kind: 'pull_request' })
    }
    return [...byBranch.values()]
  }, [branchList, analysisPage, defaultBranch])

  const baseValue = searchParams.get('base') || defaultBranch
  const headValue = searchParams.get('head') || firstOtherBranch(targets, baseValue) || baseValue

  function setSide(side: 'base' | 'head', value: string) {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        next.set(side, value)
        return next
      },
      { replace: true },
    )
  }

  const swap = () => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        next.set('base', headValue)
        next.set('head', baseValue)
        return next
      },
      { replace: true },
    )
  }

  return (
    <div className="space-y-6">
      <Card className="shadow-xs">
        <div className="flex flex-col items-stretch gap-3 sm:flex-row sm:items-end">
          <SidePicker label="Base" value={baseValue} targets={targets} onChange={(v) => setSide('base', v)} />
          <button
            type="button"
            onClick={swap}
            aria-label="Swap base and compare"
            className="mx-auto inline-flex size-8 shrink-0 items-center justify-center self-center rounded-lg border border-secondary bg-primary text-tertiary transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 sm:mb-0.5"
          >
            <ArrowRight className="size-4" aria-hidden="true" />
          </button>
          <SidePicker label="Compare" value={headValue} targets={targets} onChange={(v) => setSide('head', v)} />
        </div>
      </Card>

      {baseValue === headValue ? (
        <EmptyState
          icon={BranchIcon}
          title="Pick two different targets"
          hint="Choose a base and a compare branch or pull request to see the Quality Gate and metric differences side by side."
        />
      ) : (
        <ComparisonBody projectKey={projectKey} base={baseValue} head={headValue} targets={targets} />
      )}
    </div>
  )
}

function firstOtherBranch(targets: CompareTarget[], exclude: string): string | undefined {
  return targets.find((t) => t.branch !== exclude)?.branch
}

function SidePicker({ label, value, targets, onChange }: { label: string; value: string; targets: CompareTarget[]; onChange: (value: string) => void }) {
  const current = targets.find((t) => t.branch === value)
  const Icon = current?.kind === 'pull_request' ? PullRequestIcon : BranchIcon
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-1">
      <span className="text-xs font-semibold uppercase tracking-wider text-tertiary">{label}</span>
      <span className="inline-flex items-center gap-2 rounded-lg border border-secondary bg-primary px-2.5 py-2">
        <Icon className="size-4 shrink-0 text-quaternary" aria-hidden="true" />
        <select
          aria-label={`${label} branch or pull request`}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          className="min-w-0 flex-1 bg-transparent font-mono text-sm text-primary focus:outline-none"
        >
          {targets.map((t) => (
            <option key={t.branch} value={t.branch}>{t.label}</option>
          ))}
          {!current && <option value={value}>{value}</option>}
        </select>
      </span>
    </label>
  )
}

function ComparisonBody({ projectKey, base, head, targets }: { projectKey: string; base: string; head: string; targets: CompareTarget[] }) {
  const baseOverview = useFetch(() => api.projectOverview(projectKey, base), { deps: [projectKey, base], enabled: !!projectKey })
  const headOverview = useFetch(() => api.projectOverview(projectKey, head), { deps: [projectKey, head], enabled: !!projectKey })

  if (baseOverview.loading || headOverview.loading) return <Spinner label="Loading comparison…" />
  if (baseOverview.error || headOverview.error) {
    return (
      <div className="space-y-3">
        <ErrorState message={baseOverview.error || headOverview.error || 'Failed to load the comparison'} />
        <button
          type="button"
          onClick={() => { baseOverview.refetch(); headOverview.refetch() }}
          className="rounded-lg border border-secondary bg-primary px-3 py-1.5 text-sm text-primary transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
        >
          Retry
        </button>
      </div>
    )
  }

  const baseData = baseOverview.data
  const headData = headOverview.data
  if (!baseData || !headData) return null

  const baseLabel = targets.find((t) => t.branch === base)?.label ?? base
  const headLabel = targets.find((t) => t.branch === head)?.label ?? head

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <GateColumn label={baseLabel} overview={baseData} />
        <GateColumn label={headLabel} overview={headData} />
      </div>
      <MetricDiff baseLabel={baseLabel} headLabel={headLabel} base={baseData} head={headData} />
    </div>
  )
}

function GateColumn({ label, overview }: { label: string; overview: ProjectOverview }) {
  return (
    <div className="space-y-2">
      <p className="truncate font-mono text-xs font-semibold text-secondary" title={label}>{label}</p>
      {overview.state === 'not_analyzed' || !overview.gate ? (
        <EmptyState icon={BranchIcon} title="Not analyzed" hint="This branch has no completed analysis yet." />
      ) : (
        <QualityGateBanner gate={overview.gate} />
      )}
    </div>
  )
}

function MetricDiff({ baseLabel, headLabel, base, head }: { baseLabel: string; headLabel: string; base: ProjectOverview; head: ProjectOverview }) {
  const rows = metricRows(base.lenses.overall, head.lenses.overall)
  return (
    <Card className="shadow-xs">
      <h2 className="mb-3 text-lg font-semibold text-primary">Overall code metrics</h2>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-secondary text-left text-xs uppercase tracking-wider text-tertiary">
              <th scope="col" className="py-2 pr-3 font-semibold">Metric</th>
              <th scope="col" className="px-3 py-2 text-right font-semibold"><span className="block max-w-40 truncate font-mono normal-case" title={baseLabel}>{baseLabel}</span></th>
              <th scope="col" className="px-3 py-2 text-right font-semibold"><span className="block max-w-40 truncate font-mono normal-case" title={headLabel}>{headLabel}</span></th>
              <th scope="col" className="py-2 pl-3 text-right font-semibold">Change</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.key} className="border-b border-secondary last:border-0">
                <th scope="row" className="py-2.5 pr-3 text-left font-medium text-primary">{row.label}</th>
                <td className="px-3 py-2.5 text-right font-mono tabular-nums text-secondary">{row.base}</td>
                <td className="px-3 py-2.5 text-right font-mono tabular-nums text-primary">{row.head}</td>
                <td className="py-2.5 pl-3 text-right"><ChangeCell direction={row.direction} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function ChangeCell({ direction }: { direction: Direction }) {
  if (direction === 'same') {
    return (
      <span className="inline-flex items-center justify-end gap-1 text-tertiary" title="No change">
        <Minus className="size-3.5" aria-hidden="true" />
        <span className="sr-only">No change</span>
      </span>
    )
  }
  const improved = direction === 'better'
  const Icon = improved ? TrendUp01 : TrendDown01
  return (
    <span
      className={cn('inline-flex items-center justify-end gap-1 text-xs font-semibold', improved ? 'text-utility-green-600 dark:text-utility-green-400' : 'text-error-primary')}
      title={improved ? 'Improved' : 'Regressed'}
    >
      <Icon className="size-3.5" aria-hidden="true" />
      {improved ? 'Improved' : 'Regressed'}
    </span>
  )
}
