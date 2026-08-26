import { useState, useEffect, lazy, Suspense, type FC } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import {
  ArrowLeft,
  ChevronRight,
  LayoutGrid01,
  Package,
  ShieldTick,
  ShieldZap,
  Sliders04,
  Target04,
} from '@untitledui/icons'
import { Button, cn, EmptyState, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import type {
  Engagement,
  Finding,
  ImportedSBOMMetadata,
  ScanJob,
  ScanResult,
  Severity,
} from '../../lib/types'
import { AgentTab } from '../AgentTab'
import { ThreatModelTab } from './ThreatModelTab'
import { CodeQualityTab } from '../CodeQuality/CodeQualityTab'
import { SLATab } from './SLATab'
import { OverviewTab } from './OverviewTab'
import { FindingsTab } from './FindingsTab'
import { ScanPanel } from './ScanPanel'
import { ExportButtons } from './ExportButtons'
import { packageLocationMap, countVulnerabilityFindings, VulnsTab } from './VulnsTab'
import { LicensesTab } from './LicensesTab'
import { ComponentsTab } from './ComponentsTab'
import { ReconTab } from './ReconTab'
import { EvidenceTab } from './EvidenceTab'
import { SettingsTab } from './SettingsTab'
import { JudgmentReviewTab } from './ReviewsTab'

// Lazy-loaded so React Flow stays out of the initial bundle (only the Graph tab needs it).
const DependencyGraphTab = lazy(() => import('../DependencyGraph').then((m) => ({ default: m.DependencyGraphTab })))

export type Tab =
  | 'overview'
  | 'findings'
  | 'sla'
  | 'components'
  | 'vulns'
  | 'licenses'
  | 'graph'
  | 'quality'
  | 'threats'
  | 'recon'
  | 'agent'
  | 'reviews'
  | 'evidence'
  | 'settings'

export interface SubTabDefinition {
  id: Tab
  label: string
  countKey?: 'findings' | 'components' | 'vulns' | 'licenses'
}

export interface TabGroupDefinition {
  id: string
  label: string
  icon: FC<{ className?: string }>
  sub?: SubTabDefinition[]
}

export const TAB_GROUPS: TabGroupDefinition[] = [
  {
    id: 'overview',
    label: 'Overview',
    icon: LayoutGrid01,
  },
  {
    id: 'findings',
    label: 'Findings',
    icon: ShieldZap,
    sub: [
      { id: 'findings', label: 'All Findings', countKey: 'findings' },
      { id: 'sla', label: 'Remediation SLA' },
    ],
  },
  {
    id: 'supply-chain',
    label: 'Supply Chain',
    icon: Package,
    sub: [
      { id: 'components', label: 'Packages', countKey: 'components' },
      { id: 'vulns', label: 'Vulnerabilities', countKey: 'vulns' },
      { id: 'licenses', label: 'Licenses', countKey: 'licenses' },
      { id: 'graph', label: 'Dependency Graph' },
    ],
  },
  {
    id: 'offensive',
    label: 'Offensive',
    icon: Target04,
    sub: [
      { id: 'recon', label: 'Recon' },
      { id: 'threats', label: 'Threat Model' },
      { id: 'agent', label: 'Agent' },
    ],
  },
  {
    id: 'governance',
    label: 'Governance',
    icon: ShieldTick,
    sub: [
      { id: 'evidence', label: 'Evidence' },
      { id: 'reviews', label: 'Awaiting Review' },
      { id: 'quality', label: 'Code Quality' },
    ],
  },
  {
    id: 'settings',
    label: 'Settings',
    icon: Sliders04,
  },
]

function getGroupForTab(tab: Tab): TabGroupDefinition {
  for (const group of TAB_GROUPS) {
    if (group.id === tab && !group.sub) return group
    if (group.sub?.some((s) => s.id === tab)) return group
  }
  return TAB_GROUPS[0]
}

export function EngagementDetail() {
  const { id = '' } = useParams()
  const { hash } = useLocation()
  const focusedFindingId = hash.startsWith('#finding-') ? decodeURIComponent(hash.slice(9)) : ''
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [job, setJob] = useState<ScanJob | null>(null)
  const [tab, setTab] = useState<Tab>('overview')
  const [findingsFilter, setFindingsFilter] = useState<Severity | 'all'>('all')

  // --- Data fetches via useFetch ---
  const { data: engData, loading: engLoading, error: engErr, refetch: refetchEng } = useFetch<Engagement | null>(
    async () => {
      try {
        return await api.getEngagement(id)
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) return null
        throw e
      }
    },
    { deps: [id] },
  )
  const [eng, setEng] = useState<Engagement | null | undefined>(undefined)
  useEffect(() => {
    if (engLoading) setEng(undefined)
    else setEng(engData)
  }, [engData, engLoading])

  const { data: fetchedFindings, refetch: refetchFindings } = useFetch<Finding[]>(
    () => api.findings(id).catch(() => [] as Finding[]),
    { deps: [id] },
  )
  useEffect(() => {
    if (fetchedFindings !== null) setFindings(fetchedFindings)
  }, [fetchedFindings])

  const { data: fetchedScan, refetch: refetchScan } = useFetch<ScanResult | null>(
    () => api.latestScan(id).catch(() => null),
    { deps: [id] },
  )
  useEffect(() => {
    if (fetchedScan) {
      setScan(fetchedScan)
      if (fetchedScan.scanMode === 'licenses') setFindings(fetchedScan.findings)
    }
  }, [fetchedScan])

  const { data: importedSBOM, refetch: refetchSBOM } = useFetch<ImportedSBOMMetadata | null>(
    () => api.importedSBOM(id).catch(() => null),
    { deps: [id] },
  )

  useEffect(() => {
    if (focusedFindingId) setTab('findings')
  }, [focusedFindingId])

  function reloadFindings() {
    refetchFindings()
  }

  // refreshAll re-pulls the latest scan + findings (after an SBOM import or VEX apply).
  function refreshAll() {
    refetchEng()
    refetchScan()
    refetchFindings()
    refetchSBOM()
  }

  // applyFinding replaces a single row in place with the server's updated finding.
  function applyFinding(updated: Finding) {
    setFindings((cur) => (cur ? cur.map((f) => (f.id === updated.id ? updated : f)) : cur))
  }

  // selectSeverity wires the Overview's distribution + attention cards to the
  // Findings table (the decision surface).
  function selectSeverity(sev: Severity | 'all') {
    setFindingsFilter(sev)
    setTab('findings')
  }

  if (engErr)
    return (
      <EmptyState
        icon={ShieldZap}
        title="Couldn't load this engagement"
        hint={engErr}
        action={
          <Link to="/engagements">
            <Button variant="secondary">
              <ArrowLeft className="size-4" /> Back to engagements
            </Button>
          </Link>
        }
      />
    )
  if (eng === undefined) return <Spinner label="Loading engagement…" />
  if (eng === null) {
    return (
      <EmptyState
        icon={ShieldZap}
        title="Engagement not found"
        hint="It may have been removed."
        action={
          <Link to="/engagements">
            <Button variant="secondary">
              <ArrowLeft className="size-4" /> Back to engagements
            </Button>
          </Link>
        }
      />
    )
  }

  const counts = {
    findings: findings?.length ?? 0,
    components: scan?.components.length ?? 0,
    vulns: scan ? countVulnerabilityFindings(scan.vulnerabilities, packageLocationMap(scan.components)) : 0,
    licenses: scan?.licenses.length ?? 0,
  }

  const activeGroup = getGroupForTab(tab)

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-5">
      {/* Top Bar: Breadcrumb navigation on left + 3 Action Buttons on right */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-xs text-tertiary">
          <Link
            to="/engagements"
            className="inline-flex items-center gap-1 font-medium text-secondary transition-colors hover:text-primary"
          >
            <ArrowLeft className="size-3.5" /> Engagements
          </Link>
          <ChevronRight className="size-3 text-quaternary" />
          <span className="truncate font-semibold text-primary" aria-current="page">
            {eng.name}
          </span>
        </nav>

        {/* 3 action buttons moved up to be on the same horizontal row with breadcrumbs */}
        <ExportButtons engagementId={eng.id} scan={scan} onChanged={refreshAll} />
      </div>

      {/* Single Unified Hero Card for Engagement Details and Scan Console */}
      <div className="bg-hero rounded-2xl border border-secondary p-5 sm:p-6 shadow-xs space-y-4">
        <ScanPanel
          eng={eng}
          importedSBOM={importedSBOM}
          onImportedSBOMChanged={refreshAll}
          job={job}
          setJob={setJob}
          onScanned={(r) => {
            setScan(r)
            if (r.scanMode === 'licenses') {
              setFindings(r.findings)
              setTab('licenses')
            } else {
              if (r.scanMode === 'vulnerabilities') setTab('vulns')
              reloadFindings()
            }
          }}
        />
      </div>

      {/* 2-Tier Navigation Section */}
      <div className="space-y-2.5">
        {/* Level 1: Main Tabs */}
        <div
          role="tablist"
          aria-label="Engagement Views"
          className="flex gap-2 overflow-x-auto border-b border-secondary"
        >
          {TAB_GROUPS.map((group) => {
            const isGroupActive = activeGroup.id === group.id
            const Icon = group.icon

            // Count for top-level badge if applicable
            let groupCount: number | undefined
            if (group.id === 'findings') groupCount = counts.findings
            else if (group.id === 'supply-chain') groupCount = counts.components + counts.vulns + counts.licenses

            return (
              <button
                key={group.id}
                role="tab"
                id={`tab-${group.id}`}
                aria-selected={isGroupActive}
                aria-controls={`panel-${isGroupActive ? tab : (group.sub ? group.sub[0].id : group.id)}`}
                onClick={() => {
                  if (group.sub && group.sub.length > 0) {
                    if (activeGroup.id !== group.id) {
                      setTab(group.sub[0].id)
                    }
                  } else {
                    setTab(group.id as Tab)
                  }
                }}
                className={cn(
                  '-mb-px inline-flex items-center gap-2 whitespace-nowrap border-b-2 px-3.5 py-2.5 text-sm font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid',
                  isGroupActive
                    ? 'border-brand-solid text-brand-secondary'
                    : 'border-transparent text-tertiary hover:border-secondary hover:text-primary',
                )}
              >
                <Icon className={cn('size-4', isGroupActive ? 'text-brand-secondary' : 'text-quaternary')} />
                <span>{group.label}</span>
                {groupCount !== undefined && groupCount > 0 && (
                  <span
                    className={cn(
                      'rounded-full px-1.5 py-0.5 text-xs font-bold tabular-nums',
                      isGroupActive ? 'bg-brand-primary text-brand-secondary' : 'bg-secondary text-tertiary',
                    )}
                  >
                    {groupCount}
                  </span>
                )}
              </button>
            )
          })}
        </div>

        {/* Level 2: Sub-Navigation Pills (fixed height container to prevent layout shifts) */}
        {activeGroup.sub && activeGroup.sub.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 border-b border-secondary pb-2.5 pt-0.5">
            {activeGroup.sub.map((sub) => {
              const isSubActive = tab === sub.id
              const count = sub.countKey ? counts[sub.countKey] : undefined
              return (
                <button
                  key={sub.id}
                  onClick={() => setTab(sub.id)}
                  className={cn(
                    'inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid',
                    isSubActive
                      ? 'bg-brand-solid text-white shadow-xs'
                      : 'text-secondary hover:bg-secondary hover:text-primary',
                  )}
                >
                  <span>{sub.label}</span>
                  {count !== undefined && count > 0 && (
                    <span
                      className={cn(
                        'rounded-full px-1.5 py-0.2 text-[10px] font-bold tabular-nums',
                        isSubActive ? 'bg-primary text-brand-secondary' : 'bg-secondary text-tertiary',
                      )}
                    >
                      {count}
                    </span>
                  )}
                </button>
              )
            })}
          </div>
        )}
      </div>

      {/* Tab Panel Content */}
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${activeGroup.id}`} className="mt-4">
        {tab === 'overview' && (
          <OverviewTab findings={findings} scan={scan} job={job} onSelectSeverity={selectSeverity} onGoTab={setTab} />
        )}
        {tab === 'findings' && (
          <FindingsTab
            findings={findings}
            scan={scan}
            engagementId={id}
            filter={findingsFilter}
            setFilter={setFindingsFilter}
            focusedFindingId={focusedFindingId}
            onUpdated={applyFinding}
            onReload={reloadFindings}
          />
        )}
        {tab === 'sla' && <SLATab engagementId={id} findings={findings} />}
        {tab === 'components' && <ComponentsTab scan={scan} />}
        {tab === 'vulns' && <VulnsTab scan={scan} />}
        {tab === 'graph' && (
          <Suspense fallback={<Spinner label="Loading graph…" />}>
            <DependencyGraphTab scan={scan} />
          </Suspense>
        )}
        {tab === 'licenses' && <LicensesTab scan={scan} />}
        {tab === 'threats' && <ThreatModelTab engagementId={id} />}
        {tab === 'quality' && <CodeQualityTab engagementId={id} />}
        {tab === 'recon' && <ReconTab eng={eng} onGoTab={setTab} />}
        {tab === 'agent' && <AgentTab engagementId={id} />}
        {tab === 'reviews' && <JudgmentReviewTab key={id} engagementId={id} />}
        {tab === 'evidence' && <EvidenceTab key={id} engagementId={id} />}
        {tab === 'settings' && <SettingsTab eng={eng} onUpdated={setEng} />}
      </div>
    </div>
  )
}
