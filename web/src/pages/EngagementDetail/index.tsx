import { useState, useEffect, useCallback, useRef, lazy, Suspense, type FC } from 'react'
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  Activity,
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
  UploadedSourcePackage,
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
import { ScanRunsTab } from './ScanRunsTab'
import { PurpleCoverageTab } from './PurpleCoverageTab'
import { RiskStoriesTab } from './RiskStoriesTab'
import { VulnPostureTab } from './VulnPostureTab'
import { DetectionsTab } from './DetectionsTab'
import { ImportedFindingsTab } from './ImportedFindingsTab'
import { DataGovernanceTab } from './DataGovernanceTab'
import { WriteupDraftsTab } from './WriteupDraftsTab'
import { EvidenceTab } from './EvidenceTab'
import { SettingsTab } from './SettingsTab'
import { JudgmentReviewTab } from './ReviewsTab'
import { ARCHIVED_REASON, isReadOnly } from './readOnly'

// Lazy-loaded so React Flow stays out of the initial bundle (only the Graph tab needs it).
const DependencyGraphTab = lazy(() => import('../DependencyGraph').then((m) => ({ default: m.DependencyGraphTab })))

export type Tab =
  | 'overview'
  | 'findings'
  | 'imported'
  | 'sla'
  | 'risk-stories'
  | 'vuln-posture'
  | 'components'
  | 'vulns'
  | 'licenses'
  | 'graph'
  | 'scanruns'
  | 'quality'
  | 'threats'
  | 'recon'
  | 'purple'
  | 'agent'
  | 'detections'
  | 'reviews'
  | 'evidence'
  | 'data-governance'
  | 'writeup-drafts'
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
      { id: 'imported', label: 'Imported' },
      { id: 'risk-stories', label: 'Risk Stories' },
      { id: 'vuln-posture', label: 'Vuln Posture' },
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
      { id: 'scanruns', label: 'Scan Runs' },
    ],
  },
  {
    id: 'offensive',
    label: 'Offensive',
    icon: Target04,
    sub: [
      { id: 'recon', label: 'Recon' },
      { id: 'threats', label: 'Threat Model' },
      { id: 'purple', label: 'Purple Coverage' },
      { id: 'agent', label: 'Agent' },
    ],
  },
  {
    id: 'runtime',
    label: 'Runtime',
    icon: Activity,
    sub: [{ id: 'detections', label: 'Detections' }],
  },
  {
    id: 'governance',
    label: 'Governance',
    icon: ShieldTick,
    sub: [
      { id: 'evidence', label: 'Evidence' },
      { id: 'reviews', label: 'Awaiting Review' },
      { id: 'quality', label: 'Code Quality' },
      { id: 'data-governance', label: 'Data governance' },
      { id: 'writeup-drafts', label: 'Write-up Drafts' },
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

const ALL_TABS: Tab[] = TAB_GROUPS.flatMap((g) => (g.sub ? g.sub.map((s) => s.id) : [g.id as Tab]))

function isTab(value: string | undefined): value is Tab {
  return Boolean(value) && ALL_TABS.includes(value as Tab)
}

export function EngagementDetail() {
  const { id = '', tabSlug } = useParams()
  const location = useLocation()
  const { hash } = location
  const navigate = useNavigate()
  const scanStartError = typeof (location.state as { scanStartError?: unknown } | null)?.scanStartError === 'string'
    ? (location.state as { scanStartError: string }).scanStartError
    : undefined
  const focusedFindingId = hash.startsWith('#finding-') ? decodeURIComponent(hash.slice(9)) : ''
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [job, setJob] = useState<ScanJob | null>(null)
  // The `:tabSlug` route segment is the source of truth for the active tab, so
  // /engagements/:id/<tab> deep links land on the right tab.
  const [tab, setTabState] = useState<Tab>(() => (isTab(tabSlug) ? tabSlug : 'overview'))
  const [findingsFilter, setFindingsFilter] = useState<Severity | 'all'>('all')
  const tablistRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (isTab(tabSlug)) setTabState(tabSlug)
    else if (!tabSlug) setTabState('overview')
  }, [tabSlug])

  const setTab = useCallback(
    (next: Tab) => {
      setTabState(next)
      const base = `/engagements/${encodeURIComponent(id)}`
      // Keep the hash: a #finding-<id> deep link switches to the Findings tab and
      // the hash is what FindingsTab scrolls to.
      navigate(`${next === 'overview' ? base : `${base}/${next}`}${hash}`, { replace: true })
    },
    [hash, id, navigate],
  )

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
  // Local patch state so SettingsTab can update the engagement in place. It is
  // deliberately never reset on refetch: mirroring `engLoading` into `undefined`
  // unmounted the entire view (header, scan panel, active tab and its state)
  // behind a full-page spinner on every VEX apply or SBOM import.
  const [engPatch, setEngPatch] = useState<Engagement | null | undefined>(undefined)
  useEffect(() => {
    // A different engagement id invalidates any patch from the previous one.
    setEngPatch(undefined)
  }, [id])
  const eng = engPatch !== undefined ? engPatch : engData
  const setEng = setEngPatch

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
  const { data: uploadedSource } = useFetch<UploadedSourcePackage | null>(
    () => api.uploadedSource(id).catch(() => null),
    { deps: [id] },
  )

  useEffect(() => {
    if (focusedFindingId) setTab('findings')
  }, [focusedFindingId, setTab])

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

  const activeGroup = getGroupForTab(tab)

  // selectSeverity wires the Overview's distribution + attention cards to the
  // Findings table (the decision surface).
  function selectSeverity(sev: Severity | 'all') {
    setFindingsFilter(sev)
    setTab('findings')
  }

  function selectGroup(group: TabGroupDefinition) {
    if (group.sub && group.sub.length > 0) {
      if (activeGroup.id !== group.id) setTab(group.sub[0].id)
      return
    }
    setTab(group.id as Tab)
  }

  // WAI-ARIA tabs pattern: Left/Right move between tabs, Home/End jump to the
  // ends, and the newly selected tab takes focus.
  function onTablistKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    const keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End']
    if (!keys.includes(event.key)) return
    const current = TAB_GROUPS.findIndex((g) => g.id === activeGroup.id)
    if (current < 0) return
    event.preventDefault()
    const last = TAB_GROUPS.length - 1
    const nextIndex =
      event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? last
          : event.key === 'ArrowLeft'
            ? (current - 1 + TAB_GROUPS.length) % TAB_GROUPS.length
            : (current + 1) % TAB_GROUPS.length
    const target = TAB_GROUPS[nextIndex]
    selectGroup(target)
    tablistRef.current?.querySelector<HTMLButtonElement>(`#tab-${target.id}`)?.focus()
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
  // Spinner only on the first load. During a refetch `eng` still holds the
  // previous engagement, so the view stays mounted.
  if (eng == null && engLoading) return <Spinner label="Loading engagement…" />
  if (eng == null) {
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

  const archived = isReadOnly(eng)
  const counts = {
    findings: findings?.length ?? 0,
    components: scan?.components.length ?? 0,
    vulns: scan ? countVulnerabilityFindings(scan.vulnerabilities, packageLocationMap(scan.components)) : 0,
    licenses: scan?.licenses.length ?? 0,
  }

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
          uploadedSource={uploadedSource}
          initialError={scanStartError}
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

      {/* 2-Tier Navigation Section. Sticky so a tab switch does not leave the
          reader hunting for the content below a tall hero. */}
      <div className="sticky top-0 z-20 -mx-4 space-y-2.5 bg-secondary-subtle px-4 pt-2 sm:-mx-6 sm:px-6 xl:-mx-8 xl:px-8">
        {/* Level 1: Main Tabs */}
        <div
          ref={tablistRef}
          role="tablist"
          aria-label="Engagement Views"
          onKeyDown={onTablistKeyDown}
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
                aria-controls="engagement-tabpanel"
                // Roving tabindex: one stop for the whole tablist, arrows move within it.
                tabIndex={isGroupActive ? 0 : -1}
                onClick={() => selectGroup(group)}
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
                      ? 'bg-brand-solid text-primary_on-brand shadow-xs'
                      : 'text-secondary hover:bg-secondary hover:text-primary',
                  )}
                >
                  <span>{sub.label}</span>
                  {count !== undefined && count > 0 && (
                    <span
                      className={cn(
                        'rounded-full px-1.5 py-0.5 text-[10px] font-semibold tabular-nums',
                        isSubActive ? 'bg-primary/20 text-primary_on-brand' : 'bg-secondary text-tertiary',
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

      {/* A single panel holds whichever tab is active, so all tabs share its id. */}
      <div role="tabpanel" id="engagement-tabpanel" aria-labelledby={`tab-${activeGroup.id}`} className="mt-5">
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
            readOnly={archived}
            readOnlyReason={archived ? ARCHIVED_REASON : undefined}
          />
        )}
        {tab === 'sla' && <SLATab key={id} engagementId={id} findings={findings} />}
        {tab === 'risk-stories' && <RiskStoriesTab key={id} engagementId={id} />}
        {tab === 'vuln-posture' && <VulnPostureTab key={id} engagementId={id} />}
        {tab === 'components' && <ComponentsTab scan={scan} />}
        {tab === 'vulns' && <VulnsTab scan={scan} />}
        {tab === 'graph' && (
          <Suspense fallback={<Spinner label="Loading graph…" />}>
            <DependencyGraphTab scan={scan} />
          </Suspense>
        )}
        {tab === 'licenses' && <LicensesTab scan={scan} />}
        {tab === 'scanruns' && <ScanRunsTab key={id} engagementId={id} />}
        {tab === 'threats' && <ThreatModelTab engagementId={id} />}
        {tab === 'quality' && <CodeQualityTab engagementId={id} />}
        {tab === 'recon' && <ReconTab eng={eng} onGoTab={setTab} />}
        {tab === 'purple' && <PurpleCoverageTab key={id} engagementId={id} eng={eng} />}
        {tab === 'agent' && <AgentTab engagementId={id} />}
        {tab === 'detections' && <DetectionsTab key={id} engagementId={id} />}
        {tab === 'imported' && <ImportedFindingsTab key={id} engagementId={id} />}
        {tab === 'data-governance' && <DataGovernanceTab key={id} engagementId={id} />}
        {tab === 'writeup-drafts' && <WriteupDraftsTab key={id} engagementId={id} />}
        {tab === 'reviews' && <JudgmentReviewTab key={id} engagementId={id} />}
        {tab === 'evidence' && <EvidenceTab key={id} engagementId={id} />}
        {tab === 'settings' && <SettingsTab eng={eng} onUpdated={setEng} />}
      </div>
    </div>
  )
}
