import { useState, useEffect, useCallback, useRef, lazy, Suspense, type ComponentType, type FC } from 'react'
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
  SwitchHorizontal01,
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
import { OverviewTab } from './OverviewTab'
import { FindingsTab } from './FindingsTab'
import { ScanPanel } from './ScanPanel'
import { ExportButtons } from './ExportButtons'
import { packageLocationMap, countVulnerabilityFindings, VulnsTab } from './VulnsTab'
import { ARCHIVED_REASON, isReadOnly } from './readOnly'

import { AssessmentLifecyclePanel } from './AssessmentLifecyclePanel'
import { VulnerabilityIntelligenceBadge } from '../../components/synapse/VulnerabilityIntelligenceBadge'

// Only one tab renders at a time, so every tab except the two opened first (Overview and
// Findings) is a separate chunk. Statically importing all 27 put every tab in the initial
// bundle, which a user pays for on first paint no matter which tab they open. VulnsTab stays
// static because this module calls its counting helpers to render the tab-bar counts.
/**
 * Wraps a tab's dynamic import so a failed chunk fetch can recover.
 *
 * After a deploy rotates the hashed chunk filenames, an already-open session's import 404s.
 * React.lazy caches that rejection permanently, so the error boundary's Retry remounts into the
 * same rejected payload forever. Retry the import once (it covers a transient network failure),
 * then reload the page once, which fetches the current index and its chunk names. The one-shot
 * flag stops a genuinely missing chunk from turning into a reload loop, and it is cleared on the
 * next successful load.
 */
const CHUNK_RELOAD_FLAG = 'synapse.engagement-chunk-reloaded'

function readReloadFlag(): boolean {
  try {
    return sessionStorage.getItem(CHUNK_RELOAD_FLAG) === '1'
  } catch {
    // Private mode or blocked storage: treat as "not yet reloaded" and rely on the single attempt.
    return false
  }
}

function writeReloadFlag(value: boolean) {
  try {
    if (value) sessionStorage.setItem(CHUNK_RELOAD_FLAG, '1')
    else sessionStorage.removeItem(CHUNK_RELOAD_FLAG)
  } catch {
    // Storage is unavailable; the reload still happens, it just is not deduplicated.
  }
}

function lazyTab<T extends ComponentType<any>>(load: () => Promise<{ default: T }>) {
  return lazy(async () => {
    try {
      const loaded = await load()
      writeReloadFlag(false)
      return loaded
    } catch (first) {
      try {
        const retried = await load()
        writeReloadFlag(false)
        return retried
      } catch (second) {
        if (!readReloadFlag()) {
          writeReloadFlag(true)
          window.location.reload()
        }
        throw second instanceof Error ? second : first
      }
    }
  })
}

// Lazy-loaded so React Flow stays out of the initial bundle (only the Graph tab needs it).
const DependencyGraphTab = lazyTab(() => import('../DependencyGraph').then((m) => ({ default: m.DependencyGraphTab })))
const AgentTab = lazyTab(() => import('../AgentTab').then((m) => ({ default: m.AgentTab })))
const ThreatModelTab = lazyTab(() => import('./ThreatModelTab').then((m) => ({ default: m.ThreatModelTab })))
const CodeQualityTab = lazyTab(() => import('../CodeQuality/CodeQualityTab').then((m) => ({ default: m.CodeQualityTab })))
const SLATab = lazyTab(() => import('./SLATab').then((m) => ({ default: m.SLATab })))
const LicensesTab = lazyTab(() => import('./LicensesTab').then((m) => ({ default: m.LicensesTab })))
const ComponentsTab = lazyTab(() => import('./ComponentsTab').then((m) => ({ default: m.ComponentsTab })))
const ReconTab = lazyTab(() => import('./ReconTab').then((m) => ({ default: m.ReconTab })))
const ScanRunsTab = lazyTab(() => import('./ScanRunsTab').then((m) => ({ default: m.ScanRunsTab })))
const PurpleCoverageTab = lazyTab(() => import('./PurpleCoverageTab').then((m) => ({ default: m.PurpleCoverageTab })))
const ChainRehearsalTab = lazyTab(() => import('./ChainRehearsalTab').then((m) => ({ default: m.ChainRehearsalTab })))
const RiskStoriesTab = lazyTab(() => import('./RiskStoriesTab').then((m) => ({ default: m.RiskStoriesTab })))
const VulnPostureTab = lazyTab(() => import('./VulnPostureTab').then((m) => ({ default: m.VulnPostureTab })))
const CredentialsTab = lazyTab(() => import('./CredentialsTab').then((m) => ({ default: m.CredentialsTab })))
const DetectionsTab = lazyTab(() => import('./DetectionsTab').then((m) => ({ default: m.DetectionsTab })))
const ImportedFindingsTab = lazyTab(() => import('./ImportedFindingsTab').then((m) => ({ default: m.ImportedFindingsTab })))
const DataGovernanceTab = lazyTab(() => import('./DataGovernanceTab').then((m) => ({ default: m.DataGovernanceTab })))
const WriteupDraftsTab = lazyTab(() => import('./WriteupDraftsTab').then((m) => ({ default: m.WriteupDraftsTab })))
const CloudPostureTab = lazyTab(() => import('./CloudPostureTab').then((m) => ({ default: m.CloudPostureTab })))
const DASTTab = lazyTab(() => import('./DASTTab').then((m) => ({ default: m.DASTTab })))
const DetectionProvenanceTab = lazyTab(() => import('./DetectionProvenanceTab').then((m) => ({ default: m.DetectionProvenanceTab })))
const EvidenceTab = lazyTab(() => import('./EvidenceTab').then((m) => ({ default: m.EvidenceTab })))
const SettingsTab = lazyTab(() => import('./SettingsTab').then((m) => ({ default: m.SettingsTab })))
const JudgmentReviewTab = lazyTab(() => import('./ReviewsTab').then((m) => ({ default: m.JudgmentReviewTab })))
const AssessmentComparisonTab = lazyTab(() => import('./AssessmentComparisonTab').then((m) => ({ default: m.AssessmentComparisonTab })))

export type Tab =
  | 'overview'
  | 'findings'
  | 'imported'

  | 'comparison'
  | 'sla'
  | 'risk-stories'
  | 'vuln-posture'
  | 'components'
  | 'vulns'
  | 'licenses'
  | 'graph'
  | 'scanruns'
  | 'credentials'
  | 'quality'
  | 'threats'
  | 'recon'
  | 'purple'
  | 'rehearsal'
  | 'agent'
  | 'cspm'
  | 'dast'
  | 'detections'
  | 'detection-provenance'
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
    id: 'comparison',
    label: 'Comparison',
    icon: SwitchHorizontal01,
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
      { id: 'rehearsal', label: 'Chain Rehearsal' },
      { id: 'agent', label: 'Agent' },
      { id: 'cspm', label: 'Cloud Posture' },
      { id: 'dast', label: 'DAST' },
    ],
  },
  {
    id: 'runtime',
    label: 'Runtime',
    icon: Activity,
    sub: [
      { id: 'detections', label: 'Detections' },
      { id: 'detection-provenance', label: 'Provenance' },
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
      { id: 'credentials', label: 'Credentials' },
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

  // Findings are the engagement's core record, so a failure here is surfaced. Catching it into an
  // empty array rendered a findings-service outage as "this engagement has no findings", with a
  // zero on the tab bar, which on a security engagement is the most consequential false all-clear
  // the screen can produce.
  const { data: fetchedFindings, error: findingsError, refetch: refetchFindings } = useFetch<Finding[]>(
    () => api.findings(id),
    { deps: [id] },
  )
  useEffect(() => {
    if (fetchedFindings !== null) setFindings(fetchedFindings)
  }, [fetchedFindings])

  // An engagement with no scan yet answers 404, which is the "run a scan" state and stays silent.
  // Any other failure is an outage and must not read as "no scan has been run".
  const { data: fetchedScan, error: scanError, refetch: refetchScan } = useFetch<ScanResult | null>(
    () => api.latestScan(id).catch((error) => {
      if (error instanceof ApiError && error.status === 404) return null
      throw error
    }),
    { deps: [id] },
  )
  useEffect(() => {
    if (fetchedScan) {
      setScan(fetchedScan)
    }
  }, [fetchedScan])

  const { data: importedSBOM, refetch: refetchSBOM } = useFetch<ImportedSBOMMetadata | null>(
    () => api.importedSBOM(id).catch((error) => {
      // No imported SBOM is the ordinary case and answers 404. Anything else is an outage, and the
      // import panel says so rather than showing the engagement as having no SBOM.
      if (error instanceof ApiError && error.status === 404) return null
      throw error
    }),
    { deps: [id] },
  )
  const { data: uploadedSource, error: uploadedSourceError, refetch: refetchUploadedSource } = useFetch<UploadedSourcePackage | null>(
    () => api.uploadedSource(id).catch((error) => {
      if (error instanceof ApiError && error.status === 404) return null
      throw error
    }),
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
  // `undefined` means "not known". The badge already hides a zero, so this changes nothing on
  // screen today; it keeps the distinction in the data so a future badge that does render zero
  // cannot start claiming a clean engagement while the request behind the number is failing.
  const counts: Record<'findings' | 'components' | 'vulns' | 'licenses', number | undefined> = {
    findings: findingsError ? undefined : findings?.length,
    components: scanError ? undefined : scan?.components.length,
    vulns: scanError ? undefined : scan ? countVulnerabilityFindings(scan.vulnerabilities, packageLocationMap(scan.components)) : undefined,
    licenses: scanError ? undefined : scan?.licenses.length,
  }
  const viFindingCount = findings?.filter((finding) => Boolean(finding.advisoryId)).length ?? 0

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
        <div className="flex flex-wrap items-center justify-end gap-2">
          {viFindingCount > 0 && <VulnerabilityIntelligenceBadge count={viFindingCount} />}
          <ExportButtons engagementId={eng.id} scan={scan} onChanged={refreshAll} />
        </div>
      </div>

      {/* Keep the Engagement identity first; lifecycle is supporting context below the scan console. */}
      <section aria-label="Engagement summary" className="bg-hero rounded-2xl border border-secondary p-5 sm:p-6 shadow-xs space-y-4">
        <ScanPanel
          eng={eng}
          importedSBOM={importedSBOM}
          uploadedSource={uploadedSource}
          uploadedSourceError={uploadedSourceError}
          onRetryUploadedSource={refetchUploadedSource}
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
        <AssessmentLifecyclePanel assessmentId={id} engagementStatus={eng.status} />
      </section>

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
            else if (group.id === 'supply-chain') {
              // Summing a partly-unknown set would present a smaller total as if it were complete.
              const parts = [counts.components, counts.vulns, counts.licenses]
              groupCount = parts.some((part) => part === undefined)
                ? undefined
                : parts.reduce((total, part) => total! + part!, 0)
            }

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
        <Suspense fallback={<Spinner label="Loading tab…" />}>
        {tab === 'overview' && (
          <OverviewTab findings={findings} findingsError={findingsError} scanError={scanError} scan={scan} job={job} onSelectSeverity={selectSeverity} onGoTab={setTab} />
        )}
        {tab === 'findings' && (
          <FindingsTab
            findings={findings}
            findingsError={findingsError}
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

        {tab === 'comparison' && <AssessmentComparisonTab key={id} assessmentId={id} />}
        {tab === 'components' && <ComponentsTab scan={scan} />}
        {tab === 'vulns' && <VulnsTab scan={scan} />}
        {tab === 'graph' && <DependencyGraphTab scan={scan} />}
        {tab === 'licenses' && <LicensesTab scan={scan} />}
        {tab === 'scanruns' && <ScanRunsTab key={id} engagementId={id} />}
        {tab === 'threats' && <ThreatModelTab engagementId={id} />}
        {tab === 'quality' && <CodeQualityTab engagementId={id} />}
        {tab === 'recon' && <ReconTab eng={eng} onGoTab={setTab} />}
        {tab === 'purple' && <PurpleCoverageTab key={id} engagementId={id} />}
        {tab === 'rehearsal' && <ChainRehearsalTab key={id} engagementId={id} />}
        {tab === 'agent' && <AgentTab engagementId={id} />}
        {tab === 'dast' && <DASTTab key={id} engagementId={id} />}
        {tab === 'detections' && <DetectionsTab key={id} engagementId={id} />}
        {tab === 'detection-provenance' && <DetectionProvenanceTab key={id} engagementId={id} />}
        {tab === 'imported' && <ImportedFindingsTab key={id} engagementId={id} />}
        {tab === 'data-governance' && <DataGovernanceTab key={id} engagementId={id} />}
        {tab === 'writeup-drafts' && <WriteupDraftsTab key={id} engagementId={id} />}
        {tab === 'cspm' && <CloudPostureTab key={id} engagementId={id} />}
        {tab === 'reviews' && <JudgmentReviewTab key={id} engagementId={id} />}
        {tab === 'evidence' && <EvidenceTab key={id} engagementId={id} />}
        {tab === 'credentials' && <CredentialsTab key={id} engagementId={id} />}
        {tab === 'settings' && <SettingsTab eng={eng} onUpdated={setEng} />}
        </Suspense>
      </div>
    </div>
  )
}
