import { useState, useEffect, lazy, Suspense, type FC } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import {
  ArrowLeft,
  Package,
  Calendar,
  FileCheck01,
  ShieldZap,
  ShieldTick,
  Target04,
  LayoutGrid01,
  Sliders04,
  ChevronRight,
} from '@untitledui/icons'
import { Button, cn, EmptyState, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import { kindLabel } from '../../lib/format'
import type {
  Engagement,
  Finding,
  ImportedSBOMMetadata,
  ScanJob,
  ScanResult,
  Severity,
} from '../../lib/types'
import { StatusPill } from '../Engagements'
import { AgentTab } from '../AgentTab'
import { ThreatModelTab } from './ThreatModelTab'
import { CodeQualityTab } from '../CodeQuality/CodeQualityTab'
import { SLATab } from './SLATab'
import { OverviewTab } from './OverviewTab'
import { FindingsTab } from './FindingsTab'
import { ScanPanel } from './ScanPanel'
import { ExportButtons } from './ExportButtons'
import { packageLocationMap, countVulnerabilityFindings, VulnsTab, fmtWindow } from './VulnsTab'
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
    <div className="mx-auto max-w-[1600px] animate-fade-in">
      {/* Breadcrumb navigation */}
      <nav aria-label="Breadcrumb" className="mb-4 flex items-center gap-2 text-xs text-tertiary">
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

      <Header eng={eng} scan={scan} onChanged={refreshAll} />

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

      {/* 6 Grouped Tabs */}
      <div className="space-y-2">
        {/* Top-Level Tabs */}
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
                    // Switch to first sub-tab of group if not already in this group
                    if (activeGroup.id !== group.id) {
                      setTab(group.sub[0].id)
                    }
                  } else {
                    setTab(group.id as Tab)
                  }
                }}
                className={cn(
                  '-mb-px inline-flex items-center gap-2 whitespace-nowrap border-b-2 px-3.5 py-2.5 text-sm font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
                  isGroupActive
                    ? 'border-brand text-brand-secondary'
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

        {/* Sub-Navigation Pills (if active group has sub-tabs) */}
        {activeGroup.sub && activeGroup.sub.length > 0 && (
          <div className="flex flex-wrap items-center gap-1 border-b border-secondary px-1 pb-2 pt-1">
            {activeGroup.sub.map((sub) => {
              const isSubActive = tab === sub.id
              const count = sub.countKey ? counts[sub.countKey] : undefined
              return (
                <button
                  key={sub.id}
                  onClick={() => setTab(sub.id)}
                  className={cn(
                    'inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors',
                    isSubActive
                      ? 'bg-brand-solid text-white shadow-xs'
                      : 'text-secondary hover:bg-secondary hover:text-primary',
                  )}
                >
                  <span>{sub.label}</span>
                  {count !== undefined && count > 0 && (
                    <span
                      className={cn(
                        'rounded-full px-1.5 py-0.5 text-[10px] font-semibold tabular-nums',
                        isSubActive ? 'bg-white/20 text-white' : 'bg-secondary text-tertiary',
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

      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${activeGroup.id}`} className="mt-5">
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

function Header({ eng, scan, onChanged }: { eng: Engagement; scan: ScanResult | null; onChanged: () => void }) {
  return (
    <div className="mb-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-3xl font-bold tracking-tight text-primary">{eng.name}</h1>
          <StatusPill status={eng.status} />
          <EvidenceBadge engagementId={eng.id} />
        </div>
        <ExportButtons engagementId={eng.id} scan={scan} onChanged={onChanged} />
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-tertiary">
        {eng.client && <span>{eng.client}</span>}
        {eng.businessAssetId ? (
          <Link
            to={`/assets/${encodeURIComponent(eng.businessAssetId)}`}
            className="flex items-center gap-1.5 text-brand-secondary hover:underline"
          >
            <Package className="size-3.5" /> Asset: {eng.businessAssetId}
          </Link>
        ) : (
          <span className="flex items-center gap-1.5">
            <Package className="size-3.5 text-quaternary" /> Unassigned Asset
          </span>
        )}
        <span className="flex items-center gap-1.5">
          <Target04 className="size-3.5" /> {eng.inScope.length} in scope
        </span>
        {eng.inScope.map((t, i) => {
          const displayValue = t.kind === 'repo' && t.value.includes('/')
            ? t.value.split('/').slice(-1)[0].replace(/\.git$/, '')
            : t.value
          return (
            <span
              key={i}
              className="inline-flex items-center gap-1.5 rounded-md border border-secondary bg-secondary py-0.5 pl-1.5 pr-2 text-xs text-tertiary"
              title={t.value}
            >
              <span className="rounded bg-brand-primary px-1 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-brand-secondary">
                {kindLabel(t.kind)}
              </span>
              <span className="font-mono text-primary">{displayValue}</span>
            </span>
          )
        })}
        {(eng.authorizedFrom || eng.authorizedTo) && (
          <span className="flex items-center gap-1.5 font-mono">
            <Calendar className="size-3.5" /> {fmtWindow(eng.authorizedFrom, eng.authorizedTo)}
          </span>
        )}
      </div>
    </div>
  )
}

// EvidenceBadge shows the tamper-evident evidence-chain status and, when
// the chain head is signed, its origin attestation (integrity + origin).
function EvidenceBadge({ engagementId }: { engagementId: string }) {
  const { data: ev } = useFetch(
    () => api.evidence(engagementId).then((e) =>
      e && e.verified > 0 ? { intact: e.intact, verified: e.verified, keyId: e.attestation?.key_id } : null,
    ),
    { deps: [engagementId] },
  )
  if (!ev) return null
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={cn(
          'inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset',
          ev.intact ? 'bg-accent/10 text-accent ring-accent/25' : 'bg-critical/10 text-critical ring-critical/25',
        )}
        title={`${ev.verified} evidence link(s) in the hash chain`}
      >
        <ShieldTick className="size-3.5" />
        {ev.intact ? 'Evidence verified' : 'Evidence tampered'}
      </span>
      {ev.intact && ev.keyId && (
        <span
          className="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-0.5 font-mono text-xs text-tertiary ring-1 ring-inset ring-secondary"
          title={`Chain head signed (ed25519) by key ${ev.keyId} – proves origin, not just integrity`}
        >
          <FileCheck01 className="size-3.5 text-quaternary" />
          {ev.keyId}
        </span>
      )}
    </span>
  )
}
