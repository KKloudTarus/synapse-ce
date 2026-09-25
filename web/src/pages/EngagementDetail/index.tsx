import { useState, useEffect, Suspense } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { ArrowLeft, ChevronRight, ShieldZap } from '@untitledui/icons'
import { Button, EmptyState, Spinner } from '../../components/ui'
import type { Severity } from '../../lib/types'
import { OverviewTab } from './OverviewTab'
import { FindingsTab } from './FindingsTab'
import { ScanPanel } from './ScanPanel'
import { ExportButtons } from './ExportButtons'
import { packageLocationMap, countVulnerabilityFindings, VulnsTab } from './VulnsTab'
import { ARCHIVED_REASON, isReadOnly } from './readOnly'
import {
  AgentTab,
  AssessmentComparisonTab,
  ChainRehearsalTab,
  CloudPostureTab,
  CodeQualityTab,
  ComponentsTab,
  CredentialsTab,
  DASTTab,
  DataGovernanceTab,
  DependencyGraphTab,
  DetectionProvenanceTab,
  DetectionsTab,
  EvidenceTab,
  ImportedFindingsTab,
  JudgmentReviewTab,
  LicensesTab,
  PurpleCoverageTab,
  ReconTab,
  RiskStoriesTab,
  SLATab,
  ScanRunsTab,
  SettingsTab,
  ThreatModelTab,
  VulnPostureTab,
  WriteupDraftsTab,
  getGroupForTab,
} from './tabs'

import { EngagementTabNav } from './EngagementTabNav'
import { useEngagementData } from './useEngagementData'
import { useEngagementTab } from './useEngagementTab'
import { AssessmentLifecyclePanel } from './AssessmentLifecyclePanel'
import { VulnerabilityIntelligenceBadge } from '../../components/synapse/VulnerabilityIntelligenceBadge'

// Only one tab renders at a time, so every tab except the two opened first (Overview and
// Findings) is a separate chunk. Statically importing all 27 put every tab in the initial
// bundle, which a user pays for on first paint no matter which tab they open. VulnsTab stays
// static because this module calls its counting helpers to render the tab-bar counts.
export function EngagementDetail() {
  const { id = '', tabSlug } = useParams()
  const location = useLocation()
  const { hash } = location
  const scanStartError = typeof (location.state as { scanStartError?: unknown } | null)?.scanStartError === 'string'
    ? (location.state as { scanStartError: string }).scanStartError
    : undefined
  const focusedFindingId = hash.startsWith('#finding-') ? decodeURIComponent(hash.slice(9)) : ''
  const { tab, setTab } = useEngagementTab(id, tabSlug, hash)
  const [findingsFilter, setFindingsFilter] = useState<Severity | 'all'>('all')

  const {
    eng, setEng, engLoading, engError: engErr,
    findings, setFindings, findingsError, scan, scanError, setScan, job, setJob,
    importedSBOM, uploadedSource, uploadedSourceError,
    applyFinding, reloadFindings, refreshAll, refetchUploadedSource,
  } = useEngagementData(id)

  useEffect(() => {
    if (focusedFindingId) setTab('findings')
  }, [focusedFindingId, setTab])

  const activeGroup = getGroupForTab(tab)

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

      <EngagementTabNav tab={tab} activeGroup={activeGroup} counts={counts} onSelectTab={setTab} />

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
