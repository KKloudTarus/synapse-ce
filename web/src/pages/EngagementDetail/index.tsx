import { ArrowLeft, Boxes, CalendarClock, FileSignature, ShieldAlert, ShieldCheck, Target } from 'lucide-react'
import { lazy, Suspense, useEffect, useState } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { Button, cn, EmptyState, Select, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import { kindLabel } from '../../lib/format'
import type {
  BusinessAsset,
  Engagement,
  Finding,
  ImportedSBOMMetadata,
  ScanJob,
  ScanResult,
  Severity,
} from '../../lib/types'
import { StatusPill } from '../Engagements'
import { AgentTab } from '../AgentTab'
import { ThreatModelTab } from '../ThreatModelTab'
import { CodeQualityTab } from '../CodeQualityTab'
import { SLATab } from '../SLATab'
import { TabBar, OverviewTab } from './OverviewTab'
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

export type Tab = 'overview' | 'findings' | 'sla' | 'components' | 'vulns' | 'licenses' | 'graph' | 'quality' | 'threats' | 'recon' | 'agent' | 'reviews' | 'evidence' | 'settings'


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
        icon={ShieldAlert}
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
        icon={ShieldAlert}
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

  return (
    <div className="mx-auto max-w-6xl animate-fade-in">
      <Link
        to="/engagements"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-mutedfg transition-colors hover:text-foreground"
      >
        <ArrowLeft className="size-4" /> Engagements
      </Link>

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

      <TabBar
        tab={tab}
        setTab={setTab}
        counts={{
          findings: findings?.length ?? 0,
          components: scan?.components.length ?? 0,
          vulns: scan ? countVulnerabilityFindings(scan.vulnerabilities, packageLocationMap(scan.components)) : 0,
          licenses: scan?.licenses.length ?? 0,
        }}
      />

      <div className="mt-5">
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
          <h1 className="text-3xl font-bold tracking-tight">{eng.name}</h1>
          <StatusPill status={eng.status} />
          <EvidenceBadge engagementId={eng.id} />
        </div>
        <ExportButtons engagementId={eng.id} scan={scan} onChanged={onChanged} />
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-mutedfg">
        {eng.client && <span>{eng.client}</span>}
        {eng.businessAssetId ? <Link to={`/assets/${encodeURIComponent(eng.businessAssetId)}`} className="flex items-center gap-1.5 text-branddim hover:underline"><Boxes className="size-3.5" />Asset</Link> : <span className="flex items-center gap-1.5"><Boxes className="size-3.5" />Unassigned</span>}
        <span className="flex items-center gap-1.5">
          <Target className="size-3.5" /> {eng.inScope.length} in scope
        </span>
        {(eng.authorizedFrom || eng.authorizedTo) && (
          <span className="flex items-center gap-1.5">
            <CalendarClock className="size-3.5" /> {fmtWindow(eng.authorizedFrom, eng.authorizedTo)}
          </span>
        )}
      </div>
      <AssetAssignment engagement={eng} onChanged={onChanged} />
      {eng.inScope.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {eng.inScope.map((t, i) => (
            <span
              key={i}
              className="inline-flex items-center gap-2 rounded-md border border-border bg-elevated py-1 pl-1.5 pr-2.5 text-xs text-mutedfg"
            >
              <span className="rounded bg-brand/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-branddim">
                {kindLabel(t.kind)}
              </span>
              <span className="font-mono text-foreground">{t.value}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

function AssetAssignment({ engagement, onChanged }: { engagement: Engagement; onChanged: () => void }) {
  const { data: assets } = useFetch(
    () => api.listBusinessAssets('limit=200').then((r) => r.items).catch(() => [] as BusinessAsset[]),
    { deps: [] },
  )
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  async function assign(assetId:string){setSaving(true);setError(null);try{await api.assignEngagementAsset(engagement.id,assetId);onChanged()}catch(e){setError(e instanceof Error?e.message:'Failed to assign Asset')}finally{setSaving(false)}}
  return <div className="mt-3 flex flex-wrap items-center gap-3"><span className="text-xs font-semibold uppercase tracking-wide text-subtlefg">Asset assignment</span><Select value={engagement.businessAssetId} onValueChange={assign} disabled={saving} size="sm" options={[{value:'',label:'Unassigned'},...(assets ?? []).map(a=>({value:a.id,label:`${a.name} (${a.key})`}))]}/>{error&&<span className="text-xs text-critical">{error}</span>}</div>
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
        <ShieldCheck className="size-3.5" />
        {ev.intact ? 'Evidence verified' : 'Evidence tampered'}
      </span>
      {ev.intact && ev.keyId && (
        <span
          className="inline-flex items-center gap-1 rounded-md bg-muted px-2 py-0.5 font-mono text-xs text-mutedfg ring-1 ring-inset ring-border"
          title={`Chain head signed (ed25519) by key ${ev.keyId} – proves origin, not just integrity`}
        >
          <FileSignature className="size-3.5" />
          {ev.keyId}
        </span>
      )}
    </span>
  )
}

// Mirrors the report builder's canonical sections (internal/usecase/report); keys +
// order must match so the customer deliverable renders predictably.

// Report variants and their default section sets – mirrors reportProfiles in
// internal/usecase/report. The server stays the source of truth (framing + content);
// these only pre-select the checkboxes so the modal is WYSIWYG per type. The
// remediation + exhibits sections self-omit when there's no data, so they are safe to
// pre-select.

// ReportBuilderModal assembles a deterministic, templated report (no model in the
// path). PDF is the full sealed report; HTML/DOCX honor the section,
// status, and title customization below.

// trapTabFocus keeps Tab/Shift+Tab cycling within the modal's focusable elements.

// ---- Scan bar (Part 1) ----

// detectKind infers the target kind from its value (a URL is a git clone).

// ---- Navigation (Part 4) ----

// ---- Overview (Part 2): organized around decisions, top to bottom ----

// FindingQualityStrip: raw vs actionable vs background, before any
// vuln count – so a flood of example/test findings never reads as headline risk.

// Section 1 – Scan Health.

// Section 2 – What Needs Attention (the most important section; before composition).

// Section 3 – Top Remediation Targets: what to fix first.

// Section 4 – Vulnerability Distribution (clickable → filtered findings).

// Section 5 – Project Composition (informational, lower).

// Section 6 – Provenance (audit info, bottom).

// ---- Findings (Part 4: raw vulnerabilities folded in as expandable detail) ----

// shortPkg turns a component identity (PURL or name@version) into a bare name.

// frameworkShort renders a compact label for a compliance framework id.

// ComplianceChips lists the curated regulatory/standard controls a finding's CWE maps to.
// Deterministic, server-computed reference data (compliance.ControlsFor) – advisory context only,
// never a gate. Renders nothing when the CWE maps to no controls (the common case for non-code kinds).

// JudgmentStateBadge shows a judgment's lifecycle state (proposed = unverified AI output, confirmed
// = human-ratified, refuted = a verifier rejected it) as a text+color chip – never color alone.

// RiskNarrative (ungated) explains a finding's computed priority via closed driver tokens –
// never free prose (R8); the priority mirrors the Go-computed value.

// Critique (gated) is an adversarial review of a finding – verdict + a closed driver token +
// confidence. A confirmed "refuted" critique is what drives the suspected-FP flag on the list.

// Reachability (gated) surfaces a reachability verdict: whether the vulnerable symbol is reachable
// (reachable is the worse, attention-worthy state), the tier (a deterministic Tier-2 call-graph proof
// supersedes an LLM Tier-1.5), and the call-path proof chain. The state badge marks an unverified proposal.

// ExplainJudgments surfaces the read-side "explain & advise" analysis judgments for a finding:
// the risk narrative, adversarial critiques, and the reachability verdict (AI-proposed or deterministic).
// Self-contained, best-effort fetch – it NEVER blocks or errors the finding detail (judgments disabled /
// load failure / none ⇒ renders nothing). The state badge keeps a "proposed" (unverified) judgment
// visibly distinct from a human-ratified or deterministically-proven one.

// EVIDENCE_BAR mirrors the domain's finding.EvidenceThreshold (the server is authoritative): an
// exploitation finding is unproven + unreportable until a DISTINCT verifier raises its score to
// this bar.

// ---- Packages (formerly SBOM components) ----

// ---- Vulnerabilities (complete advisory list, incl. sub-threshold not promoted to findings) ----

// packageLocationMap groups each package@version to the distinct manifest locations it was
// declared in, so a vulnerability is counted once per place it actually ships.

// countVulnerabilityFindings is the TRUE finding count the table renders: every advisory
// (CVE/GHSA/OSV – not just CVE) counted once per affected package@version per manifest
// location. This matches the rows on screen – not distinct packages, not distinct CVE ids.

// ---- Licenses ----

// LicenseChipStack renders a package's licenses (or their severities) as one chip per
// entry, stacked vertically and coloured by each license's own severity – so a dual/multi-
// license package reads as separate choices (OR), aligned across the License/Severity columns.

// ---- shared bits ----

// PriorityBadge renders the unified Synapse risk priority (1 highest.. 5 background).

// ScopeBadge shows where the component lives; background scopes are de-emphasized.

// DetectedBy renders the detection sources – OSV, Grype, or both.

// KindBadge labels a finding's Kind – shown in the list for the non-SCA kinds (sast,
// exploitation, threat, hypothesis, recon, manual) where the provenance is worth surfacing.

// KindFilter is the finding-Kind segmented filter, mirroring SeverityFilter. Only the Kinds
// actually present are offered, plus "all".

// ---- Recon: gated live-recon launcher · runs · SSE console ----

// ReconContainmentBadge shows the confinement posture a run executed under:
// green when sandboxed (egress-restricted / isolated), amber when unsandboxed (dev).

// ReconConsole tails a run's logs over SSE (fetch-based; reconnects with the last
// event id if the stream drops before the run finishes).

// ---- Settings: scope CRUD · authorization window · lifecycle ----

// LiveReconCard toggles lab-only live recon. Off by default; enabling
// it is an explicit, audited opt-in shown with a clear safety caveat.

// Known tool classes (gate-action prefixes). Empty selection = no restriction.

// toLocalInput converts an RFC3339 instant to a datetime-local input value
// (YYYY-MM-DDTHH:mm in the browser's local time); '' for null/invalid.

// ---- Evidence vault: tamper-evident chain timeline + manual capture ----

// fileToBase64 reads a File as base64 (without the data URL prefix) for capture.

// ---- Findings workflow: manual authoring · CVSS builder · Kanban · collab ----

// Common CWEs for the picker datalist (operators can still type any value).


