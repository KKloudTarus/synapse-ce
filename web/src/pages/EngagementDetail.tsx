import {
  AlertTriangle,
  ArrowLeft,
  BadgeCheck,
  Bot,
  Boxes,
  Bug,
  CalendarClock,
  CheckCircle2,
  ChevronRight,
  Clock,
  Code2,
  Database,
  Download,
  FileSignature,
  FileClock,
  FileText,
  GaugeCircle,
  LayoutDashboard,
  Loader2,
  Network,
  PackageOpen,
  Play,
  Plus,
  Radar,
  RotateCcw,
  Save,
  Scale,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  SlidersHorizontal,
  Sparkles,
  Target,
  Trash2,
  Upload,
  Waypoints,
  Wrench,
  X,
} from 'lucide-react'
import { Fragment, lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  Button,
  Card,
  cn,
  EmptyState,
  ErrorState,
  Field,
  Input,
  KevBadge,
  Pill,
  Select,
  SevBadge,
  Spinner,
} from '../components/ui'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { AgentTab } from './AgentTab'
import { ThreatModelTab } from './ThreatModelTab'
import { api, ApiError, downloadBundle, downloadExport, downloadReport, downloadReportDoc, streamReconLogs, type ReportType } from '../lib/api'
import {
  downloadStyledExcel,
  EXCEL_EXPORT_MODE_OPTIONS,
  excelFileSafeName,
  type ExcelExportMode,
} from '../lib/excelExport'
import { findingKindLabel, kindLabel, statusLabel } from '../lib/format'
import { CATEGORY_LABEL, sevFill, sevRank, sevSoft, sevText, SEVERITY_ORDER } from '../lib/severity'
import type {
  Engagement,
  EvidenceItem,
  EvidenceLedger,
  Finding,
  FindingComment,
  ImportedSBOMMetadata,
  Judgment,
  RiskNarrativeClaim,
  CritiqueClaim,
  ReachabilityClaim,
  ScanJob,
  ScanDebugEvent,
  ScanMode,
  ScanResult,
  ReconRun,
  ReconTool,
  Retest,
  RetestOutcome,
  ScopeTarget,
  Severity,
  Vulnerability,
  Writeup,
} from '../lib/types'
import { StatusPill } from './Engagements'
// Lazy-loaded so React Flow stays out of the initial bundle (only the Graph tab needs it).
const DependencyGraphTab = lazy(() => import('./DependencyGraph').then((m) => ({ default: m.DependencyGraphTab })))

type Tab = 'overview' | 'findings' | 'components' | 'vulns' | 'licenses' | 'graph' | 'threats' | 'recon' | 'agent' | 'evidence' | 'settings'

export function EngagementDetail() {
  const { id = '' } = useParams()
  const [eng, setEng] = useState<Engagement | null | undefined>(undefined)
  const [engErr, setEngErr] = useState<string | null>(null)
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [importedSBOM, setImportedSBOM] = useState<ImportedSBOMMetadata | null>(null)
  const [job, setJob] = useState<ScanJob | null>(null)
  const [tab, setTab] = useState<Tab>('overview')
  const [findingsFilter, setFindingsFilter] = useState<Severity | 'all'>('all')

  useEffect(() => {
    setEng(undefined)
    setEngErr(null)
    api
      .getEngagement(id)
      .then(setEng)
      .catch((e) => {
        if (e instanceof ApiError && e.status === 404) setEng(null)
        else setEngErr(e instanceof Error ? e.message : 'Failed to load engagement')
      })
  }, [id])

  useEffect(() => {
    setFindings(null)
    api.findings(id).then(setFindings).catch(() => setFindings([]))
  }, [id])

  // Rehydrate the most recent scan so the tabs work on a fresh load, not only
  // right after running a scan.
  useEffect(() => {
    api
      .latestScan(id)
      .then((r) => {
        if (r) {
          setScan(r)
          if (r.scanMode === 'licenses') setFindings(r.findings)
        }
      })
      .catch(() => undefined)
  }, [id])

  useEffect(() => {
    api.importedSBOM(id).then(setImportedSBOM).catch(() => setImportedSBOM(null))
  }, [id])

  function reloadFindings() {
    api.findings(id).then(setFindings).catch(() => undefined)
  }

  // refreshAll re-pulls the latest scan + findings (after an SBOM import or VEX apply).
  function refreshAll() {
    api.latestScan(id).then((r) => r && setScan(r)).catch(() => undefined)
    api.findings(id).then(setFindings).catch(() => undefined)
    api.importedSBOM(id).then(setImportedSBOM).catch(() => setImportedSBOM(null))
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
            onUpdated={applyFinding}
            onReload={reloadFindings}
          />
        )}
        {tab === 'components' && <ComponentsTab scan={scan} />}
        {tab === 'vulns' && <VulnsTab scan={scan} />}
        {tab === 'graph' && (
          <Suspense fallback={<Spinner label="Loading graph…" />}>
            <DependencyGraphTab scan={scan} />
          </Suspense>
        )}
        {tab === 'licenses' && <LicensesTab scan={scan} />}
        {tab === 'threats' && <ThreatModelTab engagementId={id} />}
        {tab === 'recon' && <ReconTab eng={eng} onGoTab={setTab} />}
        {tab === 'agent' && <AgentTab engagementId={id} />}
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
        <span className="flex items-center gap-1.5">
          <Target className="size-3.5" /> {eng.inScope.length} in scope
        </span>
        {(eng.authorizedFrom || eng.authorizedTo) && (
          <span className="flex items-center gap-1.5">
            <CalendarClock className="size-3.5" /> {fmtWindow(eng.authorizedFrom, eng.authorizedTo)}
          </span>
        )}
      </div>
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

// EvidenceBadge shows the tamper-evident evidence-chain status and, when
// the chain head is signed, its origin attestation (integrity + origin).
function EvidenceBadge({ engagementId }: { engagementId: string }) {
  const [ev, setEv] = useState<{ intact: boolean; verified: number; keyId?: string } | null>(null)
  useEffect(() => {
    api.evidence(engagementId).then((e) => {
      if (e && e.verified > 0) setEv({ intact: e.intact, verified: e.verified, keyId: e.attestation?.key_id })
    })
  }, [engagementId])
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
          title={`Chain head signed (ed25519) by key ${ev.keyId} — proves origin, not just integrity`}
        >
          <FileSignature className="size-3.5" />
          {ev.keyId}
        </span>
      )}
    </span>
  )
}

function ExportButtons({ engagementId, scan, onChanged }: { engagementId: string; scan: ScanResult | null; onChanged: () => void }) {
  const [busy, setBusy] = useState<'sarif' | 'openvex' | 'spdx' | 'cyclonedx' | 'bundle' | 'sbom' | 'vex' | 'excel' | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [building, setBuilding] = useState(false)
  const [excelMode, setExcelMode] = useState<ExcelExportMode>('service')
  const sbomRef = useRef<HTMLInputElement>(null)
  const vexRef = useRef<HTMLInputElement>(null)

  async function run(kind: 'sarif' | 'openvex' | 'spdx' | 'cyclonedx' | 'bundle') {
    setBusy(kind)
    setErr(null)
    setMsg(null)
    try {
      if (kind === 'bundle') await downloadBundle(engagementId)
      else await downloadExport(engagementId, kind)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Download failed')
    } finally {
      setBusy(null)
    }
  }

  async function upload(kind: 'sbom' | 'vex', e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setBusy(kind)
    setErr(null)
    setMsg(null)
    try {
      const text = await file.text()
      if (kind === 'sbom') {
        const r = await api.importSBOM(engagementId, text)
        setMsg(`Imported ${r.components} package(s) from ${r.target}.`)
      } else {
        const r = await api.applyVEX(engagementId, text)
        setMsg(`VEX: applied ${r.applied} of ${r.matched} matched (${r.statements} statement(s)).`)
      }
      onChanged()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Upload failed')
    } finally {
      setBusy(null)
    }
  }

  function exportExcel() {
    if (!scan) {
      setErr('Run a scan before exporting Excel.')
      return
    }
    setBusy('excel')
    setErr(null)
    setMsg(null)
    try {
      downloadStyledExcel(`synapse-${excelFileSafeName(engagementId)}-vulnerabilities-licenses.xlsx`, scan, excelMode)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Excel export failed')
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <input ref={sbomRef} type="file" accept="application/json,.json" className="hidden" onChange={(e) => upload('sbom', e)} />
      <input ref={vexRef} type="file" accept="application/json,.json" className="hidden" onChange={(e) => upload('vex', e)} />
      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button variant="brand" onClick={() => setBuilding(true)} className="px-3 py-1.5">
          <FileText className="size-4" /> Build report
        </Button>
        <Select
          value={excelMode}
          onValueChange={(value) => setExcelMode(value as ExcelExportMode)}
          options={EXCEL_EXPORT_MODE_OPTIONS}
          ariaLabel="Excel export mode"
          disabled={!scan || busy === 'excel'}
          size="sm"
          className="w-32"
        />
        <Button variant="secondary" loading={busy === 'excel'} onClick={exportExcel} disabled={!scan} className="px-3 py-1.5" title="Export the Vulnerabilities and Licenses web tables to Excel">
          <Download className="size-4" /> Excel
        </Button>
        <Button variant="secondary" loading={busy === 'sarif'} onClick={() => run('sarif')} className="px-3 py-1.5">
          <Download className="size-4" /> SARIF
        </Button>
        <Button variant="secondary" loading={busy === 'openvex'} onClick={() => run('openvex')} className="px-3 py-1.5">
          <Download className="size-4" /> VEX
        </Button>
        <Button variant="secondary" loading={busy === 'spdx'} onClick={() => run('spdx')} className="px-3 py-1.5" title="SPDX 3.0.1 (CRA-aligned)">
          <Download className="size-4" /> SPDX
        </Button>
        <Button variant="secondary" loading={busy === 'cyclonedx'} onClick={() => run('cyclonedx')} className="px-3 py-1.5" title="CycloneDX 1.6">
          <Download className="size-4" /> CycloneDX
        </Button>
        <Button variant="secondary" loading={busy === 'bundle'} onClick={() => run('bundle')} className="px-3 py-1.5" title="Portable engagement bundle with the evidence chain (re-verified on import)">
          <PackageOpen className="size-4" /> Bundle
        </Button>
        <Button variant="secondary" loading={busy === 'sbom'} onClick={() => sbomRef.current?.click()} className="px-3 py-1.5" title="Import a client CycloneDX SBOM">
          <Upload className="size-4" /> Import SBOM
        </Button>
        <Button variant="secondary" loading={busy === 'vex'} onClick={() => vexRef.current?.click()} className="px-3 py-1.5" title="Apply a client OpenVEX document to the findings">
          <Upload className="size-4" /> Apply VEX
        </Button>
      </div>
      {err && (
        <span role="alert" className="flex items-center gap-1 text-xs text-critical">
          <AlertTriangle className="size-3.5 shrink-0" /> {err}
        </span>
      )}
      {msg && (
        <span role="status" className="flex items-center gap-1 text-xs text-accent">
          <CheckCircle2 className="size-3.5 shrink-0" /> {msg}
        </span>
      )}
      {building && <ReportBuilderModal engagementId={engagementId} onClose={() => setBuilding(false)} />}
    </div>
  )
}

// Mirrors the report builder's canonical sections (internal/usecase/report); keys +
// order must match so the customer deliverable renders predictably.
// Mirrors the report builder's canonical sections (internal/usecase/report); keys +
// order must match so the customer deliverable renders predictably.
const REPORT_SECTIONS: { key: string; label: string }[] = [
  { key: 'engagement', label: 'Engagement summary' },
  { key: 'scope', label: 'Scope statement' },
  { key: 'methodology', label: 'Methodology' },
  { key: 'summary', label: 'Executive summary' },
  { key: 'remediation', label: 'Remediation status' },
  { key: 'risk', label: 'Risk overview' },
  { key: 'top', label: 'Top findings' },
  { key: 'findings', label: 'Findings overview (table)' },
  { key: 'details', label: 'Finding details' },
  { key: 'scan', label: 'Scan & SBOM insight' },
  { key: 'evidence', label: 'Evidence & chain of custody' },
  { key: 'exhibits', label: 'Evidence exhibits (screenshots)' },
]

// Report variants and their default section sets — mirrors reportProfiles in
// internal/usecase/report. The server stays the source of truth (framing + content);
// these only pre-select the checkboxes so the modal is WYSIWYG per type. The
// remediation + exhibits sections self-omit when there's no data, so they are safe to
// pre-select.
const REPORT_TYPES: { key: ReportType; label: string }[] = [
  { key: 'sca', label: 'SCA / dependency' },
  { key: 'external', label: 'External assessment' },
  { key: 'internal', label: 'Internal assessment' },
  { key: 'retest', label: 'Retest' },
]

const ASSESSMENT_SECTIONS = ['engagement', 'scope', 'methodology', 'summary', 'risk', 'top', 'findings', 'details', 'evidence', 'exhibits']
const TYPE_DEFAULT_SECTIONS: Record<ReportType, string[]> = {
  sca: REPORT_SECTIONS.filter((s) => s.key !== 'remediation').map((s) => s.key),
  external: ASSESSMENT_SECTIONS,
  internal: ASSESSMENT_SECTIONS,
  retest: ['engagement', 'scope', 'summary', 'remediation', 'risk', 'findings', 'evidence', 'exhibits'],
}

const REPORT_STATUSES: { key: string; label: string }[] = [
  { key: 'open', label: 'Open' },
  { key: 'triage', label: 'Triage' },
  { key: 'confirmed', label: 'Confirmed' },
  { key: 'remediated', label: 'Remediated' },
  { key: 'false_positive', label: 'False positive' },
]

// ReportBuilderModal assembles a deterministic, templated report (no model in the
// path). PDF is the full sealed report; HTML/DOCX honor the section,
// status, and title customization below.
function ReportBuilderModal({ engagementId, onClose }: { engagementId: string; onClose: () => void }) {
  const [format, setFormat] = useState<'pdf' | 'html' | 'docx'>('pdf')
  const [type, setType] = useState<ReportType>('sca')
  const [sections, setSections] = useState<Set<string>>(() => new Set(TYPE_DEFAULT_SECTIONS.sca))
  const [statuses, setStatuses] = useState<Set<string>>(() => new Set())
  const [title, setTitle] = useState('')

  // Picking a variant resets the section selection to that variant's default set, so
  // the checkboxes always reflect what the chosen report type includes.
  function selectType(t: ReportType) {
    setType(t)
    setSections(new Set(TYPE_DEFAULT_SECTIONS[t]))
  }
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const customizable = format !== 'pdf'
  const noSections = customizable && sections.size === 0
  const panelRef = useRef<HTMLDivElement>(null)

  // Move focus into the dialog on open, trap Tab inside it, and restore focus to
  // the trigger on close (a11y: a modal must own keyboard focus).
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null
    panelRef.current?.focus()
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onClose()
        return
      }
      if (e.key === 'Tab') trapTabFocus(e, panelRef.current)
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      prev?.focus?.()
    }
  }, [onClose])

  function toggle(set: Set<string>, setter: (s: Set<string>) => void, key: string) {
    const next = new Set(set)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    setter(next)
  }

  async function download() {
    setBusy(true)
    setErr(null)
    try {
      if (format === 'pdf') {
        await downloadReport(engagementId)
      } else {
        await downloadReportDoc(engagementId, format, {
          type,
          sections: REPORT_SECTIONS.filter((s) => sections.has(s.key)).map((s) => s.key),
          statuses: [...statuses],
          title,
        })
      }
      onClose()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Report generation failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <button type="button" aria-label="Close" className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div
        ref={panelRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="report-builder-title"
        className="elev relative z-10 w-full max-w-lg rounded-xl border border-borderstrong bg-card p-5 text-left shadow-xl outline-none"
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 id="report-builder-title" className="flex items-center gap-2 text-lg font-semibold">
            <SlidersHorizontal className="size-4 text-brand" /> Build report
          </h2>
          <button type="button" aria-label="Close" onClick={onClose} className="rounded-md p-1 text-mutedfg hover:bg-raised hover:text-foreground">
            <X className="size-4" />
          </button>
        </div>

        <div className="space-y-4">
          <Field label="Format">
            <div role="radiogroup" aria-label="Report format" className="inline-flex rounded-lg border border-border bg-elevated p-0.5">
              {(['pdf', 'html', 'docx'] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  role="radio"
                  aria-checked={format === f}
                  onClick={() => setFormat(f)}
                  className={cn(
                    'rounded-md px-3 py-1.5 text-sm font-medium uppercase transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40',
                    format === f ? 'bg-brand text-brandfg' : 'text-mutedfg hover:text-foreground',
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
          </Field>

          {!customizable ? (
            <p className="rounded-lg border border-border bg-elevated px-3.5 py-2.5 text-xs text-mutedfg">
              The PDF is the full canonical report (all sections, all findings), sealed with a SHA-256 for chain of custody.
              Switch to HTML or DOCX to customize sections, finding statuses, and the title.
            </p>
          ) : (
            <>
              <Field label="Report type" hint="Frames the deliverable (title, methodology, sections)">
                <div role="radiogroup" aria-label="Report type" className="grid grid-cols-2 gap-1.5">
                  {REPORT_TYPES.map((rt) => (
                    <button
                      key={rt.key}
                      type="button"
                      role="radio"
                      aria-checked={type === rt.key}
                      onClick={() => selectType(rt.key)}
                      className={cn(
                        'rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40',
                        type === rt.key ? 'border-brand bg-brand/10 text-foreground' : 'border-border text-mutedfg hover:text-foreground',
                      )}
                    >
                      {rt.label}
                    </button>
                  ))}
                </div>
              </Field>
              <Field label="Title" hint="Defaults to the report-type title">
                <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Q3 External Assessment" />
              </Field>
              <Field label="Sections" hint={noSections ? undefined : 'Rendered in the canonical order'}>
                <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                  {REPORT_SECTIONS.map((s) => (
                    <CheckRow key={s.key} label={s.label} checked={sections.has(s.key)} onChange={() => toggle(sections, setSections, s.key)} />
                  ))}
                </div>
                {noSections && <p className="mt-1.5 text-xs text-critical">Select at least one section.</p>}
              </Field>
              <Field label="Include finding statuses" hint="None selected = all statuses">
                <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                  {REPORT_STATUSES.map((s) => (
                    <CheckRow key={s.key} label={s.label} checked={statuses.has(s.key)} onChange={() => toggle(statuses, setStatuses, s.key)} />
                  ))}
                </div>
              </Field>
            </>
          )}

          {err && <ErrorState message={err} />}
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose} className="px-3 py-1.5">
            Cancel
          </Button>
          <Button loading={busy} disabled={noSections} onClick={download} className="px-3 py-1.5">
            <Download className="size-4" /> Download {format.toUpperCase()}
          </Button>
        </div>
      </div>
    </div>
  )
}

function CheckRow({ label, checked, onChange }: { label: string; checked: boolean; onChange: () => void }) {
  return (
    <label className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-raised focus-within:bg-raised">
      <input type="checkbox" checked={checked} onChange={onChange} className="size-4 accent-brand" />
      <span>{label}</span>
    </label>
  )
}

// trapTabFocus keeps Tab/Shift+Tab cycling within the modal's focusable elements.
function trapTabFocus(e: KeyboardEvent, panel: HTMLElement | null) {
  if (!panel) return
  const focusable = Array.from(
    panel.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'),
  ).filter((el) => !el.hasAttribute('disabled') && el.offsetParent !== null)
  if (focusable.length === 0) return
  const first = focusable[0]
  const last = focusable[focusable.length - 1]
  const active = document.activeElement
  if (e.shiftKey && active === first) {
    e.preventDefault()
    last.focus()
  } else if (!e.shiftKey && active === last) {
    e.preventDefault()
    first.focus()
  }
}

// ---- Scan bar (Part 1) ----

const KINDS = ['git', 'local', 'archive', 'image']
const SCAN_MODES: Array<{ value: ScanMode; label: string }> = [
  { value: 'full', label: 'Full' },
  { value: 'vulnerabilities', label: 'Vulns' },
  { value: 'licenses', label: 'Licenses' },
]

// detectKind infers the target kind from its value (a URL is a git clone).
function detectKind(target: string): string {
  return /^https?:\/\//i.test(target.trim()) ? 'git': 'local'
}

function SegmentedKind({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div
      role="radiogroup"
      aria-label="Target kind"
      className="inline-flex h-10 max-w-full shrink-0 items-center overflow-x-auto rounded-lg border border-border bg-elevated p-0.5"
    >
      {KINDS.map((k) => {
        const active = value === k
        return (
          <button
            key={k}
            role="radio"
            aria-checked={active}
            onClick={() => onChange(k)}
            className={cn(
              'h-full rounded-md px-3 text-sm font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40',
              active ? 'bg-card text-foreground shadow-sm' : 'text-mutedfg hover:text-foreground',
            )}
          >
            {kindLabel(k)}
          </button>
        )
      })}
    </div>
  )
}

function SegmentedScanMode({ value, onChange }: { value: ScanMode; onChange: (v: ScanMode) => void }) {
  return (
    <div
      role="radiogroup"
      aria-label="Scan mode"
      className="inline-flex h-10 max-w-full shrink-0 items-center overflow-x-auto rounded-lg border border-border bg-elevated p-0.5"
    >
      {SCAN_MODES.map((m) => {
        const active = value === m.value
        return (
          <button
            key={m.value}
            role="radio"
            aria-checked={active}
            onClick={() => onChange(m.value)}
            className={cn(
              'h-full rounded-md px-3 text-sm font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40',
              active ? 'bg-card text-foreground shadow-sm' : 'text-mutedfg hover:text-foreground',
            )}
          >
            {m.label}
          </button>
        )
      })}
    </div>
  )
}

function ScanPanel({
  eng,
  importedSBOM,
  onImportedSBOMChanged,
  job,
  setJob,
  onScanned,
}: {
  eng: Engagement
  importedSBOM: ImportedSBOMMetadata | null
  onImportedSBOMChanged: () => void
  job: ScanJob | null
  setJob: (j: ScanJob | null) => void
  onScanned: (r: ScanResult) => void
}) {
  const target0 = eng.inScope[0]?.value ?? ''
  const [target, setTarget] = useState(target0)
  const [kind, setKind] = useState(detectKind(target0))
  const [kindManual, setKindManual] = useState(false)
  const [mode, setMode] = useState<ScanMode>('full')
  const [branch, setBranch] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [summary, setSummary] = useState<ScanResult | null>(null)
  const [sbomBusy, setSBOMBusy] = useState(false)
  const [sbomError, setSBOMError] = useState<string | null>(null)
  const [sbomMessage, setSBOMMessage] = useState<string | null>(null)
  const sbomRef = useRef<HTMLInputElement>(null)
  const poll = useRef<ReturnType<typeof setInterval> | null>(null)

  const running = job?.status === 'running'
  const debugEvents = job?.debugEvents?.length ? job.debugEvents : (summary?.debugEvents ?? [])
  const usingImportedSBOM = Boolean(importedSBOM)

  // Authorization window guard: refuse to start a scan in the UI when the
  // engagement is outside its window — the server enforces this too (403).
  const now = Date.now()
  const notYet = eng.authorizedFrom ? now < new Date(eng.authorizedFrom).getTime() : false
  const expired = eng.authorizedTo ? now > new Date(eng.authorizedTo).getTime() : false
  const outsideWindow = notYet || expired

  function stopPoll() {
    if (poll.current) {
      clearInterval(poll.current)
      poll.current = null
    }
  }

  function startPoll() {
    stopPoll()
    poll.current = setInterval(async () => {
      const j = await api.scanStatus(eng.id).catch(() => null)
      if (!j) return
      setJob(j)
      if (j.status === 'running') return
      stopPoll()
      if (j.status === 'succeeded') {
        const res = await api.latestScan(eng.id).catch(() => null)
        if (res) {
          setSummary(res)
          onScanned(res)
        }
      } else if (j.status === 'failed') {
        setError(j.error || 'Scan failed')
      }
    }, 1500)
  }

  // Resume on mount: reflect any in-progress / finished scan so a reload keeps the
  // progress bar (and doesn't reset to "Run scan" with the scan still running).
  useEffect(() => {
    let live = true
    api
      .scanStatus(eng.id)
      .then(async (j) => {
        if (!live || !j) return
        setJob(j)
        if (j.status === 'running') startPoll()
        else if (j.status === 'failed') setError(j.error || 'Scan failed')
        else if (j.status === 'succeeded') {
          const res = await api.latestScan(eng.id).catch(() => null)
          if (live && res) setSummary(res)
        }
      })
      .catch(() => undefined)
    return () => {
      live = false
      stopPoll()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eng.id])

  async function run() {
    if (!usingImportedSBOM && !target.trim()) {
      setError('Enter a target.')
      return
    }
    setError(null)
    setSummary(null)
    try {
      const ref = kind === 'git' ? branch.trim() : ''
      setJob(await api.startScan(eng.id, usingImportedSBOM ? '' : target.trim(), usingImportedSBOM ? 'imported-sbom' : kind, ref, mode))
      startPoll()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to start scan')
    }
  }

  async function uploadSBOM(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setSBOMBusy(true)
    setSBOMError(null)
    setSBOMMessage(null)
    try {
      const text = await file.text()
      const r = await api.importSBOM(eng.id, text)
      setSBOMMessage(`Imported ${r.components.toLocaleString()} component(s).`)
      onImportedSBOMChanged()
    } catch (e) {
      setSBOMError(e instanceof Error ? e.message : 'Upload failed')
    } finally {
      setSBOMBusy(false)
    }
  }

  return (
    <Card bodyClass="p-4" className="mb-6">
      <input ref={sbomRef} type="file" accept="application/json,.json" className="hidden" onChange={uploadSBOM} />
      <div className="mb-3 flex flex-col gap-3 border-b border-border pb-3 md:flex-row md:items-center md:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm font-medium text-foreground">
            <Database className="size-4 text-mutedfg" />
            <span>{importedSBOM ? importedSBOM.filename : 'SBOM.json'}</span>
            {importedSBOM && <Pill className="bg-accent/10 text-accent ring-1 ring-inset ring-accent/30">active</Pill>}
          </div>
          {importedSBOM ? (
            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-mutedfg">
              <span className="font-mono tabular-nums">{importedSBOM.componentCount.toLocaleString()} components</span>
              <span className="font-mono tabular-nums">{importedSBOM.dependencyCount.toLocaleString()} edges</span>
              <span className="truncate font-mono" title={importedSBOM.sha256}>{importedSBOM.sha256.slice(0, 12)}</span>
              <span>{importedSBOM.createdAt ? new Date(importedSBOM.createdAt).toLocaleString() : '—'}</span>
            </div>
          ) : (
            <div className="mt-1 text-xs text-mutedfg">No imported SBOM active</div>
          )}
        </div>
        <Button variant="secondary" loading={sbomBusy} onClick={() => sbomRef.current?.click()} className="h-9 shrink-0 px-3">
          <Upload className="size-4" />
          Import SBOM
        </Button>
      </div>
      {(sbomError || sbomMessage) && (
        <div className={cn('mb-3 flex items-center gap-1 text-xs', sbomError ? 'text-critical' : 'text-accent')} role={sbomError ? 'alert' : 'status'}>
          {sbomError ? <AlertTriangle className="size-3.5" /> : <CheckCircle2 className="size-3.5" />}
          {sbomError || sbomMessage}
        </div>
      )}
      {/* Single horizontal scan bar — all controls share one height + baseline. */}
      <div className="flex flex-col gap-2 lg:flex-row lg:items-center">
        {!usingImportedSBOM && (
          <SegmentedKind
            value={kind}
            onChange={(v) => {
              setKind(v)
              setKindManual(true)
            }}
          />
        )}
        <SegmentedScanMode value={mode} onChange={setMode} />
        {usingImportedSBOM ? (
          <div className="flex h-10 min-w-0 items-center rounded-lg border border-border bg-elevated px-3 font-mono text-sm text-mutedfg lg:flex-1">
            <span className="truncate">{importedSBOM?.targetRef || importedSBOM?.filename || 'SBOM.json'}</span>
          </div>
        ) : (
          <Input
            value={target}
            onChange={(e) => {
              setTarget(e.target.value)
              if (!kindManual) setKind(detectKind(e.target.value))
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !running) run()
            }}
            placeholder="https://github.com/org/repo or /path/to/repo"
            className="h-10 font-mono lg:flex-1"
            aria-label="Scan target"
          />
        )}
        {!usingImportedSBOM && kind === 'git' && (
          <Input
            value={branch}
            onChange={(e) => setBranch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !running) run()
            }}
            placeholder="branch (optional)"
            className="h-10 font-mono lg:w-48"
            aria-label="Git branch or tag"
          />
        )}
        <Button onClick={run} loading={running} disabled={running || outsideWindow} className="h-10 lg:w-auto">
          <Play className="size-4" />
          {running ? 'Scanning…' : 'Run scan'}
        </Button>
      </div>

      {!usingImportedSBOM && kind === 'local' && (
        <p className="mt-2 text-xs text-mutedfg">
          Local scans run on the server path you enter. Use an absolute folder path inside this engagement&rsquo;s scope.
        </p>
      )}

      {outsideWindow && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-critical/40 bg-critical/10 p-3 text-xs text-critical">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>
            {expired ? 'Authorization window has expired' : 'Authorization window has not started'} — scanning is
            disabled. Update the engagement’s window to proceed.
          </span>
        </div>
      )}

      {running && (
        <div className="mt-4">
          <div className="mb-1.5 flex items-center justify-between text-xs">
            <span className="capitalize text-foreground">{job?.stage || 'starting'}…</span>
            <span className="font-mono tabular-nums text-mutedfg">{job?.progress ?? 0}%</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-elevated">
            <div
              className="h-full rounded-full bg-brand transition-[width] duration-500 ease-out"
              style={{ width: `${Math.max(3, job?.progress ?? 0)}%` }}
            />
          </div>
        </div>
      )}

      <ScanDebugTimeline events={debugEvents} running={running} />

      {error && (
        <div className="mt-3">
          <ErrorState message={error} />
        </div>
      )}

      {summary && !running && summary.completeness.warning && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-medium/40 bg-medium/10 p-3 text-xs text-medium">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>{summary.completeness.warning}</span>
        </div>
      )}

      {/* Pipeline description tucked away — the scan flow reads in 3 seconds without it. */}
      <details className="group mt-3 text-xs">
        <summary className="inline-flex cursor-pointer select-none items-center gap-1 text-mutedfg transition-colors hover:text-foreground">
          <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" />
          Pipeline &amp; enforcement
        </summary>
        <p className="mt-2 pl-4 text-mutedfg">
          detect languages → SBOM (Syft) → selected vulnerability/license stages → findings. Enforced against this
          engagement&rsquo;s scope, server-side.
        </p>
      </details>
    </Card>
  )
}

function ScanDebugTimeline({ events, running }: { events: ScanDebugEvent[]; running: boolean }) {
  if (!events.length && !running) return null
  const visibleEvents = events.slice(-12)
  return (
    <details className="group mt-3 text-xs" open={running}>
      <summary className="inline-flex cursor-pointer select-none items-center gap-1 text-mutedfg transition-colors hover:text-foreground">
        <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" />
        Debug timeline
        {events.length > 0 && <span className="font-mono tabular-nums text-mutedfg">({events.length})</span>}
      </summary>
      <div className="mt-2 space-y-2 rounded-lg border border-border bg-card p-3">
        {visibleEvents.length === 0 ? (
          <div className="flex items-center gap-2 text-mutedfg">
            <Loader2 className="size-3.5 animate-spin" />
            Waiting for scan steps…
          </div>
        ) : (
          visibleEvents.map((event, idx) => <ScanDebugRow key={`${event.stage}-${event.step}-${idx}`} event={event} />)
        )}
      </div>
    </details>
  )
}

function ScanDebugRow({ event }: { event: ScanDebugEvent }) {
  const failed = event.status === 'failed'
  const running = event.status === 'running'
  const Icon = failed ? X : running ? Loader2 : CheckCircle2
  const counts = formatDebugCounts(event.counts)
  return (
    <div className="flex items-start gap-2 rounded-md bg-elevated px-3 py-2">
      <Icon
        className={cn(
          'mt-0.5 size-3.5 shrink-0',
          failed ? 'text-critical' : running ? 'animate-spin text-brand' : 'text-accent',
        )}
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="font-medium text-foreground">{event.step || event.stage}</span>
          {event.tool && <span className="font-mono text-[11px] text-mutedfg">{event.tool}</span>}
          <span className="font-mono text-[11px] tabular-nums text-mutedfg">
            {running ? 'running' : fmtDebugDuration(event.durationMs)}
          </span>
        </div>
        <div className={cn('mt-0.5 text-mutedfg', failed && 'text-critical')}>{event.error || event.message}</div>
        {counts && <div className="mt-1 font-mono text-[11px] tabular-nums text-mutedfg">{counts}</div>}
      </div>
    </div>
  )
}

function formatDebugCounts(counts: Record<string, number>) {
  const entries = Object.entries(counts ?? {})
  if (entries.length === 0) return ''
  return entries.map(([key, value]) => `${key.replaceAll('_', ' ')}: ${value}`).join(' · ')
}

function fmtDebugDuration(ms: number) {
  if (ms < 1000) return `${Math.max(0, ms)}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

// ---- Navigation (Part 4) ----

const TABS: { id: Tab; label: string; icon: typeof LayoutDashboard; countKey?: keyof TabCounts }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings', icon: ShieldAlert, countKey: 'findings' },
  { id: 'components', label: 'Packages', icon: Boxes, countKey: 'components' },
  { id: 'vulns', label: 'Vulnerabilities', icon: Bug, countKey: 'vulns' },
  { id: 'licenses', label: 'Licenses', icon: Scale, countKey: 'licenses' },
  { id: 'graph', label: 'Graph', icon: Network },
  { id: 'threats', label: 'Threat Model', icon: Waypoints },
  { id: 'recon', label: 'Recon', icon: Radar },
  { id: 'agent', label: 'Agent', icon: Bot },
  { id: 'evidence', label: 'Evidence', icon: ShieldCheck },
  { id: 'settings', label: 'Settings', icon: SlidersHorizontal },
]

interface TabCounts {
  findings: number
  components: number
  vulns: number
  licenses: number
}

function TabBar({ tab, setTab, counts }: { tab: Tab; setTab: (t: Tab) => void; counts: TabCounts }) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-border">
      {TABS.map(({ id, label, icon: Icon, countKey }) => {
        const active = tab === id
        const count = countKey ? counts[countKey] : undefined
        return (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              '-mb-px inline-flex items-center gap-2 whitespace-nowrap rounded-t-md border-b-2 px-3.5 py-2.5 text-sm font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40',
              active ? 'border-brand text-foreground' : 'border-transparent text-mutedfg hover:text-foreground',
            )}
          >
            <Icon className="size-4" />
            {label}
            {count !== undefined && count > 0 && (
              <span className="rounded-full bg-brand/15 px-1.5 text-xs font-medium tabular-nums text-branddim">
                {count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

// ---- Overview (Part 2): organized around decisions, top to bottom ----

function OverviewTab({
  findings,
  scan,
  job,
  onSelectSeverity,
  onGoTab,
}: {
  findings: Finding[] | null
  scan: ScanResult | null
  job: ScanJob | null
  onSelectSeverity: (s: Severity | 'all') => void
  onGoTab: (t: Tab) => void
}) {
  if (!scan) {
    return (
      <EmptyState
        icon={LayoutDashboard}
        title="No scan yet"
        hint="Run a scan above — this overview will show what’s risky, what to fix first, and where it came from."
      />
    )
  }
  const open = findings ?? []
  return (
    <div className="space-y-6">
      <ScanHealth scan={scan} job={job} />
      <FindingQualityStrip scan={scan} />
      <WhatNeedsAttention findings={open} scan={scan} onSelectSeverity={onSelectSeverity} onGoTab={onGoTab} />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <RemediationTargets scan={scan} onGoTab={onGoTab} />
        <VulnDistribution findings={open} loading={findings === null} onSelectSeverity={onSelectSeverity} />
      </div>
      <ProjectComposition scan={scan} onGoTab={onGoTab} />
      <ProvenanceCard scan={scan} />
    </div>
  )
}

// FindingQualityStrip: raw vs actionable vs background, before any
// vuln count — so a flood of example/test findings never reads as headline risk.
function FindingQualityStrip({ scan }: { scan: ScanResult }) {
  const q = scan.findingQuality
  if (q.rawFindings === 0) return null
  const byP = q.byPriority || {}
  return (
    <Card title="Finding quality">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <QualityTile label="Raw findings" value={q.rawFindings} />
        <QualityTile label="Actionable" value={q.actionable} accent />
        <QualityTile label="Background" value={q.background} muted />
        <QualityTile label="Production" value={q.production} />
        <QualityTile label="Development" value={q.development} muted />
        <QualityTile label="Example/Test" value={q.exampleTest} muted />
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-mutedfg">
        <span>Risk priority:</span>
        {[1, 2, 3, 4, 5].map((p) =>
          byP[String(p)] ? (
            <span key={p} className="font-mono tabular-nums">
              <span className={cn('font-semibold', p <= 2 ? 'text-critical' : p === 3 ? 'text-medium' : 'text-subtlefg')}>
                P{p}
              </span>
              : {byP[String(p)]}
            </span>
          ) : null,
        )}
        <span className="text-subtlefg">
          · version cov {q.versionCoveragePct.toFixed(0)}% · path cov {q.pathCoveragePct.toFixed(0)}%
        </span>
      </div>
    </Card>
  )
}

function QualityTile({ label, value, accent, muted }: { label: string; value: number; accent?: boolean; muted?: boolean }) {
  return (
    <div className="rounded-lg border border-border bg-bg py-2.5 text-center">
      <div
        className={cn(
          'font-mono text-xl font-semibold tabular-nums',
          accent ? 'text-accent' : muted ? 'text-subtlefg' : 'text-foreground',
        )}
      >
        {value}
      </div>
      <div className="text-[11px] text-mutedfg">{label}</div>
    </div>
  )
}

// Section 1 — Scan Health.
function ScanHealth({ scan, job }: { scan: ScanResult; job: ScanJob | null }) {
  const status = job?.status ?? 'succeeded'
  const statusLabelText = status === 'running' ? 'Running' : status === 'failed' ? 'Failed' : 'Complete'
  const statusTone = status === 'running' ? 'brand' : status === 'failed' ? 'critical' : 'accent'
  const confident = scan.completeness.confident
  const source = (scan.vulnDBSnapshot.split('@')[0] || 'osv.dev').replace(/\.dev$/, '').toUpperCase()
  return (
    <Card title="Scan health" bodyClass="p-0">
      <div className="grid grid-cols-2 divide-x divide-y divide-border sm:grid-cols-3 lg:grid-cols-5 lg:divide-y-0">
        <HealthStat icon={CheckCircle2} label="Status" value={statusLabelText} tone={statusTone} />
        <HealthStat
          icon={Clock}
          label="Duration"
          value={status === 'running' ? 'in progress' : fmtDuration(job?.startedAt ?? null, job?.finishedAt ?? null)}
        />
        <HealthStat
          icon={GaugeCircle}
          label="Confidence"
          value={confident ? 'High' : 'Partial'}
          tone={confident ? 'accent' : 'medium'}
        />
        <HealthStat
          icon={FileClock}
          label="Lockfiles"
          value={scan.completeness.lockfiles.length || '0'}
          tone={scan.completeness.lockfiles.length === 0 ? 'medium' : undefined}
          hint={scan.completeness.lockfiles.join(', ')}
        />
        <HealthStat icon={Database} label="Sources" value={source} />
      </div>
    </Card>
  )
}

function HealthStat({
  icon: Icon,
  label,
  value,
  tone,
  hint,
}: {
  icon: typeof Clock
  label: string
  value: ReactNode
  tone?: 'accent' | 'critical' | 'medium' | 'brand'
  hint?: string
}) {
  const toneText =
    tone === 'accent'
      ? 'text-accent'
      : tone === 'critical'
        ? 'text-critical'
        : tone === 'medium'
          ? 'text-medium'
          : tone === 'brand'
            ? 'text-brand'
            : 'text-foreground'
  return (
    <div className="px-5 py-4" title={hint ?? (typeof value === 'string' ? value : undefined)}>
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-mutedfg">
        <Icon className="size-3.5" />
        {label}
      </div>
      <div className={cn('mt-1 truncate text-lg font-semibold tabular-nums', toneText)}>{value}</div>
    </div>
  )
}

// Section 2 — What Needs Attention (the most important section; before composition).
function WhatNeedsAttention({
  findings,
  scan,
  onSelectSeverity,
  onGoTab,
}: {
  findings: Finding[]
  scan: ScanResult
  onSelectSeverity: (s: Severity | 'all') => void
  onGoTab: (t: Tab) => void
}) {
  // Count only actionable third-party findings — first-party historical advisories
  // (unversioned own modules) never inflate the headline risk.
  const tp = findings.filter((f) => f.class !== 'first_party_historical')
  const critical = tp.filter((f) => f.severity === 'critical').length
  const high = tp.filter((f) => f.severity === 'high').length
  const denied = scan.licenses.filter((l) => l.verdict === 'deny').length
  const componentsAtRisk = new Set(
    scan.vulnerabilities.filter((v) => !v.unversioned).map((v) => v.component),
  ).size
  return (
    <section>
      <h2 className="mb-3 text-sm font-semibold text-foreground">What needs attention</h2>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <AttentionCard
          label="Critical findings"
          value={critical}
          tone="critical"
          onClick={() => onSelectSeverity('critical')}
        />
        <AttentionCard label="High findings" value={high} tone="high" onClick={() => onSelectSeverity('high')} />
        <AttentionCard
          label="License violations"
          value={denied}
          tone={denied > 0 ? 'critical' : 'neutral'}
          onClick={() => onGoTab('licenses')}
        />
        <AttentionCard
          label="Packages at risk"
          value={componentsAtRisk}
          tone="neutral"
          onClick={() => onGoTab('components')}
        />
      </div>
    </section>
  )
}

function AttentionCard({
  label,
  value,
  tone,
  onClick,
}: {
  label: string
  value: number
  tone: 'critical' | 'high' | 'neutral'
  onClick: () => void
}) {
  const zero = value === 0
  const accentBar = tone === 'critical' ? 'bg-critical' : tone === 'high' ? 'bg-high' : 'bg-border'
  const valText = zero
    ? 'text-subtlefg'
    : tone === 'critical'
      ? 'text-critical'
      : tone === 'high'
        ? 'text-high'
        : 'text-foreground'
  return (
    <button
      onClick={onClick}
      className={cn(
        'lift elev group relative overflow-hidden rounded-xl border border-border bg-card p-4 text-left transition-colors hover:border-borderstrong',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
      )}
    >
      <div className={cn('absolute inset-x-0 top-0 h-0.5', accentBar)} />
      <div className="flex items-center justify-between">
        <span className="text-xs text-mutedfg">{label}</span>
        <ChevronRight className="size-4 text-subtlefg transition-transform group-hover:translate-x-0.5" />
      </div>
      <div className={cn('mt-2 font-mono text-3xl font-semibold tabular-nums', valText)}>{value}</div>
    </button>
  )
}

interface RemTarget {
  component: string
  version: string
  count: number
  critical: number
  high: number
  top: Severity
  maxEpss: number
  hasFix: boolean
}

function remediationTargets(scan: ScanResult): RemTarget[] {
  const map = new Map<string, RemTarget>()
  for (const v of scan.vulnerabilities) {
    if (v.unversioned) continue // first-party historical: not a remediation target
    const cur =
      map.get(v.component) ??
      ({
        component: v.component,
        version: v.version,
        count: 0,
        critical: 0,
        high: 0,
        top: 'unknown' as Severity,
        maxEpss: 0,
        hasFix: false,
      } satisfies RemTarget)
    cur.count++
    if (v.severity === 'critical') cur.critical++
    if (v.severity === 'high') cur.high++
    if (sevRank(v.severity) > sevRank(cur.top)) cur.top = v.severity
    if (v.epss > cur.maxEpss) cur.maxEpss = v.epss
    if (v.fixedVersion) cur.hasFix = true
    map.set(v.component, cur)
  }
  return [...map.values()]
    .sort(
      (a, b) =>
        b.critical - a.critical ||
        sevRank(b.top) - sevRank(a.top) ||
        b.count - a.count ||
        b.maxEpss - a.maxEpss,
    )
    .slice(0, 5)
}

// Section 3 — Top Remediation Targets: what to fix first.
function RemediationTargets({ scan, onGoTab }: { scan: ScanResult; onGoTab: (t: Tab) => void }) {
  const targets = useMemo(() => remediationTargets(scan), [scan])
  return (
    <Card
      title="Top remediation targets"
      actions={
        targets.length > 0 && (
          <button
            onClick={() => onGoTab('findings')}
            className="rounded text-xs text-branddim transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
          >
            All findings →
          </button>
        )
      }
    >
      {targets.length === 0 ? (
        <CardEmpty icon={CheckCircle2} text="No vulnerable packages — nothing to remediate." />
      ) : (
        <ol className="space-y-2.5">
          {targets.map((t, i) => (
            <li key={t.component} className="flex items-center gap-3">
              <span className="w-4 shrink-0 text-center font-mono text-xs text-subtlefg">{i + 1}</span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate font-medium text-foreground" title={`${t.component}@${t.version}`}>
                    {t.component}
                  </span>
                  {t.hasFix && <Pill className="bg-accent/12 text-accent ring-1 ring-inset ring-accent/25">fix</Pill>}
                </div>
                <div className="mt-0.5 text-xs text-mutedfg">
                  {t.count} finding{t.count === 1 ? '' : 's'}
                  {t.maxEpss > 0 && <span className="text-subtlefg"> · EPSS {(t.maxEpss * 100).toFixed(0)}%</span>}
                </div>
              </div>
              <div className="flex shrink-0 items-center gap-1.5">
                {t.critical > 0 && <CountBadge n={t.critical} sev="critical" />}
                {t.high > 0 && <CountBadge n={t.high} sev="high" />}
                {t.critical === 0 && t.high === 0 && <SevBadge sev={t.top} />}
              </div>
            </li>
          ))}
        </ol>
      )}
    </Card>
  )
}

function CountBadge({ n, sev }: { n: number; sev: Severity }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold tabular-nums ring-1 ring-inset',
        sev === 'critical' ? 'bg-critical/10 text-critical ring-critical/25' : 'bg-high/10 text-high ring-high/25',
      )}
    >
      {n} {sev === 'critical' ? 'crit' : 'high'}
    </span>
  )
}

// Section 4 — Vulnerability Distribution (clickable → filtered findings).
function VulnDistribution({
  findings,
  loading,
  onSelectSeverity,
}: {
  findings: Finding[]
  loading: boolean
  onSelectSeverity: (s: Severity | 'all') => void
}) {
  const rows = SEVERITY_ORDER.map((sev) => ({ sev, count: findings.filter((f) => f.severity === sev).length })).filter(
    (r) => r.count > 0 || ['critical', 'high', 'medium', 'low'].includes(r.sev),
  )
  const max = Math.max(1, ...rows.map((r) => r.count))
  return (
    <Card title="Findings by severity">
      {loading ? (
        <Spinner />
      ) : findings.length === 0 ? (
        <CardEmpty icon={CheckCircle2} text="No findings promoted from this scan." />
      ) : (
        <div className="space-y-2">
          {rows.map(({ sev, count }) => (
            <button
              key={sev}
              onClick={() => onSelectSeverity(sev)}
              disabled={count === 0}
              className={cn(
                'flex w-full items-center gap-3 rounded-md px-1.5 py-1 text-left transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
                count > 0 ? 'hover:bg-elevated' : 'cursor-default opacity-60',
              )}
            >
              <span className={cn('w-16 text-[11px] font-semibold uppercase tracking-wide', sevText[sev])}>{sev}</span>
              <div className="h-2 flex-1 overflow-hidden rounded bg-elevated">
                <div className={cn('bar-grow h-full rounded', sevFill[sev])} style={{ width: `${(count / max) * 100}%` }} />
              </div>
              <span className="w-7 text-right font-mono text-sm tabular-nums text-mutedfg">{count}</span>
            </button>
          ))}
        </div>
      )}
    </Card>
  )
}

// Section 5 — Project Composition (informational, lower).
function ProjectComposition({ scan, onGoTab }: { scan: ScanResult; onGoTab: (t: Tab) => void }) {
  const langs = scan.languages.slice().sort((a, b) => b.percent - a.percent)
  return (
    <Card title="Project composition">
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div>
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-mutedfg">Languages</div>
          {langs.length === 0 ? (
            <p className="text-sm text-subtlefg">No source languages detected.</p>
          ) : (
            <div className="space-y-2">
              {langs.slice(0, 6).map((l) => (
                <div key={l.name} className="flex items-center gap-2 text-sm">
                  <Code2 className="size-3.5 text-mutedfg" />
                  <span className="flex-1">{l.name}</span>
                  <span className="font-mono text-xs tabular-nums text-mutedfg">{l.percent.toFixed(1)}%</span>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="grid grid-cols-3 gap-2">
          <CompTile icon={Boxes} label="packages" value={scan.components.length} onClick={() => onGoTab('components')} />
          <CompTile icon={Scale} label="licenses" value={scan.licenses.length} onClick={() => onGoTab('licenses')} />
          <CompTile icon={Network} label="dep. edges" value={countEdges(scan)} onClick={() => onGoTab('graph')} />
        </div>
      </div>
    </Card>
  )
}

function CompTile({
  icon: Icon,
  label,
  value,
  onClick,
}: {
  icon: typeof Boxes
  label: string
  value: number
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="flex flex-col items-center justify-center gap-1 rounded-lg border border-border bg-bg py-3 transition-colors hover:border-borderstrong hover:bg-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
    >
      <Icon className="size-4 text-mutedfg" />
      <span className="font-mono text-lg font-semibold tabular-nums text-foreground">{value}</span>
      <span className="text-[11px] text-mutedfg">{label}</span>
    </button>
  )
}

// Section 6 — Provenance (audit info, bottom).
function ProvenanceCard({ scan }: { scan: ScanResult }) {
  const m = scan.manifest
  const repro = m.reproScore
  const tone = repro >= 85 ? 'text-accent' : repro >= 60 ? 'text-medium' : 'text-critical'
  return (
    <Card title="Provenance & reproducibility">
      {/* Reproducibility score: how much of the result is version-pinned. */}
      <div className="mb-4 flex items-center justify-between rounded-lg border border-border bg-bg p-3">
        <div>
          <div className="text-xs text-mutedfg">Reproducibility</div>
          <div className={cn('font-mono text-2xl font-semibold tabular-nums', tone)}>{repro}%</div>
        </div>
        <div className="max-w-[60%] text-right text-[11px] text-mutedfg">
          {m.pinnedInputs.length > 0 && (
            <div>
              pinned: <span className="text-foreground">{m.pinnedInputs.join(', ')}</span>
            </div>
          )}
          {m.unpinnedInputs.length > 0 && (
            <div className="mt-0.5">
              live: <span className="text-medium">{m.unpinnedInputs.join(', ')}</span>
            </div>
          )}
        </div>
      </div>
      <div className="grid grid-cols-1 gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
        {Object.entries(scan.toolVersions).map(([k, v]) => (
          <div key={k} className="flex items-center justify-between gap-3 border-b border-border/60 pb-1.5">
            <span className="flex items-center gap-1.5 text-mutedfg">
              <Wrench className="size-3 text-subtlefg" />
              {k}
            </span>
            <span className="truncate font-mono text-xs tabular-nums">{v}</span>
          </div>
        ))}
        <div className="flex items-center justify-between gap-3 border-b border-border/60 pb-1.5">
          <span className="flex items-center gap-1.5 text-mutedfg">
            <Database className="size-3 text-subtlefg" />
            vuln DB
          </span>
          <span className="truncate font-mono text-xs">{scan.vulnDBSnapshot || '—'}</span>
        </div>
        {m.sbomSha256 && (
          <div className="flex items-center justify-between gap-3 border-b border-border/60 pb-1.5">
            <span className="flex items-center gap-1.5 text-mutedfg">
              <FileClock className="size-3 text-subtlefg" />
              SBOM sha256
            </span>
            <span className="truncate font-mono text-xs" title={m.sbomSha256}>
              {m.sbomSha256.slice(0, 12)}
            </span>
          </div>
        )}
      </div>
    </Card>
  )
}

function CardEmpty({ icon: Icon, text }: { icon: typeof Boxes; text: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-6 text-center">
      <Icon className="size-6 text-subtlefg" />
      <p className="text-sm text-mutedfg">{text}</p>
    </div>
  )
}

// ---- Findings (Part 4: raw vulnerabilities folded in as expandable detail) ----

function vulnKey(v: Vulnerability): string {
  return `vuln:${v.id}:${v.component}:${v.version}`
}

// shortPkg turns a component identity (PURL or name@version) into a bare name.
function shortPkg(id: string): string {
  const last = id.split('/').pop() ?? id
  return last.split('@')[0] || last
}

function FindingsTab({
  findings,
  scan,
  engagementId,
  filter,
  setFilter,
  onUpdated,
  onReload,
}: {
  findings: Finding[] | null
  scan: ScanResult | null
  engagementId: string
  filter: Severity | 'all'
  setFilter: (v: Severity | 'all') => void
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [view, setView] = useState<'table' | 'board'>('table')
  const [creating, setCreating] = useState(false)
  const [kindFilter, setKindFilter] = useState<string>('all') // filter by finding Kind
  const vulnByKey = useMemo(() => {
    const m = new Map<string, Vulnerability>()
    for (const v of scan?.vulnerabilities ?? []) m.set(vulnKey(v), v)
    return m
  }, [scan])

  if (findings === null) return <Spinner label="Loading findings…" />

  // Separate actionable third-party findings from first-party historical advisories
  // — the table shows only actionable findings.
  const thirdParty = findings.filter((f) => f.class !== 'first_party_historical')
  const historical = findings.filter((f) => f.class === 'first_party_historical')
  const available = new Set(thirdParty.map((f) => f.severity))
  // The Kinds present — the Kind filter only appears when there's more than one to choose from.
  const kinds = Array.from(new Set(thirdParty.map((f) => f.kind).filter(Boolean)))
  // findings arrive already risk-ordered (KEV -> EPSS x CVSS) from the API.
  const rows = thirdParty.filter(
    (f) => (filter === 'all' || f.severity === filter) && (kindFilter === 'all' || f.kind === kindFilter),
  )

  function toggle(id: string) {
    setExpanded((cur) => {
      const next = new Set(cur)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <FindingsViewToggle view={view} onChange={setView} />
        <div className="flex items-center gap-2">
          {historical.length > 0 && (
            <span
              className="inline-flex items-center gap-1.5 rounded-md bg-muted px-2 py-1 text-xs text-mutedfg"
              title="Advisories matched against the project's own unversioned modules — cannot be confirmed, excluded from remediation."
            >
              <FileClock className="size-3.5" />
              {historical.length} historical
            </span>
          )}
          <Button variant="secondary" onClick={() => setCreating((c) => !c)} className="px-3 py-1.5">
            <Plus className="size-4" /> New finding
          </Button>
        </div>
      </div>
      {creating && (
        <NewFindingForm
          engagementId={engagementId}
          onCreated={() => {
            setCreating(false)
            onReload()
          }}
          onCancel={() => setCreating(false)}
        />
      )}
      {findings.length === 0 ? (
        <EmptyState icon={CheckCircle2} title="No findings yet" hint="Run a scan, or add a manual finding above." />
      ) : view === 'board' ? (
        <FindingsBoard findings={thirdParty} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
      ) : (
        <Card bodyClass="p-0">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border p-4">
            <SeverityFilter value={filter} onChange={setFilter} available={available} />
            {kinds.length > 1 && <KindFilter value={kindFilter} onChange={setKindFilter} kinds={kinds} />}
          </div>
      {rows.length === 0 && (
        <div className="p-6 text-center text-sm text-mutedfg">
          No actionable third-party findings
          {filter !== 'all' ? ` at ${filter}` : ''}
          {kindFilter !== 'all' ? ` of kind ${findingKindLabel(kindFilter)}` : ''}.
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[11px] uppercase tracking-wider text-subtlefg">
              <th className="w-8" />
              <th className="px-2 py-2 font-semibold">Pri</th>
              <th className="px-2 py-2 font-semibold">Severity</th>
              <th className="px-4 py-2 font-semibold">Finding</th>
              <th className="px-4 py-2 font-semibold">Scope</th>
              <th className="px-4 py-2 font-semibold">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => {
              const v = vulnByKey.get(f.dedupKey)
              const isOpen = expanded.has(f.id)
              return (
                <Fragment key={f.id}>
                  <tr
                    onClick={() => toggle(f.id)}
                    className="cursor-pointer border-t border-border transition-colors hover:bg-elevated"
                  >
                    <td className="pl-3 align-top">
                      <button
                        type="button"
                        aria-expanded={isOpen}
                        aria-label={`Toggle advisory detail for ${f.title}`}
                        onClick={(e) => {
                          e.stopPropagation()
                          toggle(f.id)
                        }}
                        className="rounded p-1 text-subtlefg transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
                      >
                        <ChevronRight className={cn('size-4 transition-transform', isOpen && 'rotate-90')} />
                      </button>
                    </td>
                    <td className="px-2 py-2 align-top">
                      <PriorityBadge priority={f.priority} />
                    </td>
                    <td className="px-2 py-2 align-top">
                      <SevBadge sev={f.severity} />
                    </td>
                    <td className="px-4 py-2 align-top">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-foreground">{f.title}</span>
                        {f.kev && <KevBadge />}
                        {f.kind && f.kind !== 'sca' && <KindBadge kind={f.kind} />}
                        {f.cwe && <span className="font-mono text-[11px] tabular-nums text-subtlefg">{f.cwe}</span>}
                        {v && !v.direct && v.path.length >= 2 && (
                          <span className="text-xs text-subtlefg" title={v.path.map(shortPkg).join(' › ')}>
                            via {shortPkg(v.path[v.path.length - 2])}
                          </span>
                        )}
                      </div>
                      {f.description && !isOpen && (
                        <div className="mt-0.5 line-clamp-1 text-xs text-mutedfg">{f.description}</div>
                      )}
                    </td>
                    <td className="px-4 py-2 align-top">
                      <ScopeBadge scope={f.scope} />
                    </td>
                    <td className="px-4 py-2 align-top" onClick={(e) => e.stopPropagation()}>
                      <FindingStatusControl finding={f} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="border-t border-border/50 bg-bg/40">
                      <td />
                      <td colSpan={5} className="px-4 py-3">
                        <FindingDetail finding={f} vuln={v} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
          </div>
        </Card>
      )}
    </div>
  )
}

// frameworkShort renders a compact label for a compliance framework id.
function frameworkShort(framework: string): string {
  switch (framework) {
    case 'OWASP-2021':
      return 'OWASP'
    case 'PCI-DSS-4.0':
      return 'PCI DSS'
    case 'ISO-27001-2022':
      return 'ISO 27001'
    default:
      return framework
  }
}

// ComplianceChips lists the curated regulatory/standard controls a finding's CWE maps to.
// Deterministic, server-computed reference data (compliance.ControlsFor) — advisory context only,
// never a gate. Renders nothing when the CWE maps to no controls (the common case for non-code kinds).
function ComplianceChips({ controls }: { controls: Finding['complianceControls'] }) {
  if (!controls || controls.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="list" aria-label="Compliance controls">
      <BadgeCheck aria-hidden className="size-3.5 shrink-0 text-subtlefg" />
      <span aria-hidden className="text-[11px] uppercase tracking-wide text-subtlefg">Compliance</span>
      {controls.map((c) => (
        <span
          key={`${c.framework}:${c.id}`}
          role="listitem"
          className="inline-flex items-center gap-1.5 rounded-md bg-elevated px-2 py-0.5 text-xs ring-1 ring-inset ring-border"
        >
          <span className="text-subtlefg">{frameworkShort(c.framework)}</span>
          <span className="font-mono tabular-nums text-foreground">{c.id}</span>
          <span className="text-mutedfg">{c.title}</span>
        </span>
      ))}
    </div>
  )
}

// JudgmentStateBadge shows a judgment's lifecycle state (proposed = unverified AI output, confirmed
// = human-ratified, refuted = a verifier rejected it) as a text+color chip — never color alone.
function JudgmentStateBadge({ state }: { state: string }) {
  const tone =
    state === 'confirmed'
      ? 'text-accent ring-accent/30 bg-accent/10'
      : state === 'refuted'
        ? 'text-medium ring-medium/30 bg-medium/10'
        : 'text-mutedfg ring-border bg-muted'
  return (
    <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide ring-1 ring-inset ${tone}`}>
      {state}
    </span>
  )
}

// RiskNarrative (ungated) explains a finding's computed priority via closed driver tokens —
// never free prose (R8); the priority mirrors the Go-computed value.
function RiskNarrative({ j }: { j: Judgment }) {
  const c = j.claim as Partial<RiskNarrativeClaim>
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-foreground">Risk narrative</span>
        <JudgmentStateBadge state={j.state} />
        {typeof c.priority === 'number' && (
          <span className="font-mono text-xs tabular-nums text-mutedfg">priority {c.priority}/5</span>
        )}
      </div>
      {(c.drivers?.length ?? 0) > 0 && (
        <div className="flex flex-wrap gap-1">
          {c.drivers!.map((d) => (
            <span
              key={d}
              className="rounded bg-elevated px-1.5 py-0.5 font-mono text-[11px] text-mutedfg ring-1 ring-inset ring-border"
            >
              {d}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

// Critique (gated) is an adversarial review of a finding — verdict + a closed driver token +
// confidence. A confirmed "refuted" critique is what drives the suspected-FP flag on the list.
function Critique({ j }: { j: Judgment }) {
  const c = j.claim as Partial<CritiqueClaim>
  const verdictTone = c.verdict === 'refuted' ? 'text-medium' : c.verdict === 'sound' ? 'text-accent' : 'text-mutedfg'
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-foreground">Critique</span>
        <JudgmentStateBadge state={j.state} />
        {c.verdict && <span className={`text-xs font-medium ${verdictTone}`}>{c.verdict}</span>}
        {typeof c.confidence === 'number' && (
          <span className="font-mono text-xs tabular-nums text-mutedfg">{c.confidence}% confidence</span>
        )}
      </div>
      {c.driver && <span className="font-mono text-[11px] text-mutedfg">{c.driver}</span>}
    </div>
  )
}

// Reachability (gated) surfaces a reachability verdict: whether the vulnerable symbol is reachable
// (reachable is the worse, attention-worthy state), the tier (a deterministic Tier-2 call-graph proof
// supersedes an LLM Tier-1.5), and the call-path proof chain. The state badge marks an unverified proposal.
function Reachability({ j }: { j: Judgment }) {
  const c = j.claim as Partial<ReachabilityClaim>
  const tone =
    c.reachable === 'reachable'
      ? 'text-critical ring-critical/30 bg-critical/10'
      : c.reachable === 'not_reachable'
        ? 'text-accent ring-accent/30 bg-accent/10'
        : 'text-mutedfg ring-border bg-muted'
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-foreground">Reachability</span>
        <JudgmentStateBadge state={j.state} />
        {c.reachable && (
          <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset ${tone}`}>
            {c.reachable.replace('_', ' ')}
          </span>
        )}
        {c.tier && <span className="font-mono text-[11px] tabular-nums text-subtlefg">{c.tier}</span>}
        {typeof c.confidence === 'number' && (
          <span className="font-mono text-xs tabular-nums text-mutedfg">{c.confidence}% confidence</span>
        )}
      </div>
      {(c.path?.length ?? 0) > 0 && (
        <div className="flex flex-wrap items-center gap-1 font-mono text-[11px] tabular-nums text-mutedfg">
          {c.path!.map((sym, i) => (
            <span key={i} className="flex items-center gap-1">
              {i > 0 && <ChevronRight aria-hidden className="size-3 text-subtlefg" />}
              <span>{sym}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

// ExplainJudgments surfaces the read-side "explain & advise" analysis judgments for a finding:
// the risk narrative, adversarial critiques, and the reachability verdict (AI-proposed or deterministic).
// Self-contained, best-effort fetch — it NEVER blocks or errors the finding detail (judgments disabled /
// load failure / none ⇒ renders nothing). The state badge keeps a "proposed" (unverified) judgment
// visibly distinct from a human-ratified or deterministically-proven one.
function ExplainJudgments({ engagementId, findingId }: { engagementId: string; findingId: string }) {
  const [judgments, setJudgments] = useState<Judgment[] | undefined>(undefined)
  useEffect(() => {
    let live = true
    setJudgments(undefined)
    api
      .judgments(engagementId)
      .then((js) => {
        if (live) setJudgments(js)
      })
      .catch(() => {
        if (live) setJudgments([]) // best-effort: the explain panel never surfaces an error
      })
    return () => {
      live = false
    }
  }, [engagementId])

  const relevant = (judgments ?? []).filter(
    (j) =>
      j.subjectId === findingId &&
      (j.capability === 'risk_narrative' || j.capability === 'critique' || j.capability === 'reachability'),
  )
  if (relevant.length === 0) return null

  return (
    <div className="space-y-2 rounded-lg border border-border bg-bg p-3">
      <div className="flex items-center gap-1.5">
        <Sparkles aria-hidden className="size-3.5 text-branddim" />
        <span className="text-[11px] uppercase tracking-wide text-subtlefg">Analysis</span>
      </div>
      <ul className="space-y-2" role="list">
        {relevant.map((j) => (
          <li key={j.id}>
            {j.capability === 'reachability' ? (
              <Reachability j={j} />
            ) : j.capability === 'critique' ? (
              <Critique j={j} />
            ) : (
              <RiskNarrative j={j} />
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

function FindingDetail({
  finding,
  vuln,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  vuln: Vulnerability | undefined
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  return (
    <div className="space-y-3">
      <FindingCollab finding={finding} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
      {finding.kind === 'exploitation' && (
        <EvidenceGate finding={finding} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
      )}
      {finding.description && <p className="whitespace-pre-line text-xs text-mutedfg">{finding.description}</p>}
      <ComplianceChips controls={finding.complianceControls} />
      {vuln ? (
        <>
          <div className="flex flex-wrap gap-x-6 gap-y-1.5 font-mono text-xs">
            <DetailKV label="CVSS" value={vuln.cvssScore > 0 ? vuln.cvssScore.toFixed(1) : '—'} />
            <DetailKV label="EPSS" value={vuln.epss > 0 ? `${(vuln.epss * 100).toFixed(1)}%` : '—'} />
            <DetailKV label="installed" value={`${vuln.component}@${vuln.version}`} />
            <DetailKV
              label="fixed in"
              value={vuln.fixedVersion || '—'}
              valueClass={vuln.fixedVersion ? 'text-accent' : 'text-subtlefg'}
            />
          </div>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-1.5 text-xs">
            <span className="flex items-center gap-2">
              <span className="text-[11px] uppercase tracking-wide text-subtlefg">detected by</span>
              <DetectedBy sources={vuln.sources} />
            </span>
            <span className="flex items-center gap-2">
              <span className="text-[11px] uppercase tracking-wide text-subtlefg">confidence</span>
              <ConfidenceBadge confidence={vuln.confidence} />
            </span>
          </div>
          {vuln.path.length > 1 && (
            <div className="text-xs">
              <span className="text-[11px] uppercase tracking-wide text-subtlefg">Dependency path</span>
              <div className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-mutedfg">
                {vuln.path.map((p, i) => (
                  <span key={i} className="flex items-center gap-1.5">
                    {i > 0 && <ChevronRight className="size-3 text-subtlefg" />}
                    <span className={i === vuln.path.length - 1 ? 'text-foreground' : ''}>{shortPkg(p)}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
          {vuln.direct && <p className="text-xs text-subtlefg">Direct dependency of the project.</p>}
        </>
      ) : (
        <p className="text-xs text-subtlefg">
          {finding.dedupKey.startsWith('license:') ? 'License-policy finding.' : 'No matching advisory detail in this scan.'}
        </p>
      )}
      <ExplainJudgments engagementId={engagementId} findingId={finding.id} />
    </div>
  )
}

// EVIDENCE_BAR mirrors the domain's finding.EvidenceThreshold (the server is authoritative): an
// exploitation finding is unproven + unreportable until a DISTINCT verifier raises its score to
// this bar.
const EVIDENCE_BAR = 75

// EvidenceGate is the finding-review panel for an agent-proposed exploitation finding: it
// shows who proposed it + its evidence score + the gate state, and lets a DISTINCT human verifier
// seal an adversarial verdict (which raises the score). The server rejects verifier == proposer
// and a machine role; a passing verdict makes the finding promotable (then a human confirms via
// the status control).
function EvidenceGate({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [open, setOpen] = useState(false)
  const [score, setScore] = useState(90)
  const [rationale, setRationale] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const proven = finding.evidenceScore >= EVIDENCE_BAR

  async function submit() {
    setBusy(true)
    setErr('')
    try {
      onUpdated(await api.verifyFinding(engagementId, finding.id, score, rationale.trim(), finding.version))
      setOpen(false)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setErr('This finding changed — reloading.')
        onReload()
      } else {
        setErr(e instanceof ApiError ? e.message : 'Verify failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="rounded-lg border border-border bg-bg p-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
        <span className="flex items-center gap-1.5">
          {proven ? (
            <ShieldCheck className="size-4 text-accent" />
          ) : (
            <ShieldQuestion className="size-4 text-medium" />
          )}
          <span className={cn('font-medium', proven ? 'text-accent' : 'text-medium')}>
            {proven ? 'Verified — reportable' : 'Unproven — not reportable'}
          </span>
        </span>
        <DetailKV label="evidence" value={`${finding.evidenceScore}/${EVIDENCE_BAR}`} valueClass="font-mono tabular-nums" />
        {finding.proposedBy && <DetailKV label="proposed by" value={finding.proposedBy} />}
      </div>

      {!proven && (
        <div className="mt-2">
          {!open ? (
            <Button variant="secondary" onClick={() => setOpen(true)} className="px-2.5 py-1 text-xs">
              <ShieldCheck className="size-3.5" /> Verify finding
            </Button>
          ) : (
            <div className="space-y-2">
              <p className="text-[11px] text-subtlefg">
                Record an adversarial verdict. The verifier must be a different person than the proposer; the verdict is
                sealed into the evidence chain. A score ≥ {EVIDENCE_BAR} makes it promotable.
              </p>
              <label htmlFor="evidence-score-input" className="flex items-center gap-2 text-xs">
                <span className="text-subtlefg">Score</span>
                <input
                  id="evidence-score-input"
                  type="number"
                  min={0}
                  max={100}
                  value={score}
                  onChange={(e) => setScore(Math.max(0, Math.min(100, Number(e.target.value))))}
                  className="w-20 rounded border border-border bg-elevated px-2 py-1 font-mono tabular-nums text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40"
                />
              </label>
              <textarea
                value={rationale}
                onChange={(e) => setRationale(e.target.value)}
                placeholder="Rationale (how it was reproduced / refuted)"
                aria-label="Verdict rationale"
                rows={2}
                className="w-full rounded border border-border bg-elevated px-2 py-1 text-xs text-foreground placeholder:text-subtlefg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40"
              />
              {err && <p className="text-xs text-critical">{err}</p>}
              <div className="flex gap-2">
                <Button loading={busy} onClick={submit} className="px-2.5 py-1 text-xs">
                  Seal verdict
                </Button>
                <Button variant="ghost" onClick={() => setOpen(false)} className="px-2.5 py-1 text-xs">
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function DetailKV({ label, value, valueClass }: { label: string; value: string; valueClass?: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="text-[11px] uppercase tracking-wide text-subtlefg">{label}</span>
      <span className={cn('text-foreground', valueClass)}>{value}</span>
    </span>
  )
}

const FINDING_STATUSES = ['open', 'triage', 'confirmed', 'false_positive', 'remediated']

const STATUS_DOT: Record<string, string> = {
  open: 'bg-mutedfg',
  triage: 'bg-medium',
  confirmed: 'bg-critical',
  false_positive: 'bg-subtlefg',
  remediated: 'bg-accent',
}

const STATUS_TEXT: Record<string, string> = {
  open: 'text-mutedfg',
  triage: 'text-medium',
  confirmed: 'text-critical',
  false_positive: 'text-subtlefg',
  remediated: 'text-accent',
}

function StatusLabel({ status }: { status: string }) {
  return (
    <span className={cn('flex items-center gap-2', STATUS_TEXT[status] ?? 'text-mutedfg')}>
      <span className={cn('size-2 shrink-0 rounded-full', STATUS_DOT[status] ?? 'bg-mutedfg')} />
      {statusLabel(status)}
    </span>
  )
}

function FindingStatusControl({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<'' | 'failed' | 'conflict'>('')

  async function change(status: string) {
    if (status === finding.status) return
    setBusy(true)
    setNote('')
    try {
      onUpdated(await api.updateFindingStatus(engagementId, finding.id, status, finding.version))
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setNote('conflict')
        onReload() // someone else moved it — pull the latest
      } else {
        setNote('failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Select
        value={finding.status}
        onValueChange={change}
        disabled={busy}
        size="sm"
        ariaLabel={`Triage status for ${finding.title}`}
        className="min-w-[9.5rem]"
        options={FINDING_STATUSES.map((s) => ({ value: s, label: <StatusLabel status={s} /> }))}
      />
      {busy && <Loader2 className="size-3.5 shrink-0 animate-spin text-mutedfg" />}
      {note === 'failed' && <span className="text-xs text-critical">failed</span>}
      {note === 'conflict' && (
        <span className="inline-flex items-center gap-1 text-xs font-medium text-medium">
          <AlertTriangle className="size-3" /> reloaded
        </span>
      )}
    </div>
  )
}

// ---- Packages (formerly SBOM components) ----

function ComponentsTab({ scan }: { scan: ScanResult | null }) {
  if (!scan) return <ScanPrompt icon={Boxes} what="the component inventory" />
  if (scan.components.length === 0) {
    return <EmptyState icon={Boxes} title="No packages" hint="Syft found no packages in this target." />
  }
  const rows = scan.components.slice().sort((a, b) => a.name.localeCompare(b.name))
  return (
    <Card bodyClass="p-0">
      <VirtualTable
        items={rows}
        rowKey={(c, i) => `${c.purl}-${i}`}
        columns={[
          { header: 'Package', className: 'flex-1 font-medium text-foreground', cell: (c) => c.name },
          {
            header: 'Version',
            className: 'w-28 font-mono text-xs tabular-nums text-mutedfg',
            cell: (c) => c.version || '—',
          },
          {
            header: 'License',
            className: 'w-44 text-xs text-mutedfg',
            cell: (c) =>
              c.licenses.length === 0
                ? '—'
                : c.licenses.map((l) => l.spdxId || l.name).filter(Boolean).join(', ') || '—',
          },
          { header: 'PURL', className: 'flex-1 font-mono text-xs text-subtlefg', cell: (c) => c.purl || '—' },
        ]}
      />
    </Card>
  )
}

// ---- Vulnerabilities (complete advisory list, incl. sub-threshold not promoted to findings) ----

function packageVersionKey(component: string, version: string): string {
  return `${component}\x00${version}`
}

function vulnPackageKey(v: Vulnerability): string {
  return packageVersionKey(v.component, v.version)
}

// packageLocationMap groups each package@version to the distinct manifest locations it was
// declared in, so a vulnerability is counted once per place it actually ships.
function packageLocationMap(components: ScanResult['components']): Map<string, string[]> {
  const m = new Map<string, string[]>()
  for (const c of components) {
    const loc = c.location.trim()
    if (!loc) continue
    const key = packageVersionKey(c.name, c.version)
    const cur = m.get(key) ?? []
    if (!cur.includes(loc)) m.set(key, [...cur, loc])
  }
  return m
}

// countVulnerabilityFindings is the TRUE finding count the table renders: every advisory
// (CVE/GHSA/OSV — not just CVE) counted once per affected package@version per manifest
// location. This matches the rows on screen — not distinct packages, not distinct CVE ids.
function countVulnerabilityFindings(vulns: Vulnerability[], locations: Map<string, string[]>): number {
  let n = 0
  for (const v of vulns) {
    const locs = locations.get(vulnPackageKey(v))
    n += locs && locs.length > 0 ? locs.length : 1
  }
  return n
}

interface VulnerabilityDisplayRow {
  key: string
  component: string
  cve: string
  severity: Severity
  installed: string
  fixedVersion: string
  location: string
  direct: boolean
  via: string
  sourceLabel: string
  sourceFile: string
  relationshipLabel: string
  dependencyPath: string
  isFirstInPackage: boolean
  packageCveCount: number
}

const LOCKFILE_BASENAMES = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'gemfile.lock',
  'poetry.lock',
  'pipfile.lock',
  'uv.lock',
  'go.sum',
  'cargo.lock',
  'composer.lock',
  'packages.lock.json',
  'gradle.lockfile',
])

const MANIFEST_BASENAMES = new Set([
  'package.json',
  'go.mod',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'settings.gradle',
  'settings.gradle.kts',
  'requirements.txt',
  'requirements-dev.txt',
  'requirements-test.txt',
  'pyproject.toml',
  'pipfile',
  'cargo.toml',
  'gemfile',
  'composer.json',
  'packages.config',
  'csproj',
  'libs.versions.toml',
])

function basename(path: string): string {
  const normalized = path.replace(/\\/g, '/')
  return normalized.slice(normalized.lastIndexOf('/') + 1).toLowerCase()
}

function dependencySourceLabel(location: string): { label: string; file: string } {
  const file = location.trim()
  if (!file) return { label: 'SBOM / resolver', file: '' }
  const base = basename(file)
  if (LOCKFILE_BASENAMES.has(base)) return { label: 'Lockfile', file }
  if (MANIFEST_BASENAMES.has(base) || base.endsWith('.csproj') || base.endsWith('.fsproj') || base.endsWith('.vbproj')) {
    return { label: 'Manifest', file }
  }
  if (file.includes('node_modules/') || file.endsWith('.jar') || file.includes('/target/') || file.includes('/build/')) {
    return { label: 'Build output', file }
  }
  return { label: 'SBOM location', file }
}

function dependencyRelationshipLabel(direct: boolean, path: string[], via: string): string {
  if (direct) return 'Direct'
  if (via) return `Transitive via ${via}`
  if (path.length > 1) return 'Transitive'
  return 'Unknown path'
}

function vulnerabilityRowMatchesSearch(row: VulnerabilityDisplayRow, query: string): boolean {
  if (!query) return true
  return [
    row.component,
    row.cve,
    row.severity,
    row.installed,
    row.fixedVersion,
    row.location,
    row.sourceLabel,
    row.relationshipLabel,
    row.dependencyPath,
  ].some((value) => value.toLowerCase().includes(query))
}

function componentIdentity(name: string, version: string, purl: string): string {
  if (purl) return purl
  if (version) return `${name}@${version}`
  return name
}

function dependencyPathToRoot(dependencies: ScanResult['dependencies'], target: string): string[] {
  if (!target) return []
  const dependents = new Map<string, string[]>()
  const hasDependent = new Set<string>()
  const inGraph = new Set<string>()
  for (const dep of dependencies) {
    inGraph.add(dep.ref)
    for (const child of dep.dependsOn) {
      inGraph.add(child)
      hasDependent.add(child)
      dependents.set(child, [...(dependents.get(child) ?? []), dep.ref])
    }
  }
  if (!inGraph.has(target)) return []
  if (!hasDependent.has(target)) return [target]
  const seen = new Set([target])
  const queue: Array<{ id: string; path: string[] }> = [{ id: target, path: [target] }]
  while (queue.length) {
    const cur = queue.shift()!
    for (const parent of dependents.get(cur.id) ?? []) {
      if (seen.has(parent)) continue
      seen.add(parent)
      const path = [parent, ...cur.path]
      if (!hasDependent.has(parent)) return path
      queue.push({ id: parent, path })
    }
  }
  return [target]
}

function buildVulnerabilityDisplayRows(vulns: Vulnerability[], packageLocations: Map<string, string[]>): VulnerabilityDisplayRow[] {
  // Group rows by package, ordering packages (and CVEs within a package) by their FIRST
  // appearance in the already-risk-ordered (KEV -> EPSS x CVSS) input. Never re-rank by raw
  // CVSS severity — that would violate the risk-priority invariant.
  const packageOrder = new Map<string, number>()
  const cveOrder = new Map<string, number>()
  vulns.forEach((vuln, i) => {
    if (!packageOrder.has(vuln.component)) packageOrder.set(vuln.component, i)
    const ck = `${vuln.component}\x00${vuln.id}`
    if (!cveOrder.has(ck)) cveOrder.set(ck, i)
  })

  const rows = vulns.flatMap((vuln) => {
    const locations = packageLocations.get(vulnPackageKey(vuln)) ?? ['']
    return locations.map((location, index) => ({
      ...(() => {
        const via = vuln.path.length >= 2 ? shortPkg(vuln.path[vuln.path.length - 2]) : ''
        const source = dependencySourceLabel(location)
        return {
          key: `${vuln.id}\x00${vuln.component}\x00${vuln.version}\x00${vuln.fixedVersion}\x00${location}\x00${index}`,
          component: vuln.component,
          cve: vuln.id,
          severity: vuln.severity,
          installed: vuln.version,
          fixedVersion: vuln.fixedVersion,
          location,
          direct: vuln.direct,
          via,
          sourceLabel: source.label,
          sourceFile: source.file,
          relationshipLabel: dependencyRelationshipLabel(vuln.direct, vuln.path, via),
          dependencyPath: vuln.path.map(shortPkg).join(' › '),
          isFirstInPackage: false,
        }
      })(),
    }))
  })

  rows.sort((a, b) => {
    const pkgDelta = (packageOrder.get(a.component) ?? 0) - (packageOrder.get(b.component) ?? 0)
    if (pkgDelta !== 0) return pkgDelta
    const cveDelta =
      (cveOrder.get(`${a.component}\x00${a.cve}`) ?? 0) - (cveOrder.get(`${b.component}\x00${b.cve}`) ?? 0)
    if (cveDelta !== 0) return cveDelta
    // same CVE expanded across install paths/locations — stable, deterministic tiebreak
    return a.installed.localeCompare(b.installed) || a.location.localeCompare(b.location)
  })

  const packageCves = new Map<string, Set<string>>()
  for (const row of rows) {
    const cves = packageCves.get(row.component) ?? new Set<string>()
    cves.add(row.cve)
    packageCves.set(row.component, cves)
  }

  let previousPackage = ''
  return rows.map((row) => {
    const isFirstInPackage = row.component !== previousPackage
    previousPackage = row.component
    return { ...row, isFirstInPackage, packageCveCount: packageCves.get(row.component)?.size ?? 0 }
  })
}

function VulnsTab({ scan }: { scan: ScanResult | null }) {
  const [filter, setFilter] = useState<Severity | 'all'>('all')
  const [search, setSearch] = useState('')
  const available = useMemo(() => new Set((scan?.vulnerabilities ?? []).map((v) => v.severity)), [scan?.vulnerabilities])
  // vulnerabilities arrive already risk-ordered (KEV -> EPSS x CVSS) from the API.
  const severityRows = useMemo(
    () => (scan?.vulnerabilities ?? []).filter((v) => filter === 'all' || v.severity === filter),
    [filter, scan?.vulnerabilities],
  )
  const packageLocations = useMemo(() => packageLocationMap(scan?.components ?? []), [scan?.components])
  const allSeverityDisplayRows = useMemo(() => buildVulnerabilityDisplayRows(severityRows, packageLocations), [packageLocations, severityRows])
  const query = search.trim().toLowerCase()
  const displayRows = useMemo(
    () => allSeverityDisplayRows.filter((row) => vulnerabilityRowMatchesSearch(row, query)),
    [allSeverityDisplayRows, query],
  )
  const shownPackages = new Set(displayRows.map((row) => packageVersionKey(row.component, row.installed))).size
  // Counts MUST equal the rows actually rendered: every advisory×package×location (incl.
  // non-CVE advisories), not distinct CVE ids — otherwise the headline undercounts the table.
  const shownAdvisories = displayRows.length
  const totalAdvisories = allSeverityDisplayRows.length
  const vulnColumns = useMemo<Column<VulnerabilityDisplayRow>[]>(
    () => [
      {
        header: 'Package',
        className: 'sticky left-0 z-10 w-64 bg-card pr-2 font-mono text-xs text-foreground',
        cell: (row) => (
          <div
            className={cn(
              'rounded-md px-2 py-1',
              row.isFirstInPackage ? 'bg-elevated/80 ring-1 ring-border/80' : 'select-none text-transparent',
            )}
            title={row.component}
          >
            <div className="truncate">{row.component}</div>
            {row.isFirstInPackage && (
              <div className="mt-0.5 font-sans text-[10px] uppercase tracking-wide text-subtlefg">
                {row.packageCveCount.toLocaleString()} advisor{row.packageCveCount === 1 ? 'y' : 'ies'}
              </div>
            )}
          </div>
        ),
      },
      {
        header: 'Severity',
        className: 'w-24',
        cell: (row) => <SevBadge sev={row.severity} />,
      },
      {
        header: 'Advisory',
        className: 'w-44',
        cell: (row) => (
          <span
            className={cn(
              'inline-flex w-fit rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold ring-1 ring-inset',
              sevSoft[row.severity],
            )}
          >
            {row.cve}
          </span>
        ),
      },
      {
        header: 'Installed',
        className: 'w-28 font-mono text-xs',
        cell: (row) => (
          <span className="truncate text-critical" title={`${row.component}@${row.installed || 'unknown'}`}>
            {row.installed || 'unknown'}
          </span>
        ),
      },
      {
        header: 'Fixed Version',
        className: 'w-32 font-mono text-xs',
        cell: (row) =>
          row.fixedVersion ? <span className="text-accent">{row.fixedVersion}</span> : <span className="text-subtlefg">—</span>,
      },
      {
        header: 'Source / Path',
        className: 'w-80 text-xs',
        cell: (row) => {
          const title = [
            row.sourceFile ? `${row.sourceLabel}: ${row.sourceFile}` : row.sourceLabel,
            row.dependencyPath ? `Path: ${row.dependencyPath}` : row.relationshipLabel,
          ].join('\n')
          return (
            <div className="min-w-0 space-y-1" title={title}>
              <div className="flex min-w-0 items-center gap-2">
                <span className="shrink-0 rounded-md bg-elevated px-1.5 py-0.5 font-mono text-[10px] uppercase text-mutedfg ring-1 ring-border/70">
                  {row.sourceLabel}
                </span>
                <span className="truncate font-mono text-[11px] text-subtlefg">{row.sourceFile || 'no source file'}</span>
              </div>
              <div className="truncate text-mutedfg">
                {row.relationshipLabel}
                {row.dependencyPath && <span className="text-subtlefg"> · {row.dependencyPath}</span>}
              </div>
            </div>
          )
        },
      },
    ],
    [],
  )

  if (!scan) return <ScanPrompt icon={Bug} what="vulnerabilities" />
  if (scan.scanMode === 'licenses') {
    return <EmptyState icon={Scale} title="Vulnerabilities skipped" hint="This run used license-only scan mode." />
  }
  if (scan.vulnerabilities.length === 0) {
    return (
      <EmptyState
        icon={CheckCircle2}
        title="No known vulnerabilities"
        hint="OSV reported no advisories for these packages."
      />
    )
  }
  return (
    <Card bodyClass="p-0">
      <div className="space-y-3 border-b border-border p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <SeverityFilter value={filter} onChange={setFilter} available={available} />
          <div className="flex flex-wrap items-center justify-end gap-2">
            <input
              value={search}
              onChange={(event) => setSearch(event.currentTarget.value)}
              placeholder="Search CVE, package, source, path…"
              aria-label="Search vulnerabilities"
              className="h-8 w-72 rounded-md border border-border bg-elevated px-2 text-xs text-foreground placeholder:text-subtlefg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40"
            />
          </div>
        </div>
        <div className="grid gap-2 text-xs text-mutedfg tabular-nums sm:grid-cols-2 xl:grid-cols-3">
          <div className="rounded-md bg-elevated/60 px-3 py-2 ring-1 ring-border/60">
            <div className="font-mono text-base font-semibold text-foreground">{shownPackages.toLocaleString()}</div>
            <div>packages shown</div>
          </div>
          <div className="rounded-md bg-elevated/60 px-3 py-2 ring-1 ring-border/60">
            <div className="font-mono text-base font-semibold text-foreground">{shownAdvisories.toLocaleString()}</div>
            <div>advisories shown</div>
          </div>
          <div className="rounded-md bg-elevated/60 px-3 py-2 ring-1 ring-border/60">
            <div className="font-mono text-base font-semibold text-mutedfg">{totalAdvisories.toLocaleString()}</div>
            <div>total advisories after filters</div>
          </div>
        </div>
      </div>
      {displayRows.length === 0 ? (
        <div className="p-8 text-center">
          <div className="text-sm font-medium text-foreground">No vulnerabilities match this filter.</div>
          <div className="mx-auto mt-2 max-w-xl text-xs leading-5 text-mutedfg">
            Clear the search query or choose another severity to review all scanner advisories.
          </div>
        </div>
      ) : (
        <VirtualTable
          items={displayRows}
          totalItems={allSeverityDisplayRows.length}
          tableMinWidthClass="min-w-[1120px]"
          rowKey={(row) => row.key}
          rowClassName={(row) => cn('items-start py-2', row.isFirstInPackage && 'border-t-2 border-t-borderstrong bg-elevated/20')}
          columns={vulnColumns}
        />
      )}
    </Card>
  )
}

// ---- Licenses ----

interface LicenseEntry {
  license: string
  category: string
  severity: Severity
}

interface LicenseDisplayRow {
  key: string
  component: string
  version: string
  licenses: string[]
  categories: string[]
  // entries = the package's licenses kept SEPARATE (dual/multi-license packages are a
  // choice/OR, shown as one chip each with its own severity — not collapsed into one row).
  entries: LicenseEntry[]
  severity: Severity
  location: string
  source: string
  confidence: string
  sourceLabel: string
  sourceFile: string
  relationshipLabel: string
  dependencyPath: string
}

const LICENSE_SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 }

function licenseComponentKey(component: string): string {
  return component.trim().toLowerCase()
}

function licenseSeverity(category: string): Severity {
  switch (category) {
    case 'proprietary':
      return 'critical'
    case 'copyleft':
      return 'high'
    case 'weak-copyleft':
      return 'medium'
    case 'permissive':
      return 'low'
    default:
      return 'unknown'
  }
}

// LicenseChipStack renders a package's licenses (or their severities) as one chip per
// entry, stacked vertically and coloured by each license's own severity — so a dual/multi-
// license package reads as separate choices (OR), aligned across the License/Severity columns.
function LicenseChipStack({
  entries,
  render,
  title,
}: {
  entries: LicenseEntry[]
  render: (e: LicenseEntry) => string
  title?: (e: LicenseEntry) => string
}) {
  const items: LicenseEntry[] = entries.length ? entries : [{ license: 'UNKNOWN', category: 'unknown', severity: 'unknown' }]
  return (
    <div className="flex flex-col gap-1">
      {items.map((e, i) => (
        <span
          key={i}
          title={title?.(e)}
          className={cn(
            'inline-flex h-6 w-fit max-w-full items-center truncate rounded-md px-2 font-mono text-[11px] font-semibold ring-1 ring-inset',
            sevSoft[e.severity],
          )}
        >
          {render(e)}
        </span>
      ))}
    </div>
  )
}

function buildLicenseComponentIndex(components: ScanResult['components']) {
  const byName = new Map<string, ScanResult['components'][number][]>()
  for (const component of components) {
    const keys = [component.name, component.version ? `${component.name}@${component.version}` : '']
      .map(licenseComponentKey)
      .filter(Boolean)
    for (const key of keys) {
      const existing = byName.get(key) ?? []
      byName.set(key, [...existing, component])
    }
  }
  return byName
}

function licenseDisplayRowMatchesSearch(row: LicenseDisplayRow, query: string): boolean {
  if (!query) return true
  return [
    row.component,
    row.version,
    row.licenses.join(' '),
    row.categories.join(' '),
    row.severity,
    row.location,
    row.source,
    row.confidence,
    row.sourceLabel,
    row.sourceFile,
    row.relationshipLabel,
    row.dependencyPath,
  ].some((value) => value.toLowerCase().includes(query))
}

function buildLicenseDisplayRows(
  licenses: ScanResult['licenses'],
  unknownPackages: ScanResult['components'],
  componentIndex: Map<string, ScanResult['components'][number][]>,
  dependencies: ScanResult['dependencies'],
): LicenseDisplayRow[] {
  const byPackage = new Map<string, LicenseDisplayRow>()
  const upsertRow = (
    componentName: string,
    component: ScanResult['components'][number] | null,
    licenseName: string,
    category: string,
    severity: Severity,
  ) => {
    const source = dependencySourceLabel(component?.location ?? '')
    const id = component ? componentIdentity(component.name, component.version, component.purl) : ''
    const path = dependencyPathToRoot(dependencies, id)
    const via = path.length >= 2 ? shortPkg(path[path.length - 2]) : ''
    const inferredDirect = path.length === 1
    const rowKey = `${component?.name || componentName || '—'}\x00${component?.version ?? ''}\x00${component?.location ?? ''}`
    const existing = byPackage.get(rowKey) ?? {
      key: rowKey,
      component: component?.name || componentName || '—',
      version: component?.version ?? '',
      licenses: [],
      categories: [],
      entries: [] as LicenseEntry[],
      severity: 'unknown' as Severity,
      location: component?.location ?? '',
      source: component?.licenseSource ?? '',
      confidence: component?.licenseConfidence ?? '',
      sourceLabel: source.label,
      sourceFile: source.file,
      relationshipLabel: dependencyRelationshipLabel(inferredDirect, path, via),
      dependencyPath: path.map(shortPkg).join(' › '),
    }
    if (licenseName && !existing.licenses.includes(licenseName)) {
      existing.licenses.push(licenseName)
      existing.entries.push({ license: licenseName, category: category || 'unknown', severity })
    }
    if (category && !existing.categories.includes(category)) existing.categories.push(category)
    // Authoritative server risk severity; keep the most severe across a package's licenses (row sort key).
    if (LICENSE_SEVERITY_RANK[severity] < LICENSE_SEVERITY_RANK[existing.severity]) existing.severity = severity
    byPackage.set(rowKey, existing)
  }

  for (const license of licenses) {
    const componentNames = license.components.length > 0 ? license.components : ['']
    for (const componentName of componentNames) {
      const matchedComponents = componentIndex.get(licenseComponentKey(componentName)) ?? []
      const componentRows = matchedComponents.length > 0 ? matchedComponents : [null]
      for (const component of componentRows) {
        upsertRow(
          componentName,
          component,
          license.license || 'UNKNOWN',
          license.category || 'unknown',
          (license.severity || licenseSeverity(license.category || 'unknown')) as Severity,
        )
      }
    }
  }

  for (const component of unknownPackages) {
    upsertRow(component.name, component, 'UNKNOWN', 'unknown', 'unknown')
  }

  return [...byPackage.values()].sort(
    (a, b) => LICENSE_SEVERITY_RANK[a.severity] - LICENSE_SEVERITY_RANK[b.severity] || a.component.localeCompare(b.component),
  )
}

function LicenseCoverageHeader({ scan }: { scan: ScanResult }) {
  const c = scan.licenseCoverage
  if (c.total === 0) return null
  const tone = c.pct >= 90 ? 'bg-accent' : c.pct >= 60 ? 'bg-medium' : 'bg-critical'
  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm">
        <span className="font-medium text-foreground">License coverage</span>
        <span className="font-mono tabular-nums text-mutedfg">
          {c.pct.toFixed(0)}% · {c.detected.toLocaleString()} detected · {c.unknown.toLocaleString()} unknown
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-elevated">
        <div className={cn('h-full rounded-full transition-[width]', tone)} style={{ width: `${Math.max(1, c.pct)}%` }} />
      </div>
    </Card>
  )
}

function LicensesTab({ scan }: { scan: ScanResult | null }) {
  const [search, setSearch] = useState('')

  if (!scan) return <ScanPrompt icon={Scale} what="the license report" />
  if (scan.scanMode === 'vulnerabilities') {
    return <EmptyState icon={Bug} title="Licenses skipped" hint="This run used vulnerability-only scan mode." />
  }
  const componentIndex = buildLicenseComponentIndex(scan.components)
  const unknownPackages = scan.components
    .filter((c) => !c.firstParty && c.licenses.length === 0)
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name))
  const allDisplayRows = buildLicenseDisplayRows(scan.licenses, unknownPackages, componentIndex, scan.dependencies)
  const displayRows = allDisplayRows.filter((row) => licenseDisplayRowMatchesSearch(row, search.trim().toLowerCase()))
  const packagesImpacted = displayRows.length
  const licenseColumns: Column<LicenseDisplayRow>[] = [
    {
      header: 'Packages',
      className: 'sticky left-0 z-10 w-72 bg-card pr-2 font-mono text-xs text-foreground',
      cell: (row) => <span title={row.version ? `${row.component}@${row.version}` : row.component}>{row.component}</span>,
    },
    {
      header: 'License',
      className: 'w-72 font-mono text-xs text-foreground',
      // Multi-license packages are a CHOICE (OR) — show one chip per license (coloured by
      // its own severity), not a collapsed "A AND B" string.
      cell: (row) => <LicenseChipStack entries={row.entries} render={(e) => e.license} title={(e) => e.license} />,
    },
    {
      header: 'Severity',
      className: 'w-28',
      cell: (row) => <LicenseChipStack entries={row.entries} render={(e) => e.severity.toUpperCase()} />,
    },
    {
      header: 'Source / Path',
      className: 'w-80 text-xs',
      cell: (row) => {
        const title = [
          row.sourceFile ? `${row.sourceLabel}: ${row.sourceFile}` : row.sourceLabel,
          row.dependencyPath ? `Path: ${row.dependencyPath}` : row.relationshipLabel,
        ].join('\n')
        return (
          <div className="min-w-0 space-y-1" title={title}>
            <div className="flex min-w-0 items-center gap-2">
              <span className="shrink-0 rounded-md bg-elevated px-1.5 py-0.5 font-mono text-[10px] uppercase text-mutedfg ring-1 ring-border/70">
                {row.sourceLabel}
              </span>
              <span className="truncate font-mono text-[11px] text-subtlefg">{row.sourceFile || 'no source file'}</span>
            </div>
            <div className="truncate text-mutedfg">
              {row.relationshipLabel}
              {row.dependencyPath && <span className="text-subtlefg"> · {row.dependencyPath}</span>}
            </div>
          </div>
        )
      },
    },
    {
      header: 'Category',
      className: 'w-56 text-sm text-mutedfg',
      cell: (row) => (
        <div className="flex flex-col gap-1">
          {(row.entries.length ? row.entries : [{ category: 'unknown', severity: 'unknown' as Severity, license: '' }]).map((e, i) => (
            <span key={i} className="leading-6" title={e.category}>
              {CATEGORY_LABEL[e.category] ?? e.category.toUpperCase()}
            </span>
          ))}
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      <LicenseCoverageHeader scan={scan} />
      {scan.licenses.length === 0 ? (
        <EmptyState
          icon={Scale}
          title="No licenses classified"
          hint="No license metadata resolved for these packages — see coverage above."
        />
      ) : (
        <Card bodyClass="p-0">
          <div className="space-y-3 border-b border-border p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-sm font-medium text-foreground">License inventory</div>
                <div className="text-xs text-mutedfg">All detected package licenses are listed without hiding allowed entries.</div>
              </div>
              <div className="flex flex-wrap items-center justify-end gap-2">
                <input
                  value={search}
                  onChange={(event) => setSearch(event.currentTarget.value)}
                  placeholder="Search package, license, source, path…"
                  aria-label="Search licenses"
                  className="h-8 w-72 rounded-md border border-border bg-elevated px-2 text-xs text-foreground placeholder:text-subtlefg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40"
                />
              </div>
            </div>
            <div className="grid gap-2 text-xs text-mutedfg tabular-nums sm:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-md bg-elevated/60 px-3 py-2 ring-1 ring-border/60">
                <div className="font-mono text-base font-semibold text-foreground">{displayRows.length.toLocaleString()}</div>
                <div>packages listed</div>
              </div>
              <div className="rounded-md bg-elevated/60 px-3 py-2 ring-1 ring-border/60">
                <div className="font-mono text-base font-semibold text-foreground">{packagesImpacted.toLocaleString()}</div>
                <div>packages impacted</div>
              </div>
              <div className="rounded-md bg-elevated/60 px-3 py-2 ring-1 ring-border/60">
                <div className="font-mono text-base font-semibold text-mutedfg">{allDisplayRows.length.toLocaleString()}</div>
                <div>total package rows</div>
              </div>
              <div className="rounded-md bg-elevated/60 px-3 py-2 ring-1 ring-border/60">
                <div className="font-mono text-base font-semibold text-subtlefg">{unknownPackages.length.toLocaleString()}</div>
                <div>unknown-license packages</div>
              </div>
            </div>
          </div>
          {displayRows.length === 0 ? (
            <div className="p-8 text-center">
              <div className="text-sm font-medium text-foreground">No licenses match this search.</div>
              <div className="mx-auto mt-2 max-w-xl text-xs leading-5 text-mutedfg">
                Clear the search query to review the full license inventory.
              </div>
            </div>
          ) : (
            <VirtualTable
              items={displayRows}
              totalItems={allDisplayRows.length}
              tableMinWidthClass="min-w-[1120px]"
              rowKey={(row) => row.key}
              rowClassName="items-start py-2"
              rowHeight={(row) => Math.max(46, (row.entries.length || 1) * 28 + 16)}
              columns={licenseColumns}
            />
          )}
        </Card>
      )}
    </div>
  )
}

// ---- shared bits ----

// PriorityBadge renders the unified Synapse risk priority (1 highest.. 5 background).
function PriorityBadge({ priority }: { priority: number }) {
  const tone =
    priority <= 1
      ? 'bg-critical/15 text-critical ring-critical/30'
      : priority === 2
        ? 'bg-high/15 text-high ring-high/30'
        : priority === 3
          ? 'bg-medium/15 text-medium ring-medium/30'
          : 'bg-muted text-subtlefg ring-border'
  return (
    <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 font-mono text-xs font-semibold ring-1 ring-inset', tone)}>
      P{priority}
    </span>
  )
}

const SCOPE_LABEL: Record<string, string> = {
  production: 'prod',
  development: 'dev',
  test: 'test',
  example: 'example',
  fixture: 'fixture',
  benchmark: 'bench',
  documentation: 'docs',
  unknown: '—',
}

// ScopeBadge shows where the component lives; background scopes are de-emphasized.
function ScopeBadge({ scope }: { scope: string }) {
  const bg = scope !== 'production' && scope !== 'unknown'
  return (
    <span className={cn('font-mono text-[11px]', bg ? 'text-subtlefg' : 'text-mutedfg')}>
      {SCOPE_LABEL[scope] ?? scope}
    </span>
  )
}

// DetectedBy renders the detection sources — OSV, Grype, or both.
function DetectedBy({ sources }: { sources: string[] }) {
  if (!sources || sources.length === 0) return <span className="text-subtlefg">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {sources.map((s) => (
        <span
          key={s}
          className={cn(
            'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1 ring-inset',
            s === 'grype' ? 'bg-brand/10 text-branddim ring-brand/25' : 'bg-muted text-mutedfg ring-border',
          )}
        >
          {s}
        </span>
      ))}
    </div>
  )
}

const CONFIDENCE_LABEL: Record<string, string> = {
  very_high: 'Very high',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

function ConfidenceBadge({ confidence }: { confidence: string }) {
  if (!confidence) return <span className="text-subtlefg">—</span>
  const tone =
    confidence === 'very_high'
      ? 'bg-accent/10 text-accent ring-accent/25'
      : confidence === 'high'
        ? 'bg-brand/10 text-branddim ring-brand/25'
        : confidence === 'medium'
          ? 'bg-muted text-mutedfg ring-border'
          : 'text-subtlefg ring-border'
  return (
    <span className={cn('inline-flex rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset', tone)}>
      {CONFIDENCE_LABEL[confidence] ?? confidence}
    </span>
  )
}

// KindBadge labels a finding's Kind — shown in the list for the non-SCA kinds (sast,
// exploitation, threat, hypothesis, recon, manual) where the provenance is worth surfacing.
function KindBadge({ kind }: { kind: string }) {
  return (
    <span className="rounded bg-muted px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide text-mutedfg">
      {findingKindLabel(kind)}
    </span>
  )
}

// KindFilter is the finding-Kind segmented filter, mirroring SeverityFilter. Only the Kinds
// actually present are offered, plus "all".
function KindFilter({ value, onChange, kinds }: { value: string; onChange: (v: string) => void; kinds: string[] }) {
  const opts = ['all', ...kinds]
  return (
    <div className="flex flex-wrap gap-1.5">
      {opts.map((o) => (
        <button
          key={o}
          onClick={() => onChange(o)}
          className={cn(
            'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
            value === o
              ? 'bg-brand/15 text-branddim ring-1 ring-inset ring-brand/30'
              : 'text-mutedfg hover:bg-elevated hover:text-foreground',
          )}
        >
          {o === 'all' ? 'all kinds' : findingKindLabel(o)}
        </button>
      ))}
    </div>
  )
}

function SeverityFilter({
  value,
  onChange,
  available,
}: {
  value: Severity | 'all'
  onChange: (v: Severity | 'all') => void
  available: Set<Severity>
}) {
  const opts: (Severity | 'all')[] = ['all', ...SEVERITY_ORDER.filter((s) => available.has(s))]
  return (
    <div className="flex flex-wrap gap-1.5">
      {opts.map((o) => (
        <button
          key={o}
          onClick={() => onChange(o)}
          className={cn(
            'rounded-md px-2.5 py-1 text-xs font-medium capitalize transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
            value === o
              ? 'bg-brand/15 text-branddim ring-1 ring-inset ring-brand/30'
              : 'text-mutedfg hover:bg-elevated hover:text-foreground',
          )}
        >
          {o}
        </button>
      ))}
    </div>
  )
}

function ScanPrompt({ icon, what }: { icon: typeof Boxes; what: string }) {
  return <EmptyState icon={icon} title={`Run a scan to populate ${what}`} hint="Use the “Run scan” panel above." />
}

function countEdges(scan: ScanResult): number {
  return scan.dependencies.reduce((n, d) => n + d.dependsOn.length, 0)
}

function fmtDuration(start: string | null, end: string | null): string {
  if (!start) return '—'
  const s = new Date(start).getTime()
  const e = end ? new Date(end).getTime() : Date.now()
  const sec = Math.max(0, Math.round((e - s) / 1000))
  if (sec < 60) return `${sec}s`
  const m = Math.floor(sec / 60)
  return `${m}m ${sec % 60}s`
}

function fmtWindow(from: string | null, to: string | null): string {
  const f = from ? new Date(from).toLocaleDateString() : '—'
  const t = to ? new Date(to).toLocaleDateString() : 'open'
  return `${f} → ${t}`
}

// ---- Recon: gated live-recon launcher · runs · SSE console ----

function ReconTab({ eng, onGoTab }: { eng: Engagement; onGoTab: (t: Tab) => void }) {
  const [tools, setTools] = useState<ReconTool[]>([])
  const [runs, setRuns] = useState<ReconRun[]>([])
  const [active, setActive] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    Promise.all([api.reconTools(), api.reconRuns(eng.id)])
      .then(([t, r]) => {
        if (alive) {
          setTools(t)
          setRuns(r)
        }
      })
      .catch((e) => alive && setErr(e instanceof Error ? e.message : 'Failed to load recon'))
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
    }
  }, [eng.id])

  // Poll while any run is queued/running so the list reflects progress.
  useEffect(() => {
    if (!runs.some((r) => r.status === 'running' || r.status === 'queued')) return
    const t = setInterval(() => {
      api.reconRuns(eng.id).then(setRuns).catch(() => {})
    }, 2500)
    return () => clearInterval(t)
  }, [runs, eng.id])

  if (loading) return <Spinner label="Loading recon…" />
  if (err) return <ErrorState message={err} />

  return (
    <div className="space-y-6">
      {eng.liveReconEnabled ? (
        <ReconLauncher
          eng={eng}
          tools={tools}
          onLaunched={(run) => {
            setRuns((prev) => [run, ...prev.filter((x) => x.id !== run.id)])
            setActive(run.id)
          }}
        />
      ) : (
        <Card title="Live reconnaissance disabled">
          <div className="flex flex-wrap items-center gap-3 text-sm text-mutedfg">
            <AlertTriangle className="size-4 shrink-0 text-info" />
            <span>Live recon is lab-only and turned off for this engagement.</span>
            <Button variant="secondary" onClick={() => onGoTab('settings')} className="px-3 py-1.5">
              Enable in Settings
            </Button>
          </div>
        </Card>
      )}
      <ReconRunsList runs={runs} activeId={active} onSelect={setActive} />
      {active && (
        <ReconConsole
          engagementId={eng.id}
          runId={active}
          onClose={() => setActive(null)}
          onDone={() => api.reconRuns(eng.id).then(setRuns).catch(() => {})}
        />
      )}
    </div>
  )
}

function ReconLauncher({ eng, tools, onLaunched }: { eng: Engagement; tools: ReconTool[]; onLaunched: (r: ReconRun) => void }) {
  const [toolName, setToolName] = useState(tools[0]?.name ?? '')
  const [target, setTarget] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const tool = tools.find((t) => t.name === toolName)
  const targets = tool ? eng.inScope.filter((t) => tool.acceptedKinds.includes(t.kind)) : []

  // Keep the selected target valid as the tool (and thus accepted kinds) changes.
  useEffect(() => {
    setTarget((cur) => (targets.some((t) => t.value === cur) ? cur : targets[0]?.value ?? ''))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toolName, eng.id])

  async function launch() {
    if (!toolName || !target) {
      setErr('Pick a tool and an in-scope target.')
      return
    }
    setBusy(true)
    setErr(null)
    try {
      onLaunched(await api.startReconRun(eng.id, toolName, target))
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Launch failed')
    } finally {
      setBusy(false)
    }
  }

  if (tools.length === 0) {
    return (
      <Card title="Recon">
        <p className="text-sm text-mutedfg">No recon tools are registered.</p>
      </Card>
    )
  }

  return (
    <Card title="Launch recon">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Tool">
          <Select
            value={toolName}
            onValueChange={setToolName}
            ariaLabel="Recon tool"
            options={tools.map((t) => ({
              value: t.name,
              label: (
                <span className="flex items-center gap-2">
                  {t.name}
                  {t.capabilitySensitive && (
                    <span className="rounded bg-medium/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-medium">lab-only</span>
                  )}
                </span>
              ),
            }))}
          />
        </Field>
        <Field label="In-scope target" hint={targets.length ? undefined : 'No in-scope target matches this tool — add one in Settings'}>
          {targets.length > 0 ? (
            <Select
              value={target}
              onValueChange={setTarget}
              ariaLabel="In-scope target"
              options={targets.map((t) => ({ value: t.value, label: <span className="font-mono">{t.value}</span> }))}
            />
          ) : (
            <Input value="" disabled placeholder="no matching in-scope target" />
          )}
        </Field>
      </div>
      {tool?.capabilitySensitive && (
        <p className="mt-3 flex items-center gap-1.5 text-xs text-medium">
          <AlertTriangle className="size-3.5" /> {tool.name} uses raw sockets — authorized lab environments only.
        </p>
      )}
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
      <div className="mt-4 flex justify-end">
        <Button loading={busy} disabled={!target} onClick={launch} className="px-3 py-1.5">
          <Play className="size-4" /> Launch
        </Button>
      </div>
    </Card>
  )
}

function ReconStatusPill({ status }: { status: ReconRun['status'] }) {
  const cls: Record<ReconRun['status'], string> = {
    queued: 'bg-elevated text-mutedfg ring-border',
    running: 'bg-info/10 text-info ring-info/25',
    succeeded: 'bg-accent/10 text-accent ring-accent/25',
    failed: 'bg-critical/10 text-critical ring-critical/25',
  }
  return (
    <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ring-inset', cls[status])}>
      {status}
    </span>
  )
}

// ReconContainmentBadge shows the confinement posture a run executed under:
// green when sandboxed (egress-restricted / isolated), amber when unsandboxed (dev).
function ReconContainmentBadge({ posture }: { posture: string }) {
  const unsandboxed = posture.startsWith('unsandboxed')
  const Icon = unsandboxed ? ShieldAlert : ShieldCheck
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 font-mono text-xs tabular-nums ring-1',
        unsandboxed ? 'bg-high/10 text-high ring-high/25' : 'bg-accent/10 text-accent ring-accent/25',
      )}
      title="Containment posture this run executed under (sealed into evidence)"
    >
      <Icon className="size-3 shrink-0" aria-hidden />
      {/* Announce the safe/unsafe state to screen readers — the icon is decorative and the
          posture string alone (e.g. "unsandboxed-dev") carries no semantic severity. */}
      <span className="sr-only">{unsandboxed ? 'Warning, unsandboxed: ' : 'Sandboxed: '}</span>
      <span className="truncate">{posture}</span>
    </span>
  )
}

function ReconRunsList({ runs, activeId, onSelect }: { runs: ReconRun[]; activeId: string | null; onSelect: (id: string) => void }) {
  if (runs.length === 0) {
    return <EmptyState icon={Radar} title="No recon runs yet" hint="Launch a tool above to start reconnaissance." />
  }
  return (
    <Card title="Runs" bodyClass="p-0">
      <div className="divide-y divide-border">
        {runs.map((r) => (
          <button
            key={r.id}
            onClick={() => onSelect(r.id)}
            aria-pressed={activeId === r.id}
            className={cn(
              'flex w-full flex-col gap-1 px-4 py-3 text-left text-sm transition-colors hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40',
              activeId === r.id && 'bg-raised',
            )}
          >
            <div className="flex w-full items-center gap-3">
              <ReconStatusPill status={r.status} />
              <span className="font-mono font-medium text-foreground">{r.tool}</span>
              <span className="truncate font-mono text-mutedfg">{r.target}</span>
              <span className="ml-auto shrink-0 tabular-nums text-xs text-subtlefg">
                {r.status === 'succeeded' ? `${r.resultCount} in-scope` : r.status === 'failed' ? 'failed' : r.stage}
              </span>
            </div>
            {r.containment && <ReconContainmentBadge posture={r.containment} />}
          </button>
        ))}
      </div>
    </Card>
  )
}

// ReconConsole tails a run's logs over SSE (fetch-based; reconnects with the last
// event id if the stream drops before the run finishes).
function ReconConsole({ engagementId, runId, onClose, onDone }: { engagementId: string; runId: string; onClose: () => void; onDone: () => void }) {
  const [lines, setLines] = useState<string[]>([])
  const [done, setDone] = useState(false)
  const [reconnecting, setReconnecting] = useState(false)
  const boxRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setLines([])
    setDone(false)
    setReconnecting(false)
    const ctrl = new AbortController()
    let lastId = 0
    let stopped = false

    async function pump() {
      while (!stopped) {
        try {
          await streamReconLogs(engagementId, runId, {
            lastEventId: lastId,
            signal: ctrl.signal,
            onEvent: (e) => {
              setReconnecting(false)
              if (e.done) {
                stopped = true
                setDone(true)
                onDone()
                return
              }
              if (e.id) lastId = e.id
              if (e.line !== undefined) setLines((prev) => [...prev, e.line as string])
            },
          })
        } catch {
          if (ctrl.signal.aborted) return
        }
        if (stopped || ctrl.signal.aborted) return
        setReconnecting(true)
        await new Promise((r) => setTimeout(r, 1000)) // brief pause, then reconnect-replay
      }
    }
    pump()
    return () => {
      stopped = true
      ctrl.abort()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [engagementId, runId])

  useEffect(() => {
    boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight })
  }, [lines])

  return (
    <Card
      title="Live log"
      actions={
        <div className="flex items-center gap-3">
          <span className={cn('flex items-center gap-1.5 text-xs', done ? 'text-mutedfg' : reconnecting ? 'text-medium' : 'text-info')}>
            <span className={cn('size-1.5 rounded-full', done ? 'bg-mutedfg' : reconnecting ? 'bg-medium' : 'bg-info')} />
            {done ? 'ended' : reconnecting ? 'reconnecting…' : 'streaming'}
          </span>
          <button type="button" aria-label="Close log" onClick={onClose} className="rounded-md p-1 text-mutedfg hover:bg-raised hover:text-foreground">
            <X className="size-4" />
          </button>
        </div>
      }
    >
      <div
        ref={boxRef}
        role="log"
        aria-live="polite"
        aria-relevant="additions"
        className="max-h-96 overflow-auto rounded-lg border border-border bg-bg p-3 font-mono text-xs leading-relaxed"
      >
        {lines.length === 0 ? (
          <span className="text-subtlefg">Waiting for output…</span>
        ) : (
          lines.map((l, i) => (
            <div
              key={i}
              className={cn(
                'whitespace-pre-wrap break-all',
                l.startsWith('ERROR') ? 'text-critical' : l.startsWith('WARN') ? 'text-medium' : l.includes('[dropped') ? 'text-mutedfg' : 'text-foreground',
              )}
            >
              {l}
            </div>
          ))
        )}
      </div>
    </Card>
  )
}

// ---- Settings: scope CRUD · authorization window · lifecycle ----

const TARGET_KINDS = ['domain', 'ip', 'cidr', 'url', 'repo', 'image']

function SettingsTab({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  return (
    <div className="space-y-6">
      <LifecycleCard eng={eng} onUpdated={onUpdated} />
      <ScopeEditorCard eng={eng} onUpdated={onUpdated} />
      <WindowEditorCard eng={eng} onUpdated={onUpdated} />
      <RoeEditorCard eng={eng} onUpdated={onUpdated} />
      <LiveReconCard eng={eng} onUpdated={onUpdated} />
    </div>
  )
}

// LiveReconCard toggles lab-only live recon. Off by default; enabling
// it is an explicit, audited opt-in shown with a clear safety caveat.
function LiveReconCard({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  async function toggle() {
    setBusy(true)
    setErr(null)
    try {
      onUpdated(await api.setLiveRecon(eng.id, !eng.liveReconEnabled))
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Update failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="Live reconnaissance">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="max-w-xl space-y-2 text-sm text-mutedfg">
          <p>
            Live recon shells out to network tools against in-scope targets. Until the hardened sandbox + egress
            allowlist ship, it is <span className="font-medium text-foreground">lab-only</span>: enable it only for
            authorized test environments.
          </p>
          <p className="flex items-center gap-2">
            <span className="text-mutedfg">Status:</span>
            {eng.liveReconEnabled ? (
              <Pill className="bg-accent/10 text-accent ring-1 ring-inset ring-accent/25">Enabled</Pill>
            ) : (
              <Pill className="bg-elevated text-mutedfg ring-1 ring-inset ring-border">Disabled</Pill>
            )}
          </p>
          {err && <span className="text-xs text-critical">{err}</span>}
        </div>
        <Button
          variant={eng.liveReconEnabled ? 'secondary' : 'primary'}
          loading={busy}
          onClick={toggle}
          className="px-3 py-1.5"
        >
          {eng.liveReconEnabled ? 'Disable live recon' : 'Enable live recon'}
        </Button>
      </div>
    </Card>
  )
}

const LIFECYCLE_NEXT: Record<string, { status: string; label: string; variant: 'primary' | 'secondary' }[]> = {
  draft: [
    { status: 'active', label: 'Activate', variant: 'primary' },
    { status: 'archived', label: 'Archive', variant: 'secondary' },
  ],
  active: [
    { status: 'completed', label: 'Complete', variant: 'primary' },
    { status: 'archived', label: 'Archive', variant: 'secondary' },
  ],
  completed: [{ status: 'archived', label: 'Archive', variant: 'secondary' }],
  archived: [],
}

function LifecycleCard({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  const [busy, setBusy] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const next = LIFECYCLE_NEXT[eng.status] ?? []

  async function go(status: string) {
    setBusy(status)
    setErr(null)
    try {
      onUpdated(await api.transitionEngagement(eng.id, status))
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Transition failed')
    } finally {
      setBusy(null)
    }
  }

  return (
    <Card title="Lifecycle">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm text-mutedfg">Status</span>
        <StatusPill status={eng.status} />
        <div className="ml-auto flex flex-wrap gap-2">
          {next.length === 0 ? (
            <span className="text-xs text-subtlefg">Terminal — no further transitions.</span>
          ) : (
            next.map((n) => (
              <Button
                key={n.status}
                variant={n.variant}
                loading={busy === n.status}
                disabled={busy !== null}
                onClick={() => go(n.status)}
              >
                {n.label}
              </Button>
            ))
          )}
        </div>
      </div>
      <p className="mt-3 text-xs text-subtlefg">
        Completing or archiving an engagement blocks all tool execution. Scope and the authorization window are enforced
        on every run too — changes here take effect immediately, server-side.
      </p>
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
    </Card>
  )
}

function ScopeEditorCard({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  const [inScope, setInScope] = useState<ScopeTarget[]>(eng.inScope)
  const [outScope, setOutScope] = useState<ScopeTarget[]>(eng.outOfScope)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  // Re-seed when navigating to a different engagement.
  useEffect(() => {
    setInScope(eng.inScope)
    setOutScope(eng.outOfScope)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eng.id])

  async function save() {
    setBusy(true)
    setErr(null)
    setSaved(false)
    const clean = (xs: ScopeTarget[]) => xs.filter((t) => t.value.trim() !== '')
    try {
      const updated = await api.updateScope(eng.id, clean(inScope), clean(outScope))
      onUpdated(updated)
      setInScope(updated.inScope)
      setOutScope(updated.outOfScope)
      setSaved(true)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to save scope')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Scope"
      actions={
        <Button loading={busy} onClick={save} className="px-3 py-1.5">
          <Save className="size-4" /> Save scope
        </Button>
      }
    >
      <div className="space-y-5">
        <TargetList label="In scope" targets={inScope} onChange={setInScope} />
        <TargetList label="Out of scope" targets={outScope} onChange={setOutScope} />
      </div>
      <p className="mt-4 text-xs text-subtlefg">
        Host-centric matching: a CIDR contains an IP, <span className="font-mono">*.example.com</span> matches
        subdomains, URLs match by host. Out-of-scope always wins. The execution gate reads this live — no restart.
      </p>
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
      {saved && !err && <p className="mt-3 text-xs text-accent">Scope saved.</p>}
    </Card>
  )
}

function TargetList({
  label,
  targets,
  onChange,
}: {
  label: string
  targets: ScopeTarget[]
  onChange: (t: ScopeTarget[]) => void
}) {
  function update(i: number, patch: Partial<ScopeTarget>) {
    onChange(targets.map((t, j) => (j === i ? { ...t, ...patch } : t)))
  }
  return (
    <div>
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-mutedfg">{label}</div>
      <div className="space-y-2">
        {targets.length === 0 && <p className="text-xs text-subtlefg">No targets.</p>}
        {targets.map((t, i) => (
          <div key={i} className="flex items-center gap-2">
            <Select
              value={t.kind}
              onValueChange={(v) => update(i, { kind: v })}
              ariaLabel={`${label} target ${i + 1} kind`}
              options={TARGET_KINDS.map((k) => ({ value: k, label: kindLabel(k) }))}
              className="w-32 shrink-0"
            />
            <Input
              value={t.value}
              onChange={(e) => update(i, { value: e.target.value })}
              placeholder="value (e.g. *.example.com, 10.0.0.0/24)"
              className="flex-1 font-mono"
              aria-label={`${label} target ${i + 1} value`}
            />
            <button
              type="button"
              onClick={() => onChange(targets.filter((_, j) => j !== i))}
              aria-label={`Remove ${label} target ${i + 1}`}
              className="rounded-md p-2 text-subtlefg transition-colors hover:bg-elevated hover:text-critical focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
            >
              <Trash2 className="size-4" />
            </button>
          </div>
        ))}
      </div>
      <button
        type="button"
        onClick={() => onChange([...targets, { kind: 'domain', value: '' }])}
        className="mt-2 inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium text-branddim transition-colors hover:bg-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
      >
        <Plus className="size-3.5" /> Add target
      </button>
    </div>
  )
}

function WindowEditorCard({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  const [from, setFrom] = useState(toLocalInput(eng.authorizedFrom))
  const [to, setTo] = useState(toLocalInput(eng.authorizedTo))
  const [tz, setTz] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    setFrom(toLocalInput(eng.authorizedFrom))
    setTo(toLocalInput(eng.authorizedTo))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eng.id])

  const clearsWindow = from === '' && to === ''

  async function save() {
    setBusy(true)
    setErr(null)
    setSaved(false)
    try {
      const f = from ? new Date(from).toISOString() : ''
      const t = to ? new Date(to).toISOString() : ''
      onUpdated(await api.setAuthorizationWindow(eng.id, f, t, tz.trim()))
      setSaved(true)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to save window')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Authorization window"
      actions={
        <Button loading={busy} onClick={save} className="px-3 py-1.5">
          <Save className="size-4" /> Save window
        </Button>
      }
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Field label="From">
          <Input
            type="datetime-local"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            aria-label="Authorization window start"
          />
        </Field>
        <Field label="To">
          <Input
            type="datetime-local"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            aria-label="Authorization window end"
          />
        </Field>
        <Field label="Timezone" hint="IANA name (display/audit)">
          <Input
            value={tz}
            onChange={(e) => setTz(e.target.value)}
            placeholder="UTC"
            aria-label="Authorization window timezone"
          />
        </Field>
      </div>
      <p className="mt-3 text-xs text-subtlefg">
        Tools are refused outside this window (±2 min skew), server-side. Leave a bound empty to leave that side open.
      </p>
      {clearsWindow && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-medium/40 bg-medium/10 p-3 text-xs text-medium">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>Both bounds are empty — saving removes the authorization window (testing allowed at any time).</span>
        </div>
      )}
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
      {saved && !err && <p className="mt-3 text-xs text-accent">Window saved.</p>}
    </Card>
  )
}

// Known tool classes (gate-action prefixes). Empty selection = no restriction.
const KNOWN_TOOL_CLASSES = ['sca', 'recon', 'exploit']

function RoeEditorCard({ eng, onUpdated }: { eng: Engagement; onUpdated: (e: Engagement) => void }) {
  const seedBlackouts = () => eng.roe.blackouts.map((b) => ({ from: toLocalInput(b.from), to: toLocalInput(b.to) }))
  const [classes, setClasses] = useState<string[]>(eng.roe.allowedToolClasses)
  const [blackouts, setBlackouts] = useState<{ from: string; to: string }[]>(seedBlackouts)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    setClasses(eng.roe.allowedToolClasses)
    setBlackouts(seedBlackouts())
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eng.id])

  function toggleClass(c: string) {
    setClasses((cur) => (cur.includes(c) ? cur.filter((x) => x !== c) : [...cur, c]))
  }

  async function save() {
    setBusy(true)
    setErr(null)
    setSaved(false)
    try {
      const bs = blackouts
        .filter((b) => b.from && b.to)
        .map((b) => ({ from: new Date(b.from).toISOString(), to: new Date(b.to).toISOString() }))
      onUpdated(await api.setRoE(eng.id, classes, bs))
      setSaved(true)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to save rules of engagement')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Rules of engagement"
      actions={
        <Button loading={busy} onClick={save} className="px-3 py-1.5">
          <Save className="size-4" /> Save RoE
        </Button>
      }
    >
      <div className="space-y-5">
        <div>
          <div id="roe-classes-label" className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-mutedfg">
            Allowed tool classes
          </div>
          <div role="group" aria-labelledby="roe-classes-label" className="flex flex-wrap gap-2">
            {KNOWN_TOOL_CLASSES.map((c) => {
              const on = classes.includes(c)
              return (
                <button
                  key={c}
                  type="button"
                  aria-pressed={on}
                  aria-label={`Allow ${c} tools`}
                  onClick={() => toggleClass(c)}
                  className={cn(
                    'rounded-md px-3 py-1.5 text-sm font-medium capitalize ring-1 ring-inset transition-colors',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
                    on
                      ? 'bg-brand/15 text-branddim ring-brand/30'
                      : 'bg-elevated text-mutedfg ring-border hover:text-foreground',
                  )}
                >
                  {c}
                </button>
              )
            })}
          </div>
          {classes.length === 0 ? (
            <div className="mt-2 flex items-start gap-2 rounded-lg border border-medium/40 bg-medium/10 p-3 text-xs text-medium">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span>
                None selected — <strong>all</strong> tool classes are allowed. Select one or more to restrict execution.
              </span>
            </div>
          ) : (
            <p className="mt-2 text-xs text-subtlefg">
              Only the selected tool classes may run; everything else is denied.
            </p>
          )}
        </div>

        <div>
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-mutedfg">Blackout windows</div>
          <div className="space-y-2">
            {blackouts.length === 0 && <p className="text-xs text-subtlefg">No blackout windows.</p>}
            {blackouts.map((b, i) => (
              <div key={i} className="grid grid-cols-1 items-center gap-2 sm:grid-cols-[1fr_auto_1fr_auto]">
                <Input
                  type="datetime-local"
                  value={b.from}
                  onChange={(e) =>
                    setBlackouts((cur) => cur.map((x, j) => (j === i ? { ...x, from: e.target.value } : x)))
                  }
                  aria-label={`Blackout ${i + 1} start`}
                />
                <span className="hidden text-center text-subtlefg sm:inline">→</span>
                <Input
                  type="datetime-local"
                  value={b.to}
                  onChange={(e) => setBlackouts((cur) => cur.map((x, j) => (j === i ? { ...x, to: e.target.value } : x)))}
                  aria-label={`Blackout ${i + 1} end`}
                />
                <button
                  type="button"
                  onClick={() => setBlackouts((cur) => cur.filter((_, j) => j !== i))}
                  aria-label={`Remove blackout ${i + 1}`}
                  className="justify-self-start rounded-md p-2 text-subtlefg transition-colors hover:bg-elevated hover:text-critical focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40 sm:justify-self-auto"
                >
                  <Trash2 className="size-4" />
                </button>
              </div>
            ))}
          </div>
          <button
            type="button"
            onClick={() => setBlackouts((cur) => [...cur, { from: '', to: '' }])}
            className="mt-2 inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium text-branddim transition-colors hover:bg-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
          >
            <Plus className="size-3.5" /> Add blackout
          </button>
        </div>
      </div>
      <p className="mt-4 text-xs text-subtlefg">
        Enforced by the execution gate on every run: a disallowed tool class, or any run inside a blackout, is denied
        and audited.
      </p>
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
      {saved && !err && <p className="mt-3 text-xs text-accent">Rules of engagement saved.</p>}
    </Card>
  )
}

// toLocalInput converts an RFC3339 instant to a datetime-local input value
// (YYYY-MM-DDTHH:mm in the browser's local time); '' for null/invalid.
function toLocalInput(rfc: string | null): string {
  if (!rfc) return ''
  const d = new Date(rfc)
  if (Number.isNaN(d.getTime())) return ''
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
}

// ---- Evidence vault: tamper-evident chain timeline + manual capture ----

const EVIDENCE_KINDS = ['screenshot', 'http', 'terminal_log', 'pcap', 'artifact']

function EvidenceTab({ engagementId }: { engagementId: string }) {
  const [ledger, setLedger] = useState<EvidenceLedger | null>(null)
  const [err, setErr] = useState<string | null>(null)

  const reload = useCallback(() => {
    api
      .evidenceLedger(engagementId)
      .then(setLedger)
      .catch((e) => setErr(e instanceof Error ? e.message : 'Failed to load evidence'))
  }, [engagementId])

  useEffect(() => {
    reload()
  }, [reload])

  if (err) return <ErrorState message={err} />
  if (ledger === null) return <Spinner label="Loading evidence…" />

  return (
    <div className="space-y-6">
      <EvidenceIntegrity ledger={ledger} />
      <CaptureEvidenceForm engagementId={engagementId} onCaptured={reload} />
      <EvidenceChain engagementId={engagementId} items={ledger.items} />
    </div>
  )
}

function EvidenceIntegrity({ ledger }: { ledger: EvidenceLedger }) {
  const intact = ledger.intact
  return (
    <div
      className={cn(
        'flex items-start gap-3 rounded-xl border p-4',
        intact ? 'border-accent/30 bg-accent/10' : 'border-critical/40 bg-critical/10',
      )}
    >
      {intact ? (
        <ShieldCheck className="mt-0.5 size-5 shrink-0 text-accent" />
      ) : (
        <ShieldAlert className="mt-0.5 size-5 shrink-0 text-critical" />
      )}
      <div className="min-w-0">
        <p className={cn('text-sm font-semibold', intact ? 'text-accent' : 'text-critical')}>
          {intact ? 'Evidence chain intact' : 'Evidence chain TAMPERED'}
        </p>
        <p className="mt-0.5 text-xs text-mutedfg">
          {ledger.verified} hash-chained link{ledger.verified === 1 ? '' : 's'} verified.{' '}
          {intact
            ? 'Each link binds to the previous, so any edit, insertion, or removal is detectable.'
            : ledger.error || 'The chain failed verification — the report path is blocked.'}
        </p>
      </div>
    </div>
  )
}

function CaptureEvidenceForm({ engagementId, onCaptured }: { engagementId: string; onCaptured: () => void }) {
  const [kind, setKind] = useState('screenshot')
  const [note, setNote] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  async function capture() {
    if (!file) {
      setErr('Choose a file to capture.')
      return
    }
    setBusy(true)
    setErr(null)
    try {
      const b64 = await fileToBase64(file)
      await api.captureEvidence(engagementId, kind, file.name, note.trim(), b64)
      setFile(null)
      setNote('')
      if (fileRef.current) fileRef.current.value = ''
      onCaptured()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Capture failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Capture evidence"
      actions={
        <Button loading={busy} onClick={capture} className="px-3 py-1.5">
          <Upload className="size-4" /> Capture
        </Button>
      }
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Field label="Kind">
          <Select
            value={kind}
            onValueChange={setKind}
            ariaLabel="Evidence kind"
            options={EVIDENCE_KINDS.map((k) => ({ value: k, label: k.replace('_', ' ') }))}
          />
        </Field>
        <Field label="File" htmlFor="evidence-file">
          <input
            id="evidence-file"
            ref={fileRef}
            type="file"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            aria-label="Evidence artifact file"
            className="block w-full text-sm text-mutedfg file:mr-3 file:rounded-md file:border-0 file:bg-elevated file:px-3 file:py-2 file:text-sm file:font-medium file:text-foreground hover:file:bg-raised"
          />
        </Field>
        <Field label="Note">
          <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="optional" aria-label="Evidence note" />
        </Field>
      </div>
      <p className="mt-3 text-xs text-subtlefg">
        The artifact is stored content-addressed and sealed into the hash chain by its sha256, so any later change to the
        stored bytes is detectable.
      </p>
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
    </Card>
  )
}

function EvidenceChain({ engagementId, items }: { engagementId: string; items: EvidenceItem[] }) {
  if (items.length === 0) {
    return (
      <EmptyState
        icon={FileClock}
        title="No evidence yet"
        hint="Scans seal evidence automatically; capture artifacts above to add to the chain."
      />
    )
  }
  return (
    <Card title="Evidence chain" bodyClass="p-0">
      <ol>
        {items.map((it, i) => (
          <li
            key={it.id || i}
            className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border px-5 py-3 first:border-t-0"
          >
            <span className="w-6 shrink-0 text-center font-mono text-xs text-subtlefg">{i + 1}</span>
            <Pill className="uppercase">{it.kind.replace('_', ' ')}</Pill>
            <span className="text-xs text-mutedfg">{it.createdAt ? new Date(it.createdAt).toLocaleString() : '—'}</span>
            <span className="text-xs text-subtlefg">{it.createdBy || '—'}</span>
            <span className="flex-1" />
            <span className="font-mono text-[11px] text-subtlefg" title={it.hash}>
              {it.hash.slice(0, 12)}
            </span>
            {it.storageRef && <ArtifactDownload engagementId={engagementId} item={it} />}
          </li>
        ))}
      </ol>
    </Card>
  )
}

function ArtifactDownload({ engagementId, item }: { engagementId: string; item: EvidenceItem }) {
  const [busy, setBusy] = useState(false)
  const [failed, setFailed] = useState(false)
  async function dl() {
    setBusy(true)
    setFailed(false)
    try {
      await api.downloadArtifact(engagementId, item.storageRef, '')
    } catch {
      setFailed(true)
    } finally {
      setBusy(false)
    }
  }
  return (
    <button
      onClick={dl}
      disabled={busy}
      title={failed ? 'Download failed — the artifact may be tampered' : 'Download artifact'}
      className={cn(
        'inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
        failed ? 'text-critical' : 'text-branddim hover:bg-elevated',
      )}
    >
      {busy ? <Loader2 className="size-3.5 animate-spin" /> : <Download className="size-3.5" />}
      {failed ? 'failed' : 'artifact'}
    </button>
  )
}

// fileToBase64 reads a File as base64 (without the data URL prefix) for capture.
function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const s = String(reader.result)
      const comma = s.indexOf(',')
      resolve(comma >= 0 ? s.slice(comma + 1) : s)
    }
    reader.onerror = () => reject(new Error('Failed to read file'))
    reader.readAsDataURL(file)
  })
}

// ---- Findings workflow: manual authoring · CVSS builder · Kanban · collab ----

function FindingsViewToggle({ view, onChange }: { view: 'table' | 'board'; onChange: (v: 'table' | 'board') => void }) {
  return (
    <div role="radiogroup" aria-label="Findings view" className="inline-flex h-9 items-center rounded-lg border border-border bg-elevated p-0.5">
      {(['table', 'board'] as const).map((v) => (
        <button
          key={v}
          role="radio"
          aria-checked={view === v}
          onClick={() => onChange(v)}
          className={cn(
            'h-full rounded-md px-3 text-sm font-medium capitalize transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40',
            view === v ? 'bg-card text-foreground shadow-sm' : 'text-mutedfg hover:text-foreground',
          )}
        >
          {v}
        </button>
      ))}
    </div>
  )
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

// Common CWEs for the picker datalist (operators can still type any value).
const COMMON_CWES: { id: string; label: string }[] = [
  { id: 'CWE-79', label: 'Cross-site Scripting' },
  { id: 'CWE-89', label: 'SQL Injection' },
  { id: 'CWE-22', label: 'Path Traversal' },
  { id: 'CWE-352', label: 'CSRF' },
  { id: 'CWE-918', label: 'SSRF' },
  { id: 'CWE-78', label: 'OS Command Injection' },
  { id: 'CWE-287', label: 'Improper Authentication' },
  { id: 'CWE-862', label: 'Missing Authorization' },
  { id: 'CWE-502', label: 'Deserialization of Untrusted Data' },
  { id: 'CWE-200', label: 'Exposure of Sensitive Information' },
]

const WRITEUP_NONE = '__none__'

function NewFindingForm({ engagementId, onCreated, onCancel }: { engagementId: string; onCreated: () => void; onCancel: () => void }) {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState('medium')
  const [cwe, setCwe] = useState('')
  const [vector, setVector] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [writeups, setWriteups] = useState<Writeup[]>([])
  const [writeupId, setWriteupId] = useState(WRITEUP_NONE)

  useEffect(() => {
    let alive = true
    api.writeups().then((w) => alive && setWriteups(w)).catch(() => {})
    return () => {
      alive = false
    }
  }, [])

  // Insert a library template: prefill the finding text (the report is later
  // templated from this stored finding, no model in the path).
  function applyWriteup(id: string) {
    setWriteupId(id)
    const w = writeups.find((x) => x.id === id)
    if (!w) return
    setTitle(w.title)
    setSeverity(w.severity)
    setCwe(w.cwe)
    setDescription(w.remediation ? `${w.description}\n\nRemediation:\n${w.remediation}` : w.description)
  }

  async function submit() {
    if (!title.trim()) {
      setErr('Title is required.')
      return
    }
    setBusy(true)
    setErr(null)
    try {
      await api.createFinding(engagementId, { title, description, severity, cvssVector: vector, cwe })
      onCreated()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to create finding')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="New finding"
      actions={
        <div className="flex gap-2">
          <Button variant="ghost" onClick={onCancel} className="px-3 py-1.5">
            Cancel
          </Button>
          <Button loading={busy} onClick={submit} className="px-3 py-1.5">
            <Plus className="size-4" /> Create
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        {writeups.length > 0 && (
          <Field label="Start from library" hint="Optional — prefills the fields below with a reusable writeup">
            <Select
              value={writeupId}
              onValueChange={applyWriteup}
              ariaLabel="Insert a finding writeup template"
              options={[
                { value: WRITEUP_NONE, label: <span className="text-mutedfg">Blank finding…</span> },
                ...writeups.map((w) => ({
                  value: w.id,
                  label: (
                    <span className="flex items-center gap-2">
                      <span className="text-[10px] uppercase tracking-wide text-subtlefg">{w.category}</span>
                      {w.title}
                    </span>
                  ),
                })),
              ]}
            />
          </Field>
        )}
        <Field label="Title" htmlFor="nf-title">
          <Input id="nf-title" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Reflected XSS in search" />
        </Field>
        <Field label="Description" htmlFor="nf-desc">
          <textarea
            id="nf-desc"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
            className="input-inset w-full rounded-lg border border-border bg-elevated px-3.5 py-2.5 text-sm text-foreground outline-none transition-colors placeholder:text-subtlefg focus:border-brand focus:ring-2 focus:ring-brand/40"
            placeholder="Impact, reproduction, remediation…"
          />
        </Field>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Severity" hint={vector.trim() ? 'set by the CVSS vector below' : undefined}>
            <Select
              value={severity}
              onValueChange={setSeverity}
              ariaLabel="Severity"
              disabled={!!vector.trim()}
              options={SEVERITIES.map((s) => ({ value: s, label: <SevBadge sev={s} /> }))}
            />
          </Field>
          <Field label="CWE" htmlFor="nf-cwe">
            <Input id="nf-cwe" value={cwe} onChange={(e) => setCwe(e.target.value)} placeholder="CWE-79" list="cwe-list" />
            <datalist id="cwe-list">
              {COMMON_CWES.map((c) => (
                <option key={c.id} value={c.id} label={c.label} />
              ))}
            </datalist>
          </Field>
        </div>
        <CvssBuilder onChange={setVector} />
      </div>
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
    </Card>
  )
}

const CVSS_METRICS: { key: string; label: string; options: { v: string; l: string }[] }[] = [
  { key: 'AV', label: 'Attack Vector', options: [{ v: 'N', l: 'Network' }, { v: 'A', l: 'Adjacent' }, { v: 'L', l: 'Local' }, { v: 'P', l: 'Physical' }] },
  { key: 'AC', label: 'Attack Complexity', options: [{ v: 'L', l: 'Low' }, { v: 'H', l: 'High' }] },
  { key: 'PR', label: 'Privileges Req.', options: [{ v: 'N', l: 'None' }, { v: 'L', l: 'Low' }, { v: 'H', l: 'High' }] },
  { key: 'UI', label: 'User Interaction', options: [{ v: 'N', l: 'None' }, { v: 'R', l: 'Required' }] },
  { key: 'S', label: 'Scope', options: [{ v: 'U', l: 'Unchanged' }, { v: 'C', l: 'Changed' }] },
  { key: 'C', label: 'Confidentiality', options: [{ v: 'N', l: 'None' }, { v: 'L', l: 'Low' }, { v: 'H', l: 'High' }] },
  { key: 'I', label: 'Integrity', options: [{ v: 'N', l: 'None' }, { v: 'L', l: 'Low' }, { v: 'H', l: 'High' }] },
  { key: 'A', label: 'Availability', options: [{ v: 'N', l: 'None' }, { v: 'L', l: 'Low' }, { v: 'H', l: 'High' }] },
]

// CvssBuilder constructs a CVSS v3.1 vector from metric dropdowns and shows the
// live base score (computed server-side, the one authoritative formula).
function CvssBuilder({ onChange }: { onChange: (v: string) => void }) {
  const [enabled, setEnabled] = useState(false)
  const [metrics, setMetrics] = useState<Record<string, string>>({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' })
  const [preview, setPreview] = useState<{ score: number; severity: string } | null>(null)
  const [scoring, setScoring] = useState(false)
  const [failed, setFailed] = useState(false)

  const built = 'CVSS:3.1/' + CVSS_METRICS.map((m) => `${m.key}:${metrics[m.key]}`).join('/')

  useEffect(() => {
    if (!enabled) return
    onChange(built)
    let live = true
    setScoring(true)
    setFailed(false)
    api
      .cvssScore(built)
      .then((r) => {
        if (live) {
          setPreview(r)
          setScoring(false)
        }
      })
      .catch(() => {
        if (live) {
          setPreview(null)
          setFailed(true)
          setScoring(false)
        }
      })
    return () => {
      live = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [built, enabled])

  function toggle(on: boolean) {
    setEnabled(on)
    if (!on) {
      onChange('')
      setPreview(null)
      setFailed(false)
      setScoring(false)
    }
  }

  return (
    <div className="rounded-lg border border-border bg-bg p-3">
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={enabled} onChange={(e) => toggle(e.target.checked)} className="size-4 accent-brand" />
        <span className="font-medium text-foreground">Score with CVSS v3.1</span>
        {scoring ? (
          <Loader2 className="ml-auto size-4 animate-spin text-mutedfg" />
        ) : failed ? (
          <span className="ml-auto text-xs text-critical">score unavailable</span>
        ) : preview ? (
          <span className="ml-auto font-mono text-sm tabular-nums">
            <span className={cn('font-semibold', sevText[preview.severity as Severity] ?? 'text-foreground')}>{preview.score.toFixed(1)}</span>{' '}
            <span className="text-mutedfg">{preview.severity}</span>
          </span>
        ) : null}
      </label>
      {enabled && (
        <>
          <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {CVSS_METRICS.map((m) => (
              <Field key={m.key} label={m.label}>
                <Select
                  size="sm"
                  value={metrics[m.key]}
                  onValueChange={(v) => setMetrics((cur) => ({ ...cur, [m.key]: v }))}
                  ariaLabel={m.label}
                  options={m.options.map((o) => ({ value: o.v, label: o.l }))}
                />
              </Field>
            ))}
          </div>
          <p className="mt-2 break-all font-mono text-[11px] text-subtlefg">{built}</p>
        </>
      )}
    </div>
  )
}

function FindingsBoard({
  findings,
  engagementId,
  onUpdated,
  onReload,
}: {
  findings: Finding[]
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
      {FINDING_STATUSES.map((status) => {
        const col = findings.filter((f) => f.status === status)
        return (
          <div key={status} className="rounded-xl border border-border bg-bg">
            <div className="flex items-center justify-between border-b border-border px-3 py-2">
              <StatusLabel status={status} />
              <span className="font-mono text-xs tabular-nums text-subtlefg">{col.length}</span>
            </div>
            <div className="space-y-2 p-2">
              {col.length === 0 && <p className="px-1 py-3 text-center text-xs text-subtlefg">—</p>}
              {col.slice(0, 25).map((f) => (
                <BoardCard key={f.id} finding={f} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
              ))}
              {col.length > 25 && (
                <p className="px-1 py-2 text-center text-xs text-subtlefg">+{col.length - 25} more — switch to Table view</p>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function BoardCard({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-2.5">
      <div className="mb-1.5 flex items-center gap-1.5">
        <PriorityBadge priority={finding.priority} />
        <SevBadge sev={finding.severity} />
        {finding.kev && <KevBadge />}
      </div>
      <p className="line-clamp-2 text-sm font-medium text-foreground" title={finding.title}>
        {finding.title}
      </p>
      {finding.assignee && <p className="mt-1 text-[11px] text-mutedfg">@{finding.assignee}</p>}
      <div className="mt-2">
        <FindingStatusControl finding={finding} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
      </div>
    </div>
  )
}

function FindingCollab({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-border bg-bg p-3">
      <AssigneeControl finding={finding} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
      <CommentsPanel engagementId={engagementId} findingId={finding.id} />
      <RetestPanel finding={finding} engagementId={engagementId} onUpdated={onUpdated} />
    </div>
  )
}

const RETEST_OUTCOMES: { value: RetestOutcome; label: string }[] = [
  { value: 'remediated', label: 'Remediated' },
  { value: 'still_vulnerable', label: 'Still vulnerable' },
  { value: 'not_reproducible', label: 'Not reproducible' },
]

function RetestOutcomeBadge({ outcome }: { outcome: RetestOutcome }) {
  const tone: Record<RetestOutcome, string> = {
    remediated: 'bg-accent/10 text-accent ring-accent/25',
    still_vulnerable: 'bg-critical/10 text-critical ring-critical/25',
    not_reproducible: 'bg-elevated text-mutedfg ring-border',
  }
  const label: Record<RetestOutcome, string> = {
    remediated: 'Remediated',
    still_vulnerable: 'Still vuln',
    not_reproducible: 'Not repro',
  }
  return (
    <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ring-1 ring-inset', tone[outcome])}>
      {label[outcome]}
    </span>
  )
}

// RetestPanel shows a finding's retest history and records a new retest, which moves
// the finding to the implied status under the optimistic-concurrency version.
function RetestPanel({ finding, engagementId, onUpdated }: { finding: Finding; engagementId: string; onUpdated: (f: Finding) => void }) {
  const [list, setList] = useState<Retest[]>([])
  const [outcome, setOutcome] = useState<RetestOutcome>('remediated')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    api
      .findingRetests(engagementId, finding.id)
      .then((r) => alive && setList(r))
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [engagementId, finding.id])

  async function submit() {
    setBusy(true)
    setErr(null)
    try {
      const { retest, finding: updated } = await api.recordRetest(engagementId, finding.id, outcome, note, finding.version)
      setList((prev) => [...prev, retest])
      setNote('')
      onUpdated(updated)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setErr('Finding changed — reload and retry.')
      else setErr(e instanceof Error ? e.message : 'Failed to record retest')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-2 border-t border-border pt-3">
      <div className="flex items-center gap-1.5 text-xs font-medium text-mutedfg">
        <RotateCcw className="size-3.5" /> Retests
      </div>
      {list.length > 0 && (
        <ul className="space-y-1">
          {list.map((r) => (
            <li key={r.id} className="flex items-center gap-2 text-xs">
              <RetestOutcomeBadge outcome={r.outcome} />
              <span className="text-mutedfg">{r.tester}</span>
              {r.note && <span className="truncate text-subtlefg">— {r.note}</span>}
              <span className="ml-auto shrink-0 tabular-nums text-subtlefg">{r.at ? new Date(r.at).toLocaleDateString() : ''}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={outcome}
          onValueChange={(v) => setOutcome(v as RetestOutcome)}
          ariaLabel="Retest outcome"
          size="sm"
          options={RETEST_OUTCOMES.map((o) => ({ value: o.value, label: o.label }))}
        />
        <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="note (optional)" className="h-8 flex-1 text-sm" />
        <Button loading={busy} onClick={submit} className="px-3 py-1.5 text-sm">
          Record
        </Button>
      </div>
      {err && <p className="text-xs text-critical">{err}</p>}
    </div>
  )
}

function AssigneeControl({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [value, setValue] = useState(finding.assignee)
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<'' | 'saved' | 'failed' | 'conflict'>('')

  useEffect(() => {
    setValue(finding.assignee)
  }, [finding.assignee, finding.version])

  async function save() {
    if (value.trim() === finding.assignee) return
    setBusy(true)
    setNote('')
    try {
      onUpdated(await api.setFindingAssignee(engagementId, finding.id, value.trim(), finding.version))
      setNote('saved')
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setNote('conflict')
        onReload()
      } else {
        setNote('failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-[11px] uppercase tracking-wide text-subtlefg">Assignee</span>
      <Input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onBlur={save}
        placeholder="unassigned"
        aria-label={`Assignee for ${finding.title}`}
        className="h-8 max-w-[14rem] text-sm"
      />
      {busy && <Loader2 className="size-3.5 animate-spin text-mutedfg" />}
      {note === 'saved' && <span className="text-xs text-accent">saved</span>}
      {note === 'failed' && <span className="text-xs text-critical">failed</span>}
      {note === 'conflict' && (
        <span className="inline-flex items-center gap-1 text-xs font-medium text-medium">
          <AlertTriangle className="size-3" /> reloaded
        </span>
      )}
    </div>
  )
}

function CommentsPanel({ engagementId, findingId }: { engagementId: string; findingId: string }) {
  const [comments, setComments] = useState<FindingComment[] | null>(null)
  const [body, setBody] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  function reload() {
    api
      .findingComments(engagementId, findingId)
      .then(setComments)
      .catch(() => setComments([]))
  }
  useEffect(() => {
    reload()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [engagementId, findingId])

  async function add() {
    if (!body.trim()) return
    setBusy(true)
    setErr(null)
    try {
      await api.addFindingComment(engagementId, findingId, body.trim())
      setBody('')
      reload()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to add comment')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <div className="mb-1.5 text-[11px] uppercase tracking-wide text-subtlefg">Comments</div>
      <div className="space-y-1.5">
        {comments === null ? (
          <span className="text-xs text-subtlefg">Loading…</span>
        ) : comments.length === 0 ? (
          <span className="text-xs text-subtlefg">No comments yet.</span>
        ) : (
          comments.map((c) => (
            <div key={c.id} className="rounded-md bg-elevated px-2.5 py-1.5 text-xs">
              <span className="font-medium text-foreground">{c.author}</span>
              <span className="text-subtlefg"> · {c.createdAt ? new Date(c.createdAt).toLocaleString() : ''}</span>
              <p className="mt-0.5 whitespace-pre-line text-mutedfg">{c.body}</p>
            </div>
          ))
        )}
      </div>
      <div className="mt-2 flex items-center gap-2">
        <Input
          value={body}
          onChange={(e) => setBody(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.nativeEvent.isComposing && !busy) add()
          }}
          placeholder="Add a comment…"
          aria-label="New comment"
          className="h-8 flex-1 text-sm"
        />
        <Button loading={busy} onClick={add} variant="secondary" className="h-8 px-3">
          Post
        </Button>
      </div>
      {err && <p className="mt-1 text-xs text-critical">{err}</p>}
    </div>
  )
}
