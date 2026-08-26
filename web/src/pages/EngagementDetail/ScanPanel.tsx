import { useState, useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowRight,
  Calendar,
  Check,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Clock,
  Copy01,
  Database01,
  FileCheck01,
  FileCheck02,
  HelpCircle,
  Loading01,
  Package,
  Play,
  Settings01,
  ShieldTick,
  Target04,
  Upload01,
  XClose,
} from '@untitledui/icons'
import { Button, Card, ErrorState, Input, Pill, cn } from '../../components/ui'
import { Tooltip, TooltipTrigger } from '@/components/base/tooltip/tooltip'
import { useFetch, usePolling } from '../../hooks'
import { api } from '../../lib/api'
import { kindLabel } from '../../lib/format'
import { StatusPill } from '../Engagements'
import { fmtWindow } from './VulnsTab'
import type { Engagement, ImportedSBOMMetadata, ScanDebugEvent, ScanJob, ScanMode, ScanResult } from '../../lib/types'

export function trapTabFocus(e: KeyboardEvent, panel: HTMLElement | null) {
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

export function ScopeBadge({ target }: { target: { kind: string; value: string } }) {
  const [copied, setCopied] = useState(false)
  const displayValue =
    target.kind === 'repo' && target.value.includes('/')
      ? target.value.split('/').slice(-1)[0].replace(/\.git$/, '')
      : target.value

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation()
    navigator.clipboard.writeText(target.value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md border border-utility-blue-200 bg-utility-blue-50 py-0.5 pl-1.5 pr-1 text-xs text-utility-blue-700 font-medium"
      title={target.value}
    >
      <span className="rounded bg-utility-blue-100 px-1 py-0.2 text-[9px] font-bold uppercase tracking-wide text-utility-blue-700">
        {kindLabel(target.kind)}
      </span>
      <span className="font-mono font-semibold text-primary">{displayValue}</span>
      <button
        type="button"
        onClick={handleCopy}
        className="inline-flex size-4 items-center justify-center rounded transition-colors hover:bg-utility-blue-200 hover:text-utility-blue-800 focus-visible:outline-none"
        title={copied ? 'Copied full URL!' : 'Copy full URL'}
      >
        {copied ? (
          <Check className="size-3 text-success-primary" />
        ) : (
          <Copy01 className="size-3 text-fg-tertiary hover:text-primary" />
        )}
      </button>
    </span>
  )
}

export function EvidenceBadge({ engagementId }: { engagementId: string }) {
  const { data: ev } = useFetch(
    () =>
      api.evidence(engagementId).then((e) =>
        e && e.verified > 0 ? { intact: e.intact, verified: e.verified, keyId: e.attestation?.key_id } : null,
      ),
    { deps: [engagementId] },
  )
  if (!ev) return null
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold',
        ev.intact
          ? 'border-utility-green-300 bg-success-primary text-success-primary'
          : 'border-error bg-error-primary text-error-primary',
      )}
      title={
        ev.intact
          ? `${ev.verified} verified links in hash chain${ev.keyId ? ` (signed by ${ev.keyId})` : ''}`
          : 'Evidence integrity compromised'
      }
    >
      <ShieldTick className="size-3.5" />
      <span>{ev.intact ? 'Evidence verified' : 'Evidence tampered'}</span>
    </span>
  )
}

export const KINDS = ['git', 'local', 'archive', 'image']

export const SCAN_MODES: Array<{ value: ScanMode; label: string }> = [
  { value: 'full', label: 'Full' },
  { value: 'vulnerabilities', label: 'Vulns' },
  { value: 'licenses', label: 'Licenses' },
]

export function detectKind(target: string): string {
  return /^https?:\/\//i.test(target.trim()) ? 'git' : 'local'
}

export function SegmentedKind({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div
      role="radiogroup"
      aria-label="Target kind"
      className="inline-flex h-9 max-w-full shrink-0 items-center overflow-x-auto rounded-lg border border-secondary bg-secondary p-0.5"
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
              'h-full rounded-md px-3 text-xs font-semibold transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-solid',
              active ? 'bg-primary text-primary shadow-xs' : 'text-tertiary hover:text-primary',
            )}
          >
            {kindLabel(k)}
          </button>
        )
      })}
    </div>
  )
}

export function SegmentedScanMode({ value, onChange }: { value: ScanMode; onChange: (v: ScanMode) => void }) {
  return (
    <div
      role="radiogroup"
      aria-label="Scan mode"
      className="inline-flex h-9 max-w-full shrink-0 items-center overflow-x-auto rounded-lg border border-secondary bg-secondary p-0.5"
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
              'h-full rounded-md px-3 text-xs font-semibold transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-solid',
              active ? 'bg-primary text-primary shadow-xs' : 'text-tertiary hover:text-primary',
            )}
          >
            {m.label}
          </button>
        )
      })}
    </div>
  )
}

export function ScanPanel({
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
  const [codeQuality, setCodeQuality] = useState(false)
  const [branch, setBranch] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [summary, setSummary] = useState<ScanResult | null>(null)
  const [configOpen, setConfigOpen] = useState(false)
  const [sbomBusy, setSBOMBusy] = useState(false)
  const [sbomError, setSBOMError] = useState<string | null>(null)
  const [sbomMessage, setSBOMMessage] = useState<string | null>(null)
  const sbomRef = useRef<HTMLInputElement>(null)

  const { data: businessAsset } = useFetch(
    () => (eng.businessAssetId ? api.getBusinessAsset(eng.businessAssetId).catch(() => null) : Promise.resolve(null)),
    { deps: [eng.businessAssetId] },
  )

  const running = job?.status === 'running'
  const debugEvents = job?.debugEvents?.length ? job.debugEvents : (summary?.debugEvents ?? [])
  const usingImportedSBOM = Boolean(importedSBOM)

  const now = Date.now()
  const notYet = eng.authorizedFrom ? now < new Date(eng.authorizedFrom).getTime() : false
  const expired = eng.authorizedTo ? now > new Date(eng.authorizedTo).getTime() : false
  const outsideWindow = notYet || expired

  const { data: polledJob } = usePolling(
    () => api.scanStatus(eng.id),
    { interval: 1500, enabled: running, deps: [eng.id] },
  )

  useEffect(() => {
    if (!polledJob) return
    setJob(polledJob)
    if (polledJob.status === 'succeeded') {
      api.latestScan(eng.id).then((res) => {
        if (res) {
          setSummary(res)
          onScanned(res)
        }
      }).catch(() => undefined)
    } else if (polledJob.status === 'failed') {
      setError(polledJob.error || 'Scan failed')
    }
  }, [polledJob])

  useEffect(() => {
    let live = true
    api
      .scanStatus(eng.id)
      .then(async (j) => {
        if (!live || !j) return
        setJob(j)
        if (j.status === 'failed') setError(j.error || 'Scan failed')
        else if (j.status === 'succeeded') {
          const res = await api.latestScan(eng.id).catch(() => null)
          if (live && res) setSummary(res)
        }
      })
      .catch(() => undefined)
    return () => {
      live = false
    }
  }, [eng.id])

  async function run() {
    if (!usingImportedSBOM && !target.trim()) {
      setError('Enter a target in Scan Settings.')
      setConfigOpen(true)
      return
    }
    setError(null)
    setSummary(null)
    try {
      const ref = kind === 'git' ? branch.trim() : ''
      setJob(await api.startScan(eng.id, usingImportedSBOM ? '' : target.trim(), usingImportedSBOM ? 'imported-sbom' : kind, ref, mode, codeQuality))
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
    <div className="space-y-4">
      <input ref={sbomRef} type="file" accept="application/json,.json" className="hidden" onChange={uploadSBOM} />

      {/* Hero Header: Left (Title + Metadata) & Right (2 Big Action Buttons, vertically centered) */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="min-w-0 space-y-2">
          {/* Row 1: Title, Status Pill, Evidence Badge */}
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-primary">{eng.name}</h1>
            <StatusPill status={eng.status} />
            <EvidenceBadge engagementId={eng.id} />
          </div>

          {/* Row 2: Metadata row with Human-Readable Asset Name */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-tertiary">
            {eng.client && <span className="font-semibold text-primary">{eng.client}</span>}
            {eng.businessAssetId && (
              <Link
                to={`/assets/${encodeURIComponent(businessAsset?.key || eng.businessAssetId)}`}
                className="inline-flex items-center gap-1.5 font-semibold text-brand-secondary hover:underline"
              >
                <Package className="size-3.5 text-brand-secondary" />
                <span>Asset: {businessAsset?.name || 'Loading…'}</span>
              </Link>
            )}
            {eng.inScope.length > 1 && (
              <span className="flex items-center gap-1.5 font-semibold text-primary">
                <Target04 className="size-3.5 text-fg-tertiary" /> {eng.inScope.length} in scope
              </span>
            )}
            {eng.inScope.map((t, i) => (
              <ScopeBadge key={i} target={t} />
            ))}
            {(eng.authorizedFrom || eng.authorizedTo) && (
              <span className="flex items-center gap-1.5 font-mono">
                <Calendar className="size-3.5" /> {fmtWindow(eng.authorizedFrom, eng.authorizedTo)}
              </span>
            )}
          </div>
        </div>

        {/* 2 Big Action Buttons vertically centered on the right */}
        <div className="flex items-center gap-3 shrink-0">
          <Button
            type="button"
            variant="secondary"
            onClick={() => setConfigOpen(true)}
            className="h-10 px-5 text-sm font-semibold rounded-xl shadow-xs transition-transform active:scale-[0.98]"
          >
            <Settings01 className="size-4 text-secondary" />
            <span>Scan settings</span>
          </Button>

          <Button
            onClick={run}
            loading={running}
            disabled={running || outsideWindow}
            variant="brand"
            className="h-10 px-6 text-sm font-bold rounded-xl shadow-xs transition-transform active:scale-[0.98]"
          >
            <Play className="size-4" />
            <span>{running ? 'Scanning…' : 'Run scan'}</span>
          </Button>
        </div>
      </div>

      {(sbomError || sbomMessage) && (
        <div
          className={cn(
            'flex items-center gap-1.5 text-xs font-medium',
            sbomError ? 'text-error-primary' : 'text-success-primary',
          )}
          role={sbomError ? 'alert' : 'status'}
        >
          {sbomError ? <AlertTriangle className="size-3.5" /> : <CheckCircle className="size-3.5" />}
          {sbomError || sbomMessage}
        </div>
      )}

      {outsideWindow && (
        <div className="flex items-start gap-2 rounded-lg border border-error bg-error-primary p-3 text-xs text-error-primary">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-fg-error-primary" />
          <span>
            {expired ? 'Authorization window has expired' : 'Authorization window has not started'}: scanning is disabled. Update the engagement authorization window to proceed.
          </span>
        </div>
      )}

      {running && (
        <div>
          <div className="mb-1.5 flex items-center justify-between text-xs">
            <span className="font-semibold capitalize text-primary">{job?.stage || 'starting'}…</span>
            <span className="font-mono font-bold tabular-nums text-tertiary">{job?.progress ?? 0}%</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-secondary">
            <div
              className="h-full rounded-full bg-brand-solid transition-[width] duration-500 ease-out"
              style={{ width: `${Math.max(3, job?.progress ?? 0)}%` }}
            />
          </div>
        </div>
      )}

      {/* Horizontal Pipeline Journey Track (kept in place) */}
      <ScanDebugTimeline events={debugEvents} running={running} />

      {error && (
        <div>
          <ErrorState message={error} />
        </div>
      )}

      {summary && !running && summary.completeness.warning && (
        <div className="flex items-start gap-2 rounded-lg border border-utility-orange-300 bg-warning-primary p-3 text-xs text-warning-primary">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-fg-warning-primary" />
          <span>{summary.completeness.warning}</span>
        </div>
      )}

      {/* ModalForm for Scan Configuration */}
      <ScanConfigModal
        open={configOpen}
        onClose={() => setConfigOpen(false)}
        kind={kind}
        setKind={(v) => {
          setKind(v)
          setKindManual(true)
        }}
        mode={mode}
        setMode={setMode}
        codeQuality={codeQuality}
        setCodeQuality={setCodeQuality}
        target={target}
        setTarget={(v) => {
          setTarget(v)
          if (!kindManual) setKind(detectKind(v))
        }}
        branch={branch}
        setBranch={setBranch}
        usingImportedSBOM={usingImportedSBOM}
        importedSBOM={importedSBOM}
        onTriggerUpload={() => sbomRef.current?.click()}
        sbomBusy={sbomBusy}
        onRun={run}
        running={running}
      />
    </div>
  )
}

export function ScanConfigModal({
  open,
  onClose,
  kind,
  setKind,
  mode,
  setMode,
  codeQuality,
  setCodeQuality,
  target,
  setTarget,
  branch,
  setBranch,
  usingImportedSBOM,
  importedSBOM,
  onTriggerUpload,
  sbomBusy,
  onRun,
  running,
}: {
  open: boolean
  onClose: () => void
  kind: string
  setKind: (v: string) => void
  mode: ScanMode
  setMode: (v: ScanMode) => void
  codeQuality: boolean
  setCodeQuality: (v: boolean) => void
  target: string
  setTarget: (v: string) => void
  branch: string
  setBranch: (v: string) => void
  usingImportedSBOM: boolean
  importedSBOM: ImportedSBOMMetadata | null
  onTriggerUpload: () => void
  sbomBusy: boolean
  onRun: () => void
  running: boolean
}) {
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onClose()
        return
      }
      if (e.key === 'Tab') {
        trapTabFocus(e, panelRef.current)
      }
    }
    if (open) {
      document.addEventListener('keydown', handleKeyDown)
      document.body.style.overflow = 'hidden'
      return () => {
        document.removeEventListener('keydown', handleKeyDown)
        document.body.style.overflow = ''
      }
    }
  }, [open, onClose])

  if (!open) return null

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop overlay */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal Dialog */}
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="scan-config-modal-title"
        className="relative z-10 w-full max-w-xl max-h-[90vh] flex flex-col rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4">
          <h2 id="scan-config-modal-title" className="text-base font-bold text-primary flex items-center gap-2">
            <Settings01 className="size-4.5 text-brand-secondary" />
            <span>Scan Configuration</span>
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-tertiary transition-colors hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
            aria-label="Close modal"
          >
            <XClose className="size-4" />
          </button>
        </div>

        {/* Modal Form Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 text-xs">
          {/* Target Source Type */}
          {!usingImportedSBOM ? (
            <div className="space-y-1.5">
              <label className="block font-semibold text-secondary">Target Type</label>
              <SegmentedKind value={kind} onChange={setKind} />
            </div>
          ) : (
            <div className="rounded-xl border border-utility-green-300 bg-success-primary p-3.5 text-success-primary space-y-1">
              <div className="flex items-center gap-2 font-bold text-sm">
                <Database01 className="size-4" />
                <span>Imported SBOM Active</span>
              </div>
              <p className="text-xs">
                Scanning target is locked to the uploaded SBOM file: <span className="font-mono font-semibold">{importedSBOM?.filename}</span>
              </p>
            </div>
          )}

          {/* Target Location / URL */}
          <div className="space-y-1.5">
            <label htmlFor="scan-target-input" className="block font-semibold text-secondary">
              {kind === 'git' ? 'Repository URL' : 'Target Path / Location'}
            </label>
            {usingImportedSBOM ? (
              <div className="flex h-9 min-w-0 items-center rounded-lg border border-secondary bg-secondary px-3 font-mono text-xs text-tertiary">
                <span className="truncate">{importedSBOM?.targetRef || importedSBOM?.filename || 'SBOM.json'}</span>
              </div>
            ) : (
              <Input
                id="scan-target-input"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={kind === 'git' ? 'https://github.com/org/repo' : '/path/to/target'}
                className="h-9 w-full font-mono text-xs"
                aria-label="Scan target"
              />
            )}
            {!usingImportedSBOM && kind === 'local' && (
              <p className="text-[11px] text-tertiary">
                Use an absolute folder path on the server inside this engagement scope.
              </p>
            )}
          </div>

          {/* Branch / Tag if Git */}
          {!usingImportedSBOM && kind === 'git' && (
            <div className="space-y-1.5">
              <label htmlFor="scan-branch-input" className="block font-semibold text-secondary">
                Branch / Tag <span className="font-normal text-quaternary">(optional)</span>
              </label>
              <Input
                id="scan-branch-input"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                placeholder="e.g. main, v1.2.0"
                className="h-9 w-full font-mono text-xs"
                aria-label="Git branch"
              />
            </div>
          )}

          {/* Scan Mode */}
          <div className="space-y-1.5">
            <label className="block font-semibold text-secondary">Scan Analysis Scope</label>
            <SegmentedScanMode value={mode} onChange={setMode} />
          </div>

          {/* Code Quality Checkbox */}
          {!usingImportedSBOM && (
            <div className="rounded-xl border border-secondary bg-secondary p-3.5">
              <label className="flex items-center gap-2.5 font-semibold text-primary cursor-pointer">
                <input
                  type="checkbox"
                  checked={codeQuality}
                  onChange={(e) => setCodeQuality(e.target.checked)}
                  className="size-4 rounded accent-brand-solid"
                />
                <span>Include Static Code Quality Analysis</span>
              </label>
              <p className="mt-1 text-[11px] text-tertiary pl-6.5">
                Evaluates maintainability ratings, duplicated lines, code smells, and technical debt.
              </p>
            </div>
          )}

          {/* SBOM Upload Option */}
          <div className="rounded-xl border border-dashed border-secondary bg-secondary p-3.5 text-center space-y-2">
            <div className="text-xs font-semibold text-secondary">Or scan with an external SBOM document</div>
            <Button
              type="button"
              variant="secondary"
              loading={sbomBusy}
              onClick={onTriggerUpload}
              className="h-8 text-xs font-semibold mx-auto"
            >
              <Upload01 className="size-3.5" />
              <span>{importedSBOM ? 'Replace SBOM (.json)' : 'Upload SBOM (.json)'}</span>
            </Button>
          </div>
        </div>

        {/* Footer: Single primary action button only (per DESIGN-REFERENCE.md rule) */}
        <div className="flex items-center justify-end border-t border-secondary px-6 py-4 bg-secondary">
          <Button
            variant="primary"
            loading={running}
            onClick={() => {
              onClose()
              onRun()
            }}
            className="h-9 px-5 text-xs font-semibold"
          >
            <Play className="size-3.5" />
            <span>Save &amp; Run scan</span>
          </Button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

export function ScanDebugTimeline({ events, running }: { events: ScanDebugEvent[]; running: boolean }) {
  if (!events.length && !running) return null
  const [selectedIdx, setSelectedIdx] = useState<number>(Math.max(0, events.length - 1))

  // Update selected index when new events arrive
  useEffect(() => {
    if (events.length > 0) {
      setSelectedIdx(events.length - 1)
    }
  }, [events.length])

  const selectedEvent = events[selectedIdx] ?? events[events.length - 1]

  return (
    <details className="group mt-3 text-xs" open={running || events.length > 0}>
      <summary className="inline-flex cursor-pointer select-none items-center gap-1.5 font-semibold text-secondary transition-colors hover:text-primary">
        <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" />
        <span>Pipeline Journey Track</span>
        <span onClick={(e) => e.stopPropagation()} className="inline-flex items-center">
          <Tooltip
            title="Pipeline Journey"
            description="Language detection → SBOM (Syft) → Vulnerability/License scan → Finding correlation."
            placement="top"
            delay={0}
            arrow
          >
            <TooltipTrigger className="inline-flex cursor-help items-center text-tertiary hover:text-primary">
              <HelpCircle className="size-3.5" />
            </TooltipTrigger>
          </Tooltip>
        </span>
        {events.length > 0 && (
          <span className="rounded-full bg-secondary px-1.5 py-0.2 font-mono text-[10px] font-bold tabular-nums text-tertiary">
            {events.length} steps
          </span>
        )}
      </summary>

      <div className="mt-2.5 rounded-xl border border-secondary bg-primary p-3.5 shadow-2xs">
        {events.length === 0 ? (
          <div className="flex items-center gap-2 py-2 text-tertiary">
            <Loading01 className="size-4 animate-spin text-brand-secondary" />
            <span>Waiting for scan steps…</span>
          </div>
        ) : (
          <div className="space-y-3">
            {/* Horizontal Timeline Rail (Scrollable) with Directed Connectors */}
            <div className="relative overflow-x-auto pb-2 pt-1">
              <div className="flex items-center gap-1.5 min-w-max px-1">
                {events.map((event, idx) => {
                  const failed = event.status === 'failed'
                  const isRunningStep = event.status === 'running'
                  const isSelected = selectedIdx === idx
                  const Icon = failed ? XClose : isRunningStep ? Loading01 : CheckCircle

                  return (
                    <div key={`${event.stage}-${event.step}-${idx}`} className="flex items-center">
                      {/* Step Milestone Node */}
                      <button
                        type="button"
                        onClick={() => setSelectedIdx(idx)}
                        className={cn(
                          'group relative flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-left transition-all',
                          isSelected
                            ? 'border-brand-solid bg-brand-primary shadow-xs ring-1 ring-brand-solid'
                            : 'border-secondary bg-secondary hover:border-brand-solid hover:bg-primary',
                        )}
                        title={`Click to inspect step: ${event.step || event.stage}`}
                      >
                        <span
                          className={cn(
                            'flex size-5 shrink-0 items-center justify-center rounded-full border',
                            failed
                              ? 'border-error bg-error-primary text-fg-error-primary'
                              : isRunningStep
                                ? 'border-brand bg-primary text-brand-secondary'
                                : 'border-utility-green-400 bg-primary text-fg-success-primary',
                          )}
                        >
                          <Icon className={cn('size-3.5', isRunningStep && 'animate-spin')} />
                        </span>

                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span
                              className={cn(
                                'truncate font-mono text-xs font-semibold',
                                isSelected ? 'text-brand-secondary' : 'text-primary',
                              )}
                            >
                              {event.step || event.stage}
                            </span>
                            <span className="font-mono text-[10px] tabular-nums text-tertiary">
                              {isRunningStep ? 'running' : fmtDebugDuration(event.durationMs)}
                            </span>
                          </div>
                        </div>
                      </button>

                      {/* Directed Arrow Connector to next step */}
                      {idx < events.length - 1 && (
                        <div className="mx-1.5 flex items-center shrink-0">
                          <div
                            className={cn(
                              'h-0.5 w-2.5',
                              event.status === 'succeeded' ? 'bg-brand-solid' : 'bg-secondary',
                            )}
                          />
                          <ArrowRight
                            className={cn(
                              'size-3.5 -ml-1',
                              event.status === 'succeeded'
                                ? 'text-brand-secondary font-bold'
                                : 'text-quaternary',
                            )}
                          />
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Selected Step Inspector Card matching customer mockup */}
            {selectedEvent && <StepInspectorCard event={selectedEvent} />}
          </div>
        )}
      </div>
    </details>
  )
}

const PROCESSING_KEYS = new Set([
  'attempted',
  'candidates',
  'critiqued',
  'gate_exempt',
  'max_findings',
  'input_count',
  'total',
  'processed',
])

const DECISION_KEYS = new Set([
  'review_required',
  'skipped_budget',
  'suspected_fp',
  'would_exempt',
  'exempt',
  'allowed',
  'denied',
  'passed',
  'failed',
  'verified',
])

function StepInspectorCard({ event }: { event: ScanDebugEvent }) {
  const [showDetails, setShowDetails] = useState(false)

  const counts = event.counts ?? {}
  const countEntries = Object.entries(counts)

  // Split into Processing and Decision groups if applicable
  let processingEntries = countEntries.filter(([k]) => PROCESSING_KEYS.has(k.toLowerCase()))
  let decisionEntries = countEntries.filter(([k]) => DECISION_KEYS.has(k.toLowerCase()))

  // Fallback if keys don't match predefined sets
  if (processingEntries.length === 0 && decisionEntries.length === 0 && countEntries.length > 0) {
    const mid = Math.ceil(countEntries.length / 2)
    processingEntries = countEntries.slice(0, mid)
    decisionEntries = countEntries.slice(mid)
  }

  const hasMetrics = countEntries.length > 0

  return (
    <div className="rounded-2xl border border-secondary bg-primary p-4 sm:p-5 shadow-xs space-y-4 transition-all">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          {/* Target/Status Icon Box */}
          <div
            className={cn(
              'flex size-10 shrink-0 items-center justify-center rounded-xl border',
              event.status === 'failed'
                ? 'border-error bg-error-primary text-error-primary'
                : event.status === 'running'
                  ? 'border-brand bg-primary text-brand-secondary'
                  : 'border-utility-green-300 bg-success-primary text-success-primary',
            )}
          >
            {event.status === 'failed' ? (
              <AlertTriangle className="size-5" />
            ) : event.status === 'running' ? (
              <Loading01 className="size-5 animate-spin" />
            ) : (
              <Target04 className="size-5" />
            )}
          </div>

          {/* Title & Metadata */}
          <div className="flex flex-wrap items-center gap-2.5">
            <h3 className="font-mono text-base font-bold text-primary sm:text-lg">
              {event.step || event.stage}
            </h3>

            {/* Status Pill */}
            <span
              className={cn(
                'inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold capitalize',
                event.status === 'failed'
                  ? 'border-error bg-error-primary text-error-primary'
                  : event.status === 'running'
                    ? 'border-brand bg-primary text-brand-secondary'
                    : 'border-utility-green-300 bg-success-primary text-success-primary',
              )}
            >
              {event.status === 'succeeded' && <CheckCircle className="size-3.5" />}
              {event.status === 'failed' && <AlertTriangle className="size-3.5" />}
              {event.status === 'running' && <Loading01 className="size-3.5 animate-spin" />}
              <span>{event.status}</span>
            </span>

            {/* Duration */}
            <span className="flex items-center gap-1.5 font-mono text-xs font-semibold text-tertiary">
              <Clock className="size-3.5 text-quaternary" />
              <span>{event.status === 'running' ? 'in progress' : fmtDebugDuration(event.durationMs)}</span>
            </span>
          </div>
        </div>

        {/* View Details Button */}
        <button
          type="button"
          onClick={() => setShowDetails(!showDetails)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-secondary bg-primary px-3 py-1.5 text-xs font-semibold text-secondary hover:bg-secondary hover:text-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
        >
          <span>View details</span>
          {showDetails ? <ChevronUp className="size-3.5 text-tertiary" /> : <ChevronDown className="size-3.5 text-tertiary" />}
        </button>
      </div>

      {/* Error Message if any */}
      {event.error && (
        <div className="rounded-lg border border-error bg-error-primary p-3 text-xs font-semibold text-error-primary">
          {event.error}
        </div>
      )}

      {/* Structured Metrics Groups */}
      {hasMetrics && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          {/* Card 1: Processing */}
          {processingEntries.length > 0 && (
            <div className="rounded-xl border border-secondary bg-secondary p-3.5 space-y-2.5">
              <div className="flex items-center gap-1.5 text-xs font-bold text-brand-secondary">
                <Target04 className="size-4" />
                <span>Processing</span>
              </div>
              <div className="flex items-center divide-x divide-secondary overflow-x-auto">
                {processingEntries.map(([k, v]) => (
                  <div key={k} className="flex-1 min-w-[4.5rem] px-2 first:pl-0 last:pr-0 text-center space-y-0.5">
                    <div className="text-[11px] font-semibold text-tertiary capitalize truncate" title={k.replaceAll('_', ' ')}>
                      {k.replaceAll('_', ' ')}
                    </div>
                    <div
                      className={cn(
                        'font-mono text-lg sm:text-xl font-extrabold tabular-nums',
                        v > 0 ? 'text-brand-solid' : 'text-tertiary',
                      )}
                    >
                      {v}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Card 2: Decision */}
          {decisionEntries.length > 0 && (
            <div className="rounded-xl border border-secondary bg-secondary p-3.5 space-y-2.5">
              <div className="flex items-center gap-1.5 text-xs font-bold text-utility-blue-700">
                <FileCheck02 className="size-4" />
                <span>Decision</span>
              </div>
              <div className="flex items-center divide-x divide-secondary overflow-x-auto">
                {decisionEntries.map(([k, v]) => (
                  <div key={k} className="flex-1 min-w-[4.5rem] px-2 first:pl-0 last:pr-0 text-center space-y-0.5">
                    <div className="text-[11px] font-semibold text-tertiary capitalize truncate" title={k.replaceAll('_', ' ')}>
                      {k.replaceAll('_', ' ')}
                    </div>
                    <div
                      className={cn(
                        'font-mono text-lg sm:text-xl font-extrabold tabular-nums',
                        v > 0 ? 'text-utility-blue-700' : 'text-tertiary',
                      )}
                    >
                      {v}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Raw Details Expansion */}
      {showDetails && (
        <div className="rounded-xl border border-secondary bg-primary p-3.5 font-mono text-xs text-tertiary space-y-2">
          <div className="text-[11px] font-bold text-secondary uppercase tracking-wider">Raw Step Event Payload</div>
          <pre className="overflow-x-auto rounded-lg border border-secondary bg-secondary p-3 text-[11px] text-primary">
            {JSON.stringify(event, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

export function formatDebugCounts(counts: Record<string, number>) {
  const entries = Object.entries(counts ?? {})
  if (entries.length === 0) return ''
  return entries.map(([key, value]) => `${key.replaceAll('_', ' ')}: ${value}`).join(' · ')
}

export function fmtDebugDuration(ms: number) {
  if (ms < 1000) return `${Math.max(0, ms)}ms`
  return `${(ms / 1000).toFixed(1)}s`
}
