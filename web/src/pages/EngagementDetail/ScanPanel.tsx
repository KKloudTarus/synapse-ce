import { useState, useEffect, useRef } from 'react'
import {
  AlertTriangle,
  CheckCircle,
  ChevronRight,
  Database01,
  Loading01,
  Play,
  XClose,
} from '@untitledui/icons'
import { Button, Card, ErrorState, Input, Pill, cn } from '../../components/ui'
import { usePolling } from '../../hooks'
import { api } from '../../lib/api'
import { kindLabel } from '../../lib/format'
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
      className="inline-flex h-10 max-w-full shrink-0 items-center overflow-x-auto rounded-lg border border-secondary bg-secondary p-0.5"
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
      className="inline-flex h-10 max-w-full shrink-0 items-center overflow-x-auto rounded-lg border border-secondary bg-secondary p-0.5"
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
  const [, setSBOMBusy] = useState(false)
  const [sbomError, setSBOMError] = useState<string | null>(null)
  const [sbomMessage, setSBOMMessage] = useState<string | null>(null)
  const sbomRef = useRef<HTMLInputElement>(null)

  const running = job?.status === 'running'
  const debugEvents = job?.debugEvents?.length ? job.debugEvents : (summary?.debugEvents ?? [])
  const usingImportedSBOM = Boolean(importedSBOM)

  // Authorization window guard: refuse to start a scan in the UI when the
  // engagement is outside its window – the server enforces this too (403).
  const now = Date.now()
  const notYet = eng.authorizedFrom ? now < new Date(eng.authorizedFrom).getTime() : false
  const expired = eng.authorizedTo ? now > new Date(eng.authorizedTo).getTime() : false
  const outsideWindow = notYet || expired

  // Poll scan status while a scan is running (or on mount to resume).
  const { data: polledJob } = usePolling(
    () => api.scanStatus(eng.id),
    { interval: 1500, enabled: running, deps: [eng.id] },
  )

  // Handle polled job updates: propagate status, fetch result on success.
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [polledJob])

  // Resume on mount: reflect any in-progress / finished scan so a reload keeps the
  // progress bar (and doesn't reset to "Run scan" with the scan still running).
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
    <Card bodyClass="p-4" className="mb-6">
      <input ref={sbomRef} type="file" accept="application/json,.json" className="hidden" onChange={uploadSBOM} />
      <div className="mb-3 flex flex-col gap-3 border-b border-secondary pb-3 md:flex-row md:items-center md:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm font-medium text-primary">
            <Database01 className="size-4 text-tertiary" />
            <span>{importedSBOM ? importedSBOM.filename : 'SBOM.json'}</span>
            {importedSBOM && <Pill className="bg-accent/10 text-accent ring-1 ring-inset ring-accent/30">active</Pill>}
            {importedSBOM ? (
              <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs font-normal text-tertiary">
                <span className="font-mono tabular-nums">{importedSBOM.componentCount.toLocaleString()} components</span>
                <span className="font-mono tabular-nums">{importedSBOM.dependencyCount.toLocaleString()} edges</span>
                <span className="truncate font-mono" title={importedSBOM.sha256}>{importedSBOM.sha256.slice(0, 12)}</span>
              </span>
            ) : (
              <span className="text-xs font-normal text-tertiary">No imported SBOM active</span>
            )}
          </div>
        </div>
        {/* Import SBOM moved to header Import dropdown */}
      </div>
      {(sbomError || sbomMessage) && (
        <div className={cn('mb-3 flex items-center gap-1 text-xs', sbomError ? 'text-critical' : 'text-accent')} role={sbomError ? 'alert' : 'status'}>
          {sbomError ? <AlertTriangle className="size-3.5" /> : <CheckCircle className="size-3.5" />}
          {sbomError || sbomMessage}
        </div>
      )}
      {/* Single horizontal scan bar – all controls share one height + baseline. */}
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
        {!usingImportedSBOM && (
          <label className="flex h-10 shrink-0 cursor-pointer items-center gap-2 rounded-lg border border-secondary bg-secondary px-3 text-sm text-tertiary hover:text-primary">
            <input
              type="checkbox"
              checked={codeQuality}
              onChange={(e) => setCodeQuality(e.target.checked)}
              className="size-4 accent-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
            />
            Code quality
          </label>
        )}
        {usingImportedSBOM ? (
          <div className="flex h-10 min-w-0 items-center rounded-lg border border-secondary bg-secondary px-3 font-mono text-sm text-tertiary lg:flex-1">
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
        <Button onClick={run} loading={running} disabled={running || outsideWindow} variant="secondary-color" className="h-10 lg:w-auto">
          <Play className="size-4" />
          {running ? 'Scanning…' : 'Run scan'}
        </Button>
      </div>

      {!usingImportedSBOM && kind === 'local' && (
        <p className="mt-2 text-xs text-tertiary">
          Local scans run on the server path you enter. Use an absolute folder path inside this engagement&rsquo;s scope.
        </p>
      )}

      {outsideWindow && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-critical/40 bg-critical/10 p-3 text-xs text-critical">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>
            {expired ? 'Authorization window has expired' : 'Authorization window has not started'} – scanning is
            disabled. Update the engagement’s window to proceed.
          </span>
        </div>
      )}

      {running && (
        <div className="mt-4">
          <div className="mb-1.5 flex items-center justify-between text-xs">
            <span className="capitalize text-primary">{job?.stage || 'starting'}…</span>
            <span className="font-mono tabular-nums text-tertiary">{job?.progress ?? 0}%</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-secondary">
            <div
              className="h-full rounded-full bg-brand-solid transition-[width] duration-500 ease-out"
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

      {/* Pipeline description tucked away – the scan flow reads in 3 seconds without it. */}
      <details className="group mt-3 text-xs">
        <summary className="inline-flex cursor-pointer select-none items-center gap-1 text-tertiary transition-colors hover:text-primary">
          <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" />
          Pipeline &amp; enforcement
        </summary>
        <p className="mt-2 pl-4 text-tertiary">
          detect languages → SBOM (Syft) → selected vulnerability/license stages → findings. Enforced against this
          engagement&rsquo;s scope, server-side.
        </p>
      </details>
    </Card>
  )
}

export function ScanDebugTimeline({ events, running }: { events: ScanDebugEvent[]; running: boolean }) {
  if (!events.length && !running) return null
  const visibleEvents = events.slice(-12)
  return (
    <details className="group mt-3 text-xs" open={running}>
      <summary className="inline-flex cursor-pointer select-none items-center gap-1 text-tertiary transition-colors hover:text-primary">
        <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" />
        Debug timeline
        {events.length > 0 && <span className="font-mono tabular-nums text-tertiary">({events.length})</span>}
      </summary>
      <div className="mt-2 space-y-2 rounded-lg border border-secondary bg-primary p-3">
        {visibleEvents.length === 0 ? (
          <div className="flex items-center gap-2 text-tertiary">
            <Loading01 className="size-3.5 animate-spin" />
            Waiting for scan steps…
          </div>
        ) : (
          visibleEvents.map((event, idx) => <ScanDebugRow key={`${event.stage}-${event.step}-${idx}`} event={event} />)
        )}
      </div>
    </details>
  )
}

export function ScanDebugRow({ event }: { event: ScanDebugEvent }) {
  const failed = event.status === 'failed'
  const running = event.status === 'running'
  const Icon = failed ? XClose : running ? Loading01 : CheckCircle
  const counts = formatDebugCounts(event.counts)
  return (
    <div className="flex items-start gap-2 rounded-md bg-secondary px-3 py-2">
      <Icon
        className={cn(
          'mt-0.5 size-3.5 shrink-0',
          failed ? 'text-critical' : running ? 'animate-spin text-brand-secondary' : 'text-accent',
        )}
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="font-medium text-primary">{event.step || event.stage}</span>
          {event.tool && <span className="font-mono text-[11px] text-tertiary">{event.tool}</span>}
          <span className="font-mono text-[11px] tabular-nums text-tertiary">
            {running ? 'running' : fmtDebugDuration(event.durationMs)}
          </span>
        </div>
        <div className={cn('mt-0.5 text-tertiary', failed && 'text-critical')}>{event.error || event.message}</div>
        {counts && <div className="mt-1 font-mono text-[11px] tabular-nums text-tertiary">{counts}</div>}
      </div>
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
