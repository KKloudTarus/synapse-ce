import { AlertTriangle, Calendar, CheckCircle, Package, Play, Settings01, Target04 } from '@untitledui/icons'
import { useState, useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { Button, ErrorState } from '../../components/ui'
import { cn } from '../../components/ui'
import { useFetch, usePolling } from '../../hooks'
import { api } from '../../lib/api'
import { StatusPill } from '../Engagements'
import { fmtWindow } from './VulnsTab'
import type { Engagement, ImportedSBOMMetadata, ScanJob, ScanMode, ScanResult, UploadedSourcePackage } from '../../lib/types'
import { EvidenceBadge, ScopeBadge } from './components/ScanBadges'
import { ScanConfigModal, detectKind } from './components/ScanConfigModal'
import { ScanDebugTimeline } from './components/ScanDebugTimeline'

// Re-export shared helpers consumed by sibling modules (ReportBuilderModal).
export { trapTabFocus } from './components/ScanConfigModal'

const UPLOADED_SOURCE_TARGET = /^uploaded-source\/sha256\/[0-9a-f]{64}$/

function isUploadedSourceTarget(value: string) {
  return UPLOADED_SOURCE_TARGET.test(value.trim())
}

export function ScanPanel({
  eng,
  importedSBOM,
  uploadedSource,
  initialError,
  onImportedSBOMChanged,
  job,
  setJob,
  onScanned,
}: {
  eng: Engagement
  importedSBOM: ImportedSBOMMetadata | null
  uploadedSource: UploadedSourcePackage | null
  initialError?: string
  onImportedSBOMChanged: () => void
  job: ScanJob | null
  setJob: (j: ScanJob | null) => void
  onScanned: (r: ScanResult) => void
}) {
  const usingUploadedSource = Boolean(uploadedSource) || eng.inScope.some((scopeTarget) => isUploadedSourceTarget(scopeTarget.value))
  const visibleScope = eng.inScope.filter((scopeTarget) => !isUploadedSourceTarget(scopeTarget.value))
  const target0 = usingUploadedSource ? '' : (eng.inScope[0]?.value ?? '')
  const [target, setTarget] = useState(target0)
  const [kind, setKind] = useState(usingUploadedSource ? 'upload' : detectKind(target0))
  const [kindManual, setKindManual] = useState(false)
  const [mode, setMode] = useState<ScanMode>('full')
  const [codeQuality, setCodeQuality] = useState(false)
  const [branch, setBranch] = useState('')
  const [error, setError] = useState<string | null>(initialError ?? null)
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
  const usingImportedSBOM = Boolean(importedSBOM) && !usingUploadedSource

  useEffect(() => {
    if (!usingUploadedSource) return
    setKind('upload')
    setKindManual(true)
    setTarget('')
    setBranch('')
  }, [usingUploadedSource])

  useEffect(() => {
    if (initialError) setError(initialError)
  }, [initialError])

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
    if (!usingUploadedSource && !usingImportedSBOM && !target.trim()) {
      setError('Enter a target in Scan Settings.')
      setConfigOpen(true)
      return
    }
    setError(null)
    setSummary(null)
    try {
      const ref = kind === 'git' ? branch.trim() : ''
      const scanKind = usingUploadedSource ? 'upload' : (usingImportedSBOM ? 'imported-sbom' : kind)
      setJob(await api.startScan(eng.id, usingUploadedSource || usingImportedSBOM ? '' : target.trim(), scanKind, ref, mode, codeQuality))
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
            {uploadedSource && (
              <span className="flex min-w-0 items-center gap-1.5 font-semibold text-primary" title={uploadedSource.sha256}>
                <Package className="size-3.5 shrink-0 text-brand-secondary" />
                <span className="max-w-64 truncate">Source: {uploadedSource.filename}</span>
              </span>
            )}
            {visibleScope.length > 1 && (
              <span className="flex items-center gap-1.5 font-semibold text-primary">
                <Target04 className="size-3.5 text-fg-tertiary" /> {visibleScope.length} in scope
              </span>
            )}
            {visibleScope.map((t, i) => (
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
            variant="primary"
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
        usingUploadedSource={usingUploadedSource}
        uploadedSource={uploadedSource}
        onTriggerUpload={() => sbomRef.current?.click()}
        sbomBusy={sbomBusy}
        onRun={run}
        running={running}
      />
    </div>
  )
}
