import { Database01, Play, Settings01, Upload01, XClose } from '@untitledui/icons'
import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { Button, Input, cn } from '../../../components/ui'
import { kindLabel } from '../../../lib/format'
import type { ImportedSBOMMetadata, ScanMode, UploadedSourcePackage } from '../../../lib/types'

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

// Scan-by-reference kinds. An archive is uploaded through the source-upload flow, not scanned by
// reference, so it is not offered here (the server refuses kind=archive on this route).
export const KINDS = ['git', 'local', 'image']

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
  usingUploadedSource,
  uploadedSource,
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
  usingUploadedSource: boolean
  uploadedSource: UploadedSourcePackage | null
  onTriggerUpload: () => void
  sbomBusy: boolean
  onRun: () => void
  running: boolean
}) {
  const panelRef = useRef<HTMLDivElement>(null)
  const sourceLocked = usingUploadedSource || usingImportedSBOM

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
          {!sourceLocked ? (
            <div className="space-y-1.5">
              <label className="block font-semibold text-secondary">Target Type</label>
              <SegmentedKind value={kind} onChange={setKind} />
            </div>
          ) : usingUploadedSource ? (
            <div className="rounded-xl border border-utility-green-300 bg-success-primary p-3.5 text-success-primary space-y-1">
              <div className="flex items-center gap-2 font-bold text-sm">
                <Upload01 className="size-4" />
                <span>Uploaded Source Active</span>
              </div>
              <p className="text-xs">
                Scanning target is locked to the immutable package: <span className="font-mono font-semibold">{uploadedSource?.filename || 'source package'}</span>
              </p>
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
              {usingUploadedSource ? 'Uploaded source package' : kind === 'git' ? 'Repository URL' : 'Target Path / Location'}
            </label>
            {sourceLocked ? (
              <div className="flex h-9 min-w-0 items-center rounded-lg border border-secondary bg-secondary px-3 font-mono text-xs text-tertiary">
                <span className="truncate">
                  {usingUploadedSource
                    ? uploadedSource?.filename || 'Source package'
                    : importedSBOM?.targetRef || importedSBOM?.filename || 'SBOM.json'}
                </span>
              </div>
            ) : (
              <Input
                id="scan-target-input"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={
                  kind === 'git'
                    ? 'https://github.com/org/repo'
                    : kind === 'image'
                      ? 'docker.io/library/nginx:1.27'
                      : '/path/to/target'
                }
                className="h-9 w-full font-mono text-xs"
                aria-label="Scan target"
              />
            )}
            {!sourceLocked && kind === 'local' && (
              <p className="text-[11px] text-tertiary">
                Use an absolute folder path on the server inside this engagement scope.
              </p>
            )}
            {!sourceLocked && kind === 'image' && (
              <p className="text-[11px] text-tertiary">
                A container image reference. Synapse pulls it daemonlessly and reports its OS and language
                package CVEs. The image must be in this engagement's scope.
              </p>
            )}
          </div>

          {/* Branch / Tag if Git */}
          {!sourceLocked && kind === 'git' && (
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
          {!usingUploadedSource && (
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
          )}
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
