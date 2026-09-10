import { File02, RefreshCw01, Upload01, XClose } from '@untitledui/icons'
import { useId, useRef, useState } from 'react'
import { Spinner, cn } from '../ui'
import type { useRetestSource } from '../../hooks/useRetestSource'
import { SourcePackageSummary } from './SourcePackageSummary'

function formatSize(bytes: number) {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.ceil(bytes / 1024))} KiB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`
}

export function RetestSourceChoice({ selection, disabled = false, onChange }: { selection: ReturnType<typeof useRetestSource>; disabled?: boolean; onChange?: () => void }) {
  const id = useId()
  const fileInput = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const chooseFile = (file?: File) => {
    onChange?.()
    selection.chooseFile(file)
  }

  if (selection.loading) return <Spinner label="Loading previous source…" />
  if (selection.error) return <div role="alert" className="rounded-xl border border-error/30 bg-error/5 p-4 text-sm text-error-primary">
    <p className="font-medium">Could not load the previous source</p>
    <p className="mt-1 text-xs">{selection.error}</p>
    <button type="button" disabled={disabled} onClick={() => { onChange?.(); selection.refetch() }} className="mt-3 inline-flex min-h-9 items-center gap-2 rounded-lg px-2 text-sm font-semibold underline underline-offset-4 disabled:opacity-50">
      <RefreshCw01 className="size-4" aria-hidden="true" />Retry source lookup
    </button>
  </div>
  if (!selection.hasUploadedSource) return null

  const usePrevious = selection.strategy === 'reuse_current'
  const selectStrategy = (strategy: 'reuse_current' | 'upload_new') => {
    onChange?.()
    selection.changeStrategy(strategy)
  }
  return <fieldset disabled={disabled} className="min-w-0 space-y-4">
    <div>
      <legend className="text-base font-semibold text-primary">Source</legend>
      <p className="mt-1 text-sm text-tertiary">Choose what this verification cycle should assess.</p>
    </div>

    <div role="radiogroup" aria-label="Re-test source" className="grid gap-3 sm:grid-cols-2">
      <label className={cn('cursor-pointer rounded-xl border p-4 transition-colors focus-within:ring-2 focus-within:ring-brand/60', usePrevious ? 'border-brand/50 bg-brand-primary/10' : 'border-secondary bg-primary hover:border-brand/40')}>
        <input type="radio" disabled={!selection.source} name={`${id}-source`} checked={usePrevious} onChange={() => selectStrategy('reuse_current')} className="sr-only" />
        <span className="flex items-start gap-3">
          <span aria-hidden="true" className={cn('mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border', usePrevious ? 'border-brand-solid bg-brand-solid ring-2 ring-brand-primary' : 'border-secondary')}><span className={cn('size-1.5 rounded-full bg-white', !usePrevious && 'hidden')} /></span>
          <span className="min-w-0">
            <span className="block text-sm font-semibold text-primary">Use current source</span>
            <span className="mt-1 block text-xs leading-relaxed text-tertiary">Continue using the current source retained by the previous assessment.</span>
          </span>
        </span>
      </label>
      <label className={cn('cursor-pointer rounded-xl border p-4 transition-colors focus-within:ring-2 focus-within:ring-brand/60', !usePrevious ? 'border-brand/50 bg-brand-primary/10' : 'border-secondary bg-primary hover:border-brand/40')}>
        <input type="radio" name={`${id}-source`} checked={!usePrevious} onChange={() => selectStrategy('upload_new')} className="sr-only" />
        <span className="flex items-start gap-3">
          <span aria-hidden="true" className={cn('mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border', !usePrevious ? 'border-brand-solid bg-brand-solid ring-2 ring-brand-primary' : 'border-secondary')}><span className={cn('size-1.5 rounded-full bg-white', usePrevious && 'hidden')} /></span>
          <span className="min-w-0">
            <span className="block text-sm font-semibold text-primary">Upload new source</span>
            <span className="mt-1 block text-xs leading-relaxed text-tertiary">Use a remediated archive for this Re-test.</span>
          </span>
        </span>
      </label>
    </div>

    {!selection.source ? <p role="status" className="rounded-xl border border-warning/30 bg-warning/10 p-3 text-xs leading-relaxed text-warning">The previous source archive is unavailable. Upload an archive for this Re-test; previous scan history remains unchanged.</p> : null}

    {usePrevious && selection.source ? <div className="rounded-xl border border-secondary bg-secondary/30 p-4">
      <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-tertiary">Previous source</p>
      <SourcePackageSummary source={selection.source} compact />
    </div> : null}

    {!usePrevious ? <div className="space-y-3 rounded-xl border border-secondary bg-secondary/20 p-4">
      <input ref={fileInput} key={selection.assessmentId} id={`${id}-source-file`} disabled={disabled} aria-label="Re-test source archive" type="file" accept=".zip,.tar,.tar.gz,.tgz" className="sr-only" onChange={(event) => chooseFile(event.target.files?.[0])} />
      {selection.file ? <div className="flex min-w-0 items-start gap-3 rounded-lg bg-primary p-3">
        <File02 className="mt-0.5 size-5 shrink-0 text-brand-secondary" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-primary" title={selection.file.name}>{selection.file.name}</p>
          <p className="mt-1 text-xs text-tertiary">{formatSize(selection.file.size)} · Ready to upload when the Re-test is created</p>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <button type="button" disabled={disabled} onClick={() => fileInput.current?.click()} className="min-h-9 rounded-lg px-2 text-xs font-semibold text-brand-secondary hover:bg-brand-primary/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 disabled:opacity-50">Replace</button>
          <button type="button" disabled={disabled} onClick={() => chooseFile()} className="flex size-9 items-center justify-center rounded-lg text-tertiary hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 disabled:opacity-50" aria-label="Remove source archive"><XClose className="size-4" aria-hidden="true" /></button>
        </div>
      </div> : <button type="button" disabled={disabled} onClick={() => fileInput.current?.click()} onDragEnter={(event) => { event.preventDefault(); setDragging(true) }} onDragOver={(event) => event.preventDefault()} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); chooseFile(event.dataTransfer.files[0]) }} className={cn('flex min-h-28 w-full flex-col items-center justify-center rounded-lg border border-dashed px-4 text-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 disabled:cursor-not-allowed disabled:opacity-50', dragging ? 'border-brand bg-brand-primary/10 text-primary' : 'border-secondary bg-primary text-tertiary hover:border-brand/50')}>
        <Upload01 className="size-5" aria-hidden="true" />
        <span className="mt-2 text-sm font-semibold text-primary">Drop an archive here or choose a file</span>
        <span className="mt-1 text-xs">ZIP, TAR, TAR.GZ, or TGZ · up to 512 MiB</span>
      </button>}
      {selection.file ? <label className="flex cursor-default items-start gap-2 rounded-lg bg-primary/70 px-3 py-2.5 text-xs text-secondary">
        <input type="checkbox" checked readOnly aria-label="Force update source" className="mt-0.5 size-4 shrink-0 rounded accent-brand-solid" />
        <span><span className="font-semibold text-primary">Force update source</span><span className="mt-0.5 block leading-relaxed">This archive will be used for this Re-test. The previous assessment’s archive remains unchanged.</span></span>
      </label> : null}
    </div> : null}
    <p className="text-xs text-tertiary">The source is immutable for this Assessment. Creating the draft does not start a scan.</p>
  </fieldset>
}
