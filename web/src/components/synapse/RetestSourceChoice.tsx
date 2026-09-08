import { useId } from 'react'
import { Field, Input, Spinner } from '../ui'
import type { useRetestSource } from '../../hooks/useRetestSource'
import { SourcePackageSummary } from './SourcePackageSummary'

export function RetestSourceChoice({ selection, disabled = false, onChange }: { selection: ReturnType<typeof useRetestSource>; disabled?: boolean; onChange?: () => void }) {
  const id = useId()
  if (selection.loading) return <Spinner label="Loading predecessor source…" />
  if (selection.error) return <div role="alert" className="rounded-lg border border-error/30 p-3 text-sm text-error-primary">
    <p>Could not load the predecessor source: {selection.error}</p>
    <button type="button" disabled={disabled} onClick={() => { onChange?.(); selection.refetch() }} className="mt-2 font-semibold underline disabled:opacity-50">Retry source lookup</button>
  </div>
  if (!selection.hasUploadedSource) return null
  return <fieldset disabled={disabled} className="min-w-0 space-y-3">
    <legend className="mb-2 text-sm font-semibold text-primary">Re-test source</legend>
    <div className="grid gap-3 sm:grid-cols-2">
      {([
        ['reuse_current', 'Use current source', 'Reuse the exact archive attached to the selected predecessor.'],
        ['upload_new', 'Upload new source', 'Attach another revision to this Re-test only.'],
      ] as const).map(([value, label, hint]) => <label key={value} className="flex cursor-pointer gap-3 rounded-xl border border-secondary bg-secondary/30 p-3">
        <input type="radio" disabled={disabled || value === 'reuse_current' && !selection.source} name={`${id}-source`} checked={selection.strategy === value} onChange={() => { onChange?.(); selection.changeStrategy(value) }} className="mt-1 size-4 shrink-0 accent-brand-solid" />
        <span><span className="block text-sm font-semibold text-primary">{label}</span><span className="mt-1 block text-xs text-tertiary">{hint}</span></span>
      </label>)}
    </div>
    {!selection.source ? <p role="status" className="rounded-lg bg-warning/10 p-3 text-xs text-warning">The previous source archive is unavailable. Upload an archive for this new Re-test; missing original bytes or metadata cannot be reconstructed, and previous scan history is not changed.</p> : null}
    {selection.strategy === 'reuse_current' && selection.source ? <div className="rounded-lg border border-secondary bg-secondary/20 p-3"><SourcePackageSummary source={selection.source} /></div> :
      <Field label="Source archive" hint="ZIP, TAR, TAR.GZ, or TGZ · non-empty · maximum 512 MiB. The previous archive and scan history remain unchanged.">
        <Input key={selection.assessmentId} disabled={disabled} aria-label="Re-test source archive" type="file" accept=".zip,.tar,.tar.gz,.tgz" onChange={(event) => { onChange?.(); selection.chooseFile(event.target.files?.[0]) }} />
      </Field>}
    <p className="text-xs text-tertiary">The source is immutable for this Assessment. Creating the draft does not start a scan.</p>
  </fieldset>
}
