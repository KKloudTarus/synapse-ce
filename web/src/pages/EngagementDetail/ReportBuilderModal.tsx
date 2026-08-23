import { useState, useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { Download01, Sliders04, XClose } from '@untitledui/icons'
import { Button, ErrorState, Field, Input, cn } from '../../components/ui'
import { ReportType, downloadReport, downloadReportDoc } from '../../lib/api'
import { trapTabFocus } from './ScanPanel'

export const REPORT_SECTIONS: { key: string; label: string }[] = [
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

export const REPORT_TYPES: { key: ReportType; label: string }[] = [
  { key: 'sca', label: 'SCA / dependency' },
  { key: 'external', label: 'External assessment' },
  { key: 'internal', label: 'Internal assessment' },
  { key: 'retest', label: 'Retest' },
]

export const ASSESSMENT_SECTIONS = ['engagement', 'scope', 'methodology', 'summary', 'risk', 'top', 'findings', 'details', 'evidence', 'exhibits']

export const TYPE_DEFAULT_SECTIONS: Record<ReportType, string[]> = {
  sca: REPORT_SECTIONS.filter((s) => s.key !== 'remediation').map((s) => s.key),
  external: ASSESSMENT_SECTIONS,
  internal: ASSESSMENT_SECTIONS,
  retest: ['engagement', 'scope', 'summary', 'remediation', 'risk', 'findings', 'evidence', 'exhibits'],
}

export const REPORT_STATUSES: { key: string; label: string }[] = [
  { key: 'open', label: 'Open' },
  { key: 'triage', label: 'Triage' },
  { key: 'confirmed', label: 'Confirmed' },
  { key: 'remediated', label: 'Remediated' },
  { key: 'false_positive', label: 'False positive' },
]

export function ReportBuilderModal({ engagementId, onClose }: { engagementId: string; onClose: () => void }) {
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

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <button type="button" aria-label="Close" className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div
        ref={panelRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="report-builder-title"
        className="relative z-10 w-full max-w-lg rounded-xl border border-secondary bg-primary p-5 text-left shadow-xl outline-none"
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 id="report-builder-title" className="flex items-center gap-2 text-lg font-semibold text-primary">
            <Sliders04 className="size-4 text-brand-secondary" /> Build report
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="rounded-md p-1 text-tertiary hover:bg-secondary hover:text-primary"
          >
            <XClose className="size-4" />
          </button>
        </div>

        <div className="space-y-4">
          <Field label="Format">
            <div role="radiogroup" aria-label="Report format" className="inline-flex rounded-lg border border-secondary bg-secondary p-0.5">
              {(['pdf', 'html', 'docx'] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  role="radio"
                  aria-checked={format === f}
                  onClick={() => setFormat(f)}
                  className={cn(
                    'rounded-md px-3 py-1.5 text-sm font-medium uppercase transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40',
                    format === f ? 'bg-brand-solid text-white' : 'text-tertiary hover:text-primary',
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
          </Field>

          {!customizable ? (
            <p className="rounded-lg border border-secondary bg-secondary px-3.5 py-2.5 text-xs text-tertiary">
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
                        type === rt.key ? 'border-brand bg-brand-primary text-primary' : 'border-secondary text-tertiary hover:text-primary',
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
                {noSections && <p className="mt-1.5 text-xs text-error-primary">Select at least one section.</p>}
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
            <Download01 className="size-4" /> Download {format.toUpperCase()}
          </Button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

export function CheckRow({ label, checked, onChange }: { label: string; checked: boolean; onChange: () => void }) {
  return (
    <label className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-secondary focus-within:bg-secondary text-primary">
      <input type="checkbox" checked={checked} onChange={onChange} className="size-4 accent-brand" />
      <span>{label}</span>
    </label>
  )
}
