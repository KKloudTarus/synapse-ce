import { Loading01, Plus, XClose } from '@untitledui/icons'
import { useEffect, useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import { Input, Select, cn } from '../../../components/ui'
import { Button } from '../../../components/ui'
import { useFetch } from '../../../hooks'
import { api } from '../../../lib/api'
import { sevText } from '../../../lib/severity'
import type { Severity, Writeup } from '../../../lib/types'
import { STATUS_DOT } from './FindingStatus'

export const WRITEUP_NONE = '__none__'

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

export function NewFindingModal({ engagementId, onCreated, onCancel }: { engagementId: string; onCreated: () => void; onCancel: () => void }) {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState('medium')
  const [cwe, setCwe] = useState('')
  const [vector, setVector] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [writeups, setWriteups] = useState<Writeup[]>([])
  const [writeupId, setWriteupId] = useState(WRITEUP_NONE)

  useFetch(
    () => api.writeups().then((w) => { setWriteups(w); return w }).catch(() => [] as Writeup[]),
    { deps: [] },
  )

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onCancel()
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [onCancel])

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

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop overlay */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onCancel}
        aria-hidden="true"
      />

      {/* Modal Dialog */}
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="new-finding-modal-title"
        className="relative z-10 w-full max-w-xl max-h-[90vh] flex flex-col rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4">
          <h2 id="new-finding-modal-title" className="text-base font-bold text-primary flex items-center gap-2">
            <Plus className="size-4 text-brand-secondary" />
            <span>New finding</span>
          </h2>
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg p-1.5 text-tertiary transition-colors hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
            aria-label="Close modal"
          >
            <XClose className="size-4" />
          </button>
        </div>

        {/* Scrollable Form Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {writeups.length > 0 && (
            <div>
              <label htmlFor="nf-template" className="block text-xs font-semibold text-secondary mb-1.5">
                Start from template <span className="font-normal text-quaternary">(optional)</span>
              </label>
              <Select
                id="nf-template"
                value={writeupId}
                onValueChange={applyWriteup}
                ariaLabel="Insert a finding writeup template"
                className="w-full"
                options={[
                  { value: WRITEUP_NONE, label: <span className="text-tertiary">Blank finding template...</span> },
                  ...writeups.map((w) => ({
                    value: w.id,
                    label: (
                      <span className="flex items-center gap-2">
                        <span className="text-[10px] font-bold uppercase tracking-wide text-quaternary">{w.category}</span>
                        {w.title}
                      </span>
                    ),
                  })),
                ]}
              />
            </div>
          )}

          <div>
            <label htmlFor="nf-title" className="block text-xs font-semibold text-secondary mb-1.5">
              Title <span className="text-error-primary">*</span>
            </label>
            <Input
              id="nf-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Reflected XSS in search endpoint"
              className="h-9 w-full text-xs"
            />
          </div>

          <div>
            <label htmlFor="nf-desc" className="block text-xs font-semibold text-secondary mb-1.5">
              Description &amp; Remediation
            </label>
            <textarea
              id="nf-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="w-full rounded-lg border border-secondary bg-secondary px-3.5 py-2 text-xs text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid resize-none"
              placeholder="Impact, reproduction steps, remediation guidance..."
            />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-semibold text-secondary mb-1.5">
                Severity {vector.trim() && <span className="font-normal text-quaternary">(from CVSS)</span>}
              </label>
              <Select
                value={severity}
                onValueChange={setSeverity}
                disabled={Boolean(vector.trim())}
                ariaLabel="Severity"
                className="w-full"
                options={['critical', 'high', 'medium', 'low', 'info'].map((s) => ({
                  value: s,
                  label: (
                    <span className="flex items-center gap-2">
                      <span className={cn('size-2 rounded-full', STATUS_DOT[s] ?? 'bg-utility-gray-400')} />
                      <span className="capitalize">{s}</span>
                    </span>
                  ),
                }))}
              />
            </div>

            <div>
              <label htmlFor="nf-cwe" className="block text-xs font-semibold text-secondary mb-1.5">
                CWE Identifier
              </label>
              <Input
                id="nf-cwe"
                value={cwe}
                onChange={(e) => setCwe(e.target.value)}
                placeholder="e.g. CWE-79"
                className="h-9 w-full text-xs"
              />
            </div>
          </div>

          <CvssCalculator vector={vector} onChange={setVector} onSeverityChange={setSeverity} />

          {err && <p className="text-xs font-semibold text-error-primary">{err}</p>}
        </div>

        {/* Footer: Single primary action button only (per DESIGN-REFERENCE.md modal rule) */}
        <div className="flex items-center justify-end border-t border-secondary px-6 py-4 bg-secondary">
          <Button variant="primary" loading={busy} onClick={submit} className="h-9 px-5 text-xs font-semibold">
            <Plus className="size-4" /> Create finding
          </Button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

function CvssCalculator({
  vector,
  onChange,
  onSeverityChange,
}: {
  vector: string
  onChange: (v: string) => void
  onSeverityChange: (s: Severity) => void
}) {
  const [enabled, setEnabled] = useState(Boolean(vector.trim()))
  const [metrics, setMetrics] = useState<Record<string, string>>(() => ({
    AV: 'N',
    AC: 'L',
    PR: 'N',
    UI: 'N',
    S: 'U',
    C: 'H',
    I: 'H',
    A: 'H',
  }))
  const [preview, setPreview] = useState<{ score: number; severity: string } | null>(null)
  const [scoring, setScoring] = useState(false)
  const [failed, setFailed] = useState(false)

  const built = useMemo(() => {
    if (!enabled) return ''
    const parts = CVSS_METRICS.map((m) => `${m.key}:${metrics[m.key] || m.options[0].v}`)
    return `CVSS:3.1/${parts.join('/')}`
  }, [enabled, metrics])

  useEffect(() => {
    if (!enabled || !built) return
    let live = true
    setScoring(true)
    setFailed(false)
    api
      .cvssScore(built)
      .then((res) => {
        if (!live) return
        setPreview(res)
        setScoring(false)
        onChange(built)
        if (res.severity) onSeverityChange(res.severity.toLowerCase() as Severity)
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
  }, [built, enabled, onChange, onSeverityChange])

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
    <div className="rounded-lg border border-secondary bg-primary p-3">
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={enabled} onChange={(e) => toggle(e.target.checked)} className="size-4 accent-brand-solid" />
        <span className="font-semibold text-primary">Score with CVSS v3.1 Calculator</span>
        {scoring ? (
          <Loading01 className="ml-auto size-4 animate-spin text-tertiary" />
        ) : failed ? (
          <span className="ml-auto text-xs text-error-primary font-semibold">score unavailable</span>
        ) : preview ? (
          <span className="ml-auto font-mono text-sm tabular-nums">
            <span className={cn('font-bold', sevText[preview.severity as Severity] ?? 'text-primary')}>
              {preview.score.toFixed(1)}
            </span>{' '}
            <span className="text-secondary font-semibold capitalize">({preview.severity})</span>
          </span>
        ) : null}
      </label>
      {enabled && (
        <>
          <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {CVSS_METRICS.map((m) => (
              <div key={m.key}>
                <label className="block text-[11px] font-semibold text-secondary mb-1">
                  {m.label}
                </label>
                <Select
                  size="sm"
                  value={metrics[m.key]}
                  onValueChange={(v) => setMetrics((cur) => ({ ...cur, [m.key]: v }))}
                  ariaLabel={m.label}
                  className="w-full"
                  options={m.options.map((o) => ({ value: o.v, label: o.l }))}
                />
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
