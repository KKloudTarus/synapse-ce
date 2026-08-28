import { useState, useRef, type DragEvent } from 'react'
import { Download01, File06, Loading01, ShieldZap, ShieldTick, Upload01 } from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Input, Pill, Select, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { EvidenceItem, EvidenceLedger } from '../../lib/types'

export const EVIDENCE_KINDS = ['screenshot', 'http', 'terminal_log', 'pcap', 'artifact']

export function EvidenceTab({ engagementId }: { engagementId: string }) {
  const { data: ledger, loading, error, refetch } = useFetch<EvidenceLedger>(
    () => api.evidenceLedger(engagementId),
    { deps: [engagementId] },
  )

  if (error) return <ErrorState message={error} />
  if (loading || ledger === null) return <Spinner label="Loading evidence…" />

  return (
    <div className="space-y-6">
      <EvidenceIntegrity ledger={ledger} />
      <CaptureEvidenceForm engagementId={engagementId} onCaptured={refetch} />
      <EvidenceChain engagementId={engagementId} items={ledger.items} />
    </div>
  )
}

export function EvidenceIntegrity({ ledger }: { ledger: EvidenceLedger }) {
  const intact = ledger.intact
  return (
    <div
      className={cn(
        'flex items-start gap-3 rounded-xl border p-4',
        intact ? 'border-accent/30 bg-accent/10' : 'border-critical/40 bg-critical/10',
      )}
    >
      {intact ? (
        <ShieldTick className="mt-0.5 size-5 shrink-0 text-accent" />
      ) : (
        <ShieldZap className="mt-0.5 size-5 shrink-0 text-critical" />
      )}
      <div className="min-w-0">
        <p className={cn('text-sm font-semibold', intact ? 'text-accent' : 'text-critical')}>
          {intact ? 'Evidence chain intact' : 'Evidence chain TAMPERED'}
        </p>
        <p className="mt-0.5 text-xs text-tertiary">
          {ledger.verified} hash-chained link{ledger.verified === 1 ? '' : 's'} verified.{' '}
          {intact
            ? 'Each link binds to the previous, so any edit, insertion, or removal is detectable.'
            : ledger.error || 'The chain failed verification – the report path is blocked.'}
        </p>
      </div>
    </div>
  )
}

export function CaptureEvidenceForm({ engagementId, onCaptured }: { engagementId: string; onCaptured: () => void }) {
  const [kind, setKind] = useState('screenshot')
  const [note, setNote] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)
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

  function handleDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files[0]
    if (f) setFile(f)
  }

  return (
    <Card title="Capture evidence">
      <div className="flex flex-col gap-3">
        {/* Row 1: Kind + File drop zone + Note + Capture button */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          {/* Kind */}
          <div className="w-full sm:w-36">
            <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-tertiary">Kind</label>
            <Select
              value={kind}
              onValueChange={setKind}
              ariaLabel="Evidence kind"
              options={EVIDENCE_KINDS.map((k) => ({ value: k, label: k.replace('_', ' ') }))}
            />
          </div>

          {/* File drop zone */}
          <div className="flex-1">
            <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-tertiary">File</label>
            <div
              onDragOver={(e) => {
                e.preventDefault()
                setDragOver(true)
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileRef.current?.click()}
              className={cn(
                'flex h-9 cursor-pointer items-center gap-2 rounded-lg border px-3 text-sm transition-colors',
                dragOver
                  ? 'border-brand bg-brand/5'
                  : file
                    ? 'border-secondary bg-primary text-primary'
                    : 'border-dashed border-secondary bg-primary text-tertiary hover:border-primary',
              )}
            >
              <Upload01 className="size-3.5 shrink-0 text-quaternary" />
              <span className="truncate">
                {file ? file.name : 'Drop file or click to choose'}
              </span>
              {file && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation()
                    setFile(null)
                    if (fileRef.current) fileRef.current.value = ''
                  }}
                  className="ml-auto shrink-0 rounded p-0.5 text-quaternary hover:text-primary"
                  aria-label="Remove file"
                >
                  ×
                </button>
              )}
            </div>
            <input
              ref={fileRef}
              type="file"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="hidden"
              aria-hidden="true"
            />
          </div>

          {/* Note */}
          <div className="w-full sm:w-44">
            <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-tertiary">Note</label>
            <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="optional" aria-label="Evidence note" />
          </div>

          {/* Capture button - inline */}
          <Button loading={busy} onClick={capture} color="secondary" className="h-9 shrink-0 px-4">
            <Upload01 className="size-4" /> Capture
          </Button>
        </div>

        {/* Hint + error */}
        <p className="text-[11px] text-quaternary">
          Content-addressed and hash-chained by sha256 — any later change to stored bytes is detectable.
        </p>
        {err && <ErrorState message={err} />}
      </div>
    </Card>
  )
}

export function EvidenceChain({ engagementId, items }: { engagementId: string; items: EvidenceItem[] }) {
  if (items.length === 0) {
    return (
      <EmptyState
        icon={File06}
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
            className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-secondary px-5 py-3 first:border-t-0"
          >
            <span className="w-6 shrink-0 text-center font-mono text-xs text-quaternary">{i + 1}</span>
            <Pill className="uppercase">{it.kind.replace('_', ' ')}</Pill>
            <span className="text-xs text-tertiary">{it.createdAt ? new Date(it.createdAt).toLocaleString() : '–'}</span>
            <span className="text-xs text-quaternary">{it.createdBy || '–'}</span>
            <span className="flex-1" />
            <span className="font-mono text-[11px] text-quaternary" title={it.hash}>
              {it.hash.slice(0, 12)}
            </span>
            {it.storageRef && <ArtifactDownload engagementId={engagementId} item={it} />}
          </li>
        ))}
      </ol>
    </Card>
  )
}

export function ArtifactDownload({ engagementId, item }: { engagementId: string; item: EvidenceItem }) {
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
      title={failed ? 'Download failed – the artifact may be tampered' : 'Download artifact'}
      className={cn(
        'inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
        failed ? 'text-critical' : 'text-brand-secondary hover:bg-secondary',
      )}
    >
      {busy ? <Loading01 className="size-3.5 animate-spin" /> : <Download01 className="size-3.5" />}
      {failed ? 'failed' : 'artifact'}
    </button>
  )
}

export function fileToBase64(file: File): Promise<string> {
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
