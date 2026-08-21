import { Download, FileClock, Loader2, ShieldAlert, ShieldCheck, Upload } from 'lucide-react'
import { useRef, useState } from 'react'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../../components/ui'
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

export function EvidenceChain({ engagementId, items }: { engagementId: string; items: EvidenceItem[] }) {
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
            <span className="text-xs text-mutedfg">{it.createdAt ? new Date(it.createdAt).toLocaleString() : '–'}</span>
            <span className="text-xs text-subtlefg">{it.createdBy || '–'}</span>
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
        failed ? 'text-critical' : 'text-branddim hover:bg-elevated',
      )}
    >
      {busy ? <Loader2 className="size-3.5 animate-spin" /> : <Download className="size-3.5" />}
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
