import { FileSignature, Loader2, RefreshCw, ScrollText, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { AuditEntry, AuditReport } from '../lib/types'
import { Button, Card, cn, EmptyState, ErrorState, Spinner } from '../components/ui'
import { VirtualTable, type Column } from '../components/VirtualTable'

export function Audit() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .recentAudit(500)
      .then(setEntries)
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load the audit log'))
  }, [])

  const columns: Column<AuditEntry>[] = [
    { header: 'Time', className: 'w-44 shrink-0 font-mono text-xs tabular-nums text-mutedfg', cell: (e) => fmtTime(e.at) },
    { header: 'Actor', className: 'w-32 shrink-0 truncate', cell: (e) => e.actor || '–' },
    {
      header: 'Action',
      className: 'w-52 shrink-0 font-mono text-xs',
      cell: (e) => <span className={cn(e.action.endsWith('.denied') && 'text-critical')}>{e.action}</span>,
    },
    { header: 'Target', className: 'w-48 shrink-0 truncate font-mono text-xs text-mutedfg', cell: (e) => e.target || '–' },
    { header: 'Details', className: 'flex-1 truncate text-xs text-subtlefg', cell: (e) => metaSummary(e.metadata) },
  ]

  return (
    <div className="mx-auto max-w-6xl animate-fade-in">
      <header className="bg-hero mb-6 rounded-xl border border-border p-6">
        <h1 className="text-3xl font-bold tracking-tight">Audit log</h1>
        <p className="mt-1.5 max-w-2xl text-sm text-mutedfg">
          Append-only, attributable record of every action – scans, gate decisions (incl. denials), findings, lifecycle, and
          evidence.
        </p>
        <ChainStatus />
      </header>

      {error && <ErrorState message={error} />}
      {!entries && !error && <Spinner label="Loading audit log…" />}
      {entries && entries.length === 0 && (
        <EmptyState icon={ScrollText} title="No audit entries yet" hint="Actions appear here as they happen." />
      )}
      {entries && entries.length > 0 && (
        <Card bodyClass="p-0">
          <VirtualTable columns={columns} items={entries} rowKey={(_, i) => String(i)} />
        </Card>
      )}
    </div>
  )
}

// ChainStatus verifies the audit hash chain server-side and shows whether the
// append-only log is intact – the audit-trail analogue of the evidence badge.
function ChainStatus() {
  const [report, setReport] = useState<AuditReport | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const verify = useCallback(() => {
    setBusy(true)
    setErr(null)
    api
      .verifyAudit()
      .then(setReport)
      .catch((e) => setErr(e instanceof Error ? e.message : 'Verification failed'))
      .finally(() => setBusy(false))
  }, [])

  useEffect(() => verify(), [verify])

  const intact = report?.intact ?? false
  const Icon = busy ? Loader2 : intact ? ShieldCheck : ShieldAlert

  return (
    <div className="mt-4 flex flex-wrap items-center gap-3">
      <span
        className={cn(
          'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium ring-1 ring-inset',
          err
            ? 'bg-muted text-mutedfg ring-border'
            : intact
              ? 'bg-accent/10 text-accent ring-accent/25'
              : 'bg-critical/10 text-critical ring-critical/25',
        )}
        title={report?.head ? `chain head ${report.head}` : undefined}
      >
        <Icon className={cn('size-3.5', busy && 'animate-spin motion-reduce:animate-none')} />
        {err
          ? 'Integrity check unavailable'
          : !report
            ? 'Checking integrity…'
            : intact
              ? `Chain verified · ${report.verified} entr${report.verified === 1 ? 'y' : 'ies'}`
              : 'Chain integrity broken'}
      </span>

      {report?.head && !err && (
        <code className="font-mono text-xs text-mutedfg" title="SHA-256 chain head">
          head {report.head.slice(0, 12)}…
        </code>
      )}
      {report?.intact && report.attestation && !err && (
        <span
          className="inline-flex items-center gap-1 rounded-md bg-muted px-2 py-0.5 font-mono text-xs text-mutedfg ring-1 ring-inset ring-border"
          title={`Chain head signed (ed25519) by key ${report.attestation.key_id} – proves origin, not just integrity`}
        >
          <FileSignature className="size-3.5" />
          {report.attestation.key_id}
        </span>
      )}
      {report && report.unchained > 0 && !err && (
        <span className="text-xs text-subtlefg">{report.unchained} legacy (pre-chain) entr{report.unchained === 1 ? 'y' : 'ies'}</span>
      )}
      {report && !report.intact && report.error && (
        <span className="text-xs text-critical">{report.error}</span>
      )}

      <Button variant="ghost" onClick={verify} loading={busy} className="ml-auto px-2.5 py-1 text-xs">
        {!busy && <RefreshCw className="size-3.5" />} Re-verify
      </Button>
    </div>
  )
}

function fmtTime(s: string | null): string {
  return s ? new Date(s).toLocaleString() : '–'
}

function metaSummary(m?: Record<string, string>): string {
  if (!m) return ''
  return Object.entries(m)
    .map(([k, v]) => `${k}=${v}`)
    .join('  ·  ')
}
