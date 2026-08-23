import { AlertTriangle, CheckVerified01, CheckCircle, ChevronLeft, ChevronRight, File06, Loading01, Plus, RefreshCcw01, ShieldTick, Shield01, Stars01 } from '@untitledui/icons'
import { Fragment, useEffect, useMemo, useState } from 'react'
import { AITriageBadges } from '../../components/synapse/AITriageBadges'
import { useFetch } from '../../hooks'

function findingAnchor(id: string) {
  return `finding-${id}`
}

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
import { Button, Card, EmptyState, ErrorState, Field, Input, KevBadge, Select, SevBadge, Spinner, cn } from '../../components/ui'
import { ApiError, api } from '../../lib/api'
import { findingKindLabel, statusLabel } from '../../lib/format'
import { sevText } from '../../lib/severity'
import type { CritiqueClaim, EvidenceItem, Finding, FindingComment, Judgment, ReachabilityClaim, Retest, RetestOutcome, RiskNarrativeClaim, ScanResult, Severity, Vulnerability, Writeup } from '../../lib/types'
import { ConfidenceBadge, DetectedBy, KindBadge, KindFilter, PriorityBadge, ScopeBadge, SeverityFilter, shortPkg, vulnKey } from './VulnsTab'

const PAGE_SIZE = 12

function TablePagination({
  page,
  totalPages,
  total,
  pageSize,
  onPageChange,
}: {
  page: number
  totalPages: number
  total: number
  pageSize: number
  onPageChange: (p: number) => void
}) {
  if (totalPages <= 1) return null
  const start = (page - 1) * pageSize
  const end = Math.min(start + pageSize, total)
  return (
    <div className="flex items-center justify-between border-t border-secondary px-4 py-3">
      <span className="text-xs text-tertiary">
        Showing {start + 1}–{end} of {total}
      </span>
      <div className="flex items-center gap-2">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page === 1}
          aria-label="Previous page"
          className="inline-flex size-8 items-center justify-center rounded-md border border-secondary text-secondary transition-colors hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:opacity-40"
        >
          <ChevronLeft className="size-4" aria-hidden="true" />
        </button>
        <span className="text-xs tabular-nums text-tertiary">
          Page {page} of {totalPages}
        </span>
        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page === totalPages}
          aria-label="Next page"
          className="inline-flex size-8 items-center justify-center rounded-md border border-secondary text-secondary transition-colors hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:opacity-40"
        >
          <ChevronRight className="size-4" aria-hidden="true" />
        </button>
      </div>
    </div>
  )
}

export function FindingsTab({
  findings,
  scan,
  engagementId,
  filter,
  setFilter,
  focusedFindingId,
  onUpdated,
  onReload,
}: {
  findings: Finding[] | null
  scan: ScanResult | null
  engagementId: string
  filter: Severity | 'all'
  setFilter: (v: Severity | 'all') => void
  focusedFindingId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [view, setView] = useState<'table' | 'board'>('table')
  const [creating, setCreating] = useState(false)
  const [kindFilter, setKindFilter] = useState<string>('all') // filter by finding Kind
  const [page, setPage] = useState(1)

  useEffect(() => {
    setPage(1)
  }, [filter, kindFilter])

  // Separate actionable third-party findings from first-party historical advisories
  // – the table shows only actionable findings.
  const thirdParty = (findings ?? []).filter((f) => f.class !== 'first_party_historical')
  const historical = (findings ?? []).filter((f) => f.class === 'first_party_historical')
  const available = new Set(thirdParty.map((f) => f.severity))
  // The Kinds present – the Kind filter only appears when there's more than one to choose from.
  const kinds = Array.from(new Set(thirdParty.map((f) => f.kind).filter(Boolean)))
  // findings arrive already risk-ordered (KEV -> EPSS x CVSS) from the API.
  const rows = thirdParty.filter(
    (f) => (filter === 'all' || f.severity === filter) && (kindFilter === 'all' || f.kind === kindFilter),
  )

  useEffect(() => {
    if (!focusedFindingId || findings === null) return
    const idx = rows.findIndex((f) => f.id === focusedFindingId)
    if (idx >= 0) {
      setPage(Math.floor(idx / PAGE_SIZE) + 1)
    }
    setExpanded((current) => new Set(current).add(focusedFindingId))
    const frame = requestAnimationFrame(() => {
      document.getElementById(findingAnchor(focusedFindingId))?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    })
    return () => cancelAnimationFrame(frame)
  }, [findings, focusedFindingId, rows])
  const vulnByKey = useMemo(() => {
    const m = new Map<string, Vulnerability>()
    for (const v of scan?.vulnerabilities ?? []) m.set(vulnKey(v), v)
    return m
  }, [scan])
  const triageByKey = useMemo(() => {
    const map = new Map<string, NonNullable<ScanResult['aiTriage']>[number]>()
    for (const item of scan?.aiTriage ?? []) {
      if (item.findingId) map.set(item.findingId, item)
      if (item.dedupKey) map.set(item.dedupKey, item)
    }
    return map
  }, [scan])

  if (findings === null) return <Spinner label="Loading findings…" />

  function toggle(id: string) {
    setExpanded((cur) => {
      const next = new Set(cur)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <FindingsViewToggle view={view} onChange={setView} />
        <div className="flex items-center gap-2">
          {historical.length > 0 && (
            <span
              className="inline-flex items-center gap-1.5 rounded-md bg-secondary px-2 py-1 text-xs text-tertiary"
              title="Advisories matched against the project's own unversioned modules – cannot be confirmed, excluded from remediation."
            >
              <File06 className="size-3.5" />
              {historical.length} historical
            </span>
          )}
          <Button variant="secondary" onClick={() => setCreating((c) => !c)} className="px-3 py-1.5">
            <Plus className="size-4" /> New finding
          </Button>
        </div>
      </div>
      {creating && (
        <NewFindingForm
          engagementId={engagementId}
          onCreated={() => {
            setCreating(false)
            onReload()
          }}
          onCancel={() => setCreating(false)}
        />
      )}
      {findings.length === 0 ? (
        <EmptyState icon={CheckCircle} title="No findings yet" hint="Run a scan, or add a manual finding above." />
      ) : view === 'board' ? (
        <FindingsBoard findings={thirdParty} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
      ) : (
        <Card bodyClass="p-0">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-secondary p-4">
            <SeverityFilter value={filter} onChange={setFilter} available={available} />
            {kinds.length > 1 && <KindFilter value={kindFilter} onChange={setKindFilter} kinds={kinds} />}
          </div>
      {rows.length === 0 && (
        <div className="p-6 text-center text-sm text-tertiary">
          No actionable third-party findings
          {filter !== 'all' ? ` at ${filter}` : ''}
          {kindFilter !== 'all' ? ` of kind ${findingKindLabel(kindFilter)}` : ''}.
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[11px] uppercase tracking-wider text-quaternary">
              <th className="w-8" />
              <th className="px-2 py-2 font-semibold">Pri</th>
              <th className="px-2 py-2 font-semibold">Severity</th>
              <th className="px-4 py-2 font-semibold">Finding</th>
              <th className="px-4 py-2 font-semibold">Scope</th>
              <th className="px-4 py-2 font-semibold">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE).map((f) => {
              const v = vulnByKey.get(f.dedupKey)
              const triage = triageByKey.get(f.id) ?? triageByKey.get(f.dedupKey)
              const isOpen = expanded.has(f.id)
              return (
                <Fragment key={f.id}>
                  <tr
                    id={findingAnchor(f.id)}
                    onClick={() => toggle(f.id)}
                    className={cn('cursor-pointer border-t border-secondary transition-colors hover:bg-secondary', focusedFindingId === f.id && 'bg-brand-primary/50 ring-1 ring-inset ring-brand/30')}
                  >
                    <td className="pl-3 align-top">
                      <button
                        type="button"
                        aria-expanded={isOpen}
                        aria-label={`Toggle advisory detail for ${f.title}`}
                        onClick={(e) => {
                          e.stopPropagation()
                          toggle(f.id)
                        }}
                        className="rounded p-1 text-quaternary transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
                      >
                        <ChevronRight className={cn('size-4 transition-transform', isOpen && 'rotate-90')} />
                      </button>
                    </td>
                    <td className="px-2 py-2 align-top">
                      <PriorityBadge priority={f.priority} />
                    </td>
                    <td className="px-2 py-2 align-top">
                      <SevBadge sev={f.severity} />
                    </td>
                    <td className="px-4 py-2 align-top">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-primary">{f.title}</span>
                        {f.kev && <KevBadge />}
                        {f.kind && f.kind !== 'sca' && <KindBadge kind={f.kind} />}
                        {f.cwe && <span className="font-mono text-[11px] tabular-nums text-quaternary">{f.cwe}</span>}
                        {triage && <AITriageBadges triage={triage} />}
                        {v && !v.direct && v.path.length >= 2 && (
                          <span className="text-xs text-quaternary" title={v.path.map(shortPkg).join(' › ')}>
                            via {shortPkg(v.path[v.path.length - 2])}
                          </span>
                        )}
                      </div>
                      {f.description && !isOpen && (
                        <div className="mt-0.5 line-clamp-1 text-xs text-tertiary">{f.description}</div>
                      )}
                    </td>
                    <td className="px-4 py-2 align-top">
                      <ScopeBadge scope={f.scope} />
                    </td>
                    <td className="px-4 py-2 align-top" onClick={(e) => e.stopPropagation()}>
                      <FindingStatusControl finding={f} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="border-t border-secondary/50 bg-primary/40">
                      <td />
                      <td colSpan={5} className="px-4 py-3">
                        <FindingDetail finding={f} vuln={v} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
          </div>
          <TablePagination
            page={page}
            totalPages={Math.max(1, Math.ceil(rows.length / PAGE_SIZE))}
            total={rows.length}
            pageSize={PAGE_SIZE}
            onPageChange={setPage}
          />
        </Card>
      )}
    </div>
  )
}

export function frameworkShort(framework: string): string {
  switch (framework) {
    case 'OWASP-2021':
      return 'OWASP'
    case 'PCI-DSS-4.0':
      return 'PCI DSS'
    case 'ISO-27001-2022':
      return 'ISO 27001'
    default:
      return framework
  }
}

export function ComplianceChips({ controls }: { controls: Finding['complianceControls'] }) {
  if (!controls || controls.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="list" aria-label="Compliance controls">
      <CheckVerified01 aria-hidden className="size-3.5 shrink-0 text-quaternary" />
      <span aria-hidden className="text-[11px] uppercase tracking-wide text-quaternary">Compliance</span>
      {controls.map((c) => (
        <span
          key={`${c.framework}:${c.id}`}
          role="listitem"
          className="inline-flex items-center gap-1.5 rounded-md bg-secondary px-2 py-0.5 text-xs ring-1 ring-inset ring-secondary"
        >
          <span className="text-quaternary">{frameworkShort(c.framework)}</span>
          <span className="font-mono tabular-nums text-primary">{c.id}</span>
          <span className="text-tertiary">{c.title}</span>
        </span>
      ))}
    </div>
  )
}

export function JudgmentStateBadge({ state }: { state: string }) {
  const tone =
    state === 'confirmed'
      ? 'text-accent ring-accent/30 bg-accent/10'
      : state === 'refuted'
        ? 'text-medium ring-medium/30 bg-medium/10'
        : 'text-tertiary ring-secondary bg-secondary'
  return (
    <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide ring-1 ring-inset ${tone}`}>
      {state}
    </span>
  )
}

export function RiskNarrative({ j }: { j: Judgment }) {
  const c = j.claim as Partial<RiskNarrativeClaim>
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-primary">Risk narrative</span>
        <JudgmentStateBadge state={j.state} />
        {typeof c.priority === 'number' && (
          <span className="font-mono text-xs tabular-nums text-tertiary">priority {c.priority}/5</span>
        )}
      </div>
      {(c.drivers?.length ?? 0) > 0 && (
        <div className="flex flex-wrap gap-1">
          {c.drivers!.map((d) => (
            <span
              key={d}
              className="rounded bg-secondary px-1.5 py-0.5 font-mono text-[11px] text-tertiary ring-1 ring-inset ring-secondary"
            >
              {d}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

export function Critique({ j }: { j: Judgment }) {
  const c = j.claim as Partial<CritiqueClaim>
  const verdictTone = c.verdict === 'refuted' ? 'text-medium' : c.verdict === 'sound' ? 'text-accent' : 'text-tertiary'
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-primary">Critique</span>
        <JudgmentStateBadge state={j.state} />
        {c.verdict && <span className={`text-xs font-medium ${verdictTone}`}>{c.verdict}</span>}
        {typeof c.confidence === 'number' && (
          <span className="font-mono text-xs tabular-nums text-tertiary">{c.confidence}% confidence</span>
        )}
      </div>
      {c.driver && <span className="font-mono text-[11px] text-tertiary">{c.driver}</span>}
    </div>
  )
}

export function Reachability({ j }: { j: Judgment }) {
  const c = j.claim as Partial<ReachabilityClaim>
  const tone =
    c.reachable === 'reachable'
      ? 'text-critical ring-critical/30 bg-critical/10'
      : c.reachable === 'not_reachable'
        ? 'text-accent ring-accent/30 bg-accent/10'
        : 'text-tertiary ring-secondary bg-secondary'
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-primary">Reachability</span>
        <JudgmentStateBadge state={j.state} />
        {c.reachable && (
          <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset ${tone}`}>
            {c.reachable.replace('_', ' ')}
          </span>
        )}
        {c.tier && <span className="font-mono text-[11px] tabular-nums text-quaternary">{c.tier}</span>}
        {typeof c.confidence === 'number' && (
          <span className="font-mono text-xs tabular-nums text-tertiary">{c.confidence}% confidence</span>
        )}
      </div>
      {(c.path?.length ?? 0) > 0 && (
        <div className="flex flex-wrap items-center gap-1 font-mono text-[11px] tabular-nums text-tertiary">
          {c.path!.map((sym, i) => (
            <span key={i} className="flex items-center gap-1">
              {i > 0 && <ChevronRight aria-hidden className="size-3 text-quaternary" />}
              <span>{sym}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

export function ExplainJudgments({ engagementId, findingId }: { engagementId: string; findingId: string }) {
  const { data: judgments } = useFetch(
    () => api.judgments(engagementId).catch(() => [] as Judgment[]),
    { deps: [engagementId] },
  )

  const relevant = (judgments ?? []).filter(
    (j) =>
      j.subjectId === findingId &&
      (j.capability === 'risk_narrative' || j.capability === 'critique' || j.capability === 'reachability'),
  )
  if (relevant.length === 0) return null

  return (
    <div className="space-y-2 rounded-lg border border-secondary bg-primary p-3">
      <div className="flex items-center gap-1.5">
        <Stars01 aria-hidden className="size-3.5 text-brand-secondary" />
        <span className="text-[11px] uppercase tracking-wide text-quaternary">Analysis</span>
      </div>
      <ul className="space-y-2" role="list">
        {relevant.map((j) => (
          <li key={j.id}>
            {j.capability === 'reachability' ? (
              <Reachability j={j} />
            ) : j.capability === 'critique' ? (
              <Critique j={j} />
            ) : (
              <RiskNarrative j={j} />
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

export const GATED_JUDGMENT_CAPABILITIES = new Set(['reachability', 'sast', 'critique', 'threat', 'vex_justification'])

export function JudgmentClaim({ judgment }: { judgment: Judgment }) {
  if (judgment.capability === 'reachability') return <Reachability j={judgment} />
  if (judgment.capability === 'critique') return <Critique j={judgment} />
  if (judgment.capability === 'risk_narrative') return <RiskNarrative j={judgment} />

  return (
    <dl className="grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
      {Object.entries(judgment.claim).map(([key, value]) => (
        <div key={key} className="rounded-md border border-secondary bg-secondary px-2.5 py-2">
          <dt className="text-[11px] uppercase tracking-wide text-quaternary">{key.replaceAll('_', ' ')}</dt>
          <dd className="mt-0.5 break-words font-mono text-primary">
            {Array.isArray(value) ? value.join(', ') : String(value ?? '–')}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function sealedJudgmentId(item: EvidenceItem): string {
  if (item.kind !== 'judgment_proposed' || !item.contentBase64) return ''
  try {
    const bytes = Uint8Array.from(atob(item.contentBase64), (c) => c.charCodeAt(0))
    const payload = JSON.parse(new TextDecoder().decode(bytes)) as unknown
    if (payload && typeof payload === 'object' && 'judgment_id' in payload) {
      const id = (payload as { judgment_id?: unknown }).judgment_id
      return typeof id === 'string' ? id : ''
    }
  } catch {
    // A malformed ledger item must not hide the rest of the review queue.
  }
  return ''
}

export function FindingDetail({
  finding,
  vuln,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  vuln: Vulnerability | undefined
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  return (
    <div className="space-y-3">
      <FindingCollab finding={finding} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
      {finding.kind === 'exploitation' && (
        <EvidenceGate finding={finding} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
      )}
      {finding.description && <p className="whitespace-pre-line text-xs text-tertiary">{finding.description}</p>}
      <ComplianceChips controls={finding.complianceControls} />
      {vuln ? (
        <>
          <div className="flex flex-wrap gap-x-6 gap-y-1.5 font-mono text-xs">
            <DetailKV label="CVSS" value={vuln.cvssScore > 0 ? vuln.cvssScore.toFixed(1) : '–'} />
            <DetailKV label="EPSS" value={vuln.epss > 0 ? `${(vuln.epss * 100).toFixed(1)}%` : '–'} />
            <DetailKV label="installed" value={`${vuln.component}@${vuln.version}`} />
            <DetailKV
              label="fixed in"
              value={vuln.fixedVersion || '–'}
              valueClass={vuln.fixedVersion ? 'text-accent' : 'text-quaternary'}
            />
          </div>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-1.5 text-xs">
            <span className="flex items-center gap-2">
              <span className="text-[11px] uppercase tracking-wide text-quaternary">detected by</span>
              <DetectedBy sources={vuln.sources} />
            </span>
            <span className="flex items-center gap-2">
              <span className="text-[11px] uppercase tracking-wide text-quaternary">confidence</span>
              <ConfidenceBadge confidence={vuln.confidence} />
            </span>
          </div>
          {vuln.path.length > 1 && (
            <div className="text-xs">
              <span className="text-[11px] uppercase tracking-wide text-quaternary">Dependency path</span>
              <div className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-tertiary">
                {vuln.path.map((p, i) => (
                  <span key={i} className="flex items-center gap-1.5">
                    {i > 0 && <ChevronRight className="size-3 text-quaternary" />}
                    <span className={i === vuln.path.length - 1 ? 'text-primary' : ''}>{shortPkg(p)}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
          {vuln.direct && <p className="text-xs text-quaternary">Direct dependency of the project.</p>}
        </>
      ) : (
        <p className="text-xs text-quaternary">
          {finding.dedupKey.startsWith('license:') ? 'License-policy finding.' : 'No matching advisory detail in this scan.'}
        </p>
      )}
      <ExplainJudgments engagementId={engagementId} findingId={finding.id} />
    </div>
  )
}

export const EVIDENCE_BAR = 75

// EvidenceGate is the finding-review panel for an agent-proposed exploitation finding: it
// shows who proposed it + its evidence score + the gate state, and lets a DISTINCT human verifier
// seal an adversarial verdict (which raises the score). The server rejects verifier == proposer
// and a machine role; a passing verdict makes the finding promotable (then a human confirms via
// the status control).
function EvidenceGate({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [open, setOpen] = useState(false)
  const [score, setScore] = useState(90)
  const [rationale, setRationale] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const proven = finding.evidenceScore >= EVIDENCE_BAR

  async function submit() {
    setBusy(true)
    setErr('')
    try {
      onUpdated(await api.verifyFinding(engagementId, finding.id, score, rationale.trim(), finding.version))
      setOpen(false)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setErr('This finding changed – reloading.')
        onReload()
      } else {
        setErr(e instanceof ApiError ? e.message : 'Verify failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="rounded-lg border border-secondary bg-primary p-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
        <span className="flex items-center gap-1.5">
          {proven ? (
            <ShieldTick className="size-4 text-accent" />
          ) : (
            <Shield01 className="size-4 text-medium" />
          )}
          <span className={cn('font-medium', proven ? 'text-accent' : 'text-medium')}>
            {proven ? 'Verified – reportable' : 'Unproven – not reportable'}
          </span>
        </span>
        <DetailKV label="evidence" value={`${finding.evidenceScore}/${EVIDENCE_BAR}`} valueClass="font-mono tabular-nums" />
        {finding.proposedBy && <DetailKV label="proposed by" value={finding.proposedBy} />}
      </div>

      {!proven && (
        <div className="mt-2">
          {!open ? (
            <Button variant="secondary" onClick={() => setOpen(true)} className="px-2.5 py-1 text-xs">
              <ShieldTick className="size-3.5" /> Verify finding
            </Button>
          ) : (
            <div className="space-y-2">
              <p className="text-[11px] text-quaternary">
                Record an adversarial verdict. The verifier must be a different person than the proposer; the verdict is
                sealed into the evidence chain. A score ≥ {EVIDENCE_BAR} makes it promotable.
              </p>
              <label htmlFor="evidence-score-input" className="flex items-center gap-2 text-xs">
                <span className="text-quaternary">Score</span>
                <input
                  id="evidence-score-input"
                  type="number"
                  min={0}
                  max={100}
                  value={score}
                  onChange={(e) => setScore(Math.max(0, Math.min(100, Number(e.target.value))))}
                  className="w-20 rounded border border-secondary bg-secondary px-2 py-1 font-mono tabular-nums text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40"
                />
              </label>
              <textarea
                value={rationale}
                onChange={(e) => setRationale(e.target.value)}
                placeholder="Rationale (how it was reproduced / refuted)"
                aria-label="Verdict rationale"
                rows={2}
                className="w-full rounded border border-secondary bg-secondary px-2 py-1 text-xs text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40"
              />
              {err && <p className="text-xs text-critical">{err}</p>}
              <div className="flex gap-2">
                <Button loading={busy} onClick={submit} className="px-2.5 py-1 text-xs">
                  Seal verdict
                </Button>
                <Button variant="ghost" onClick={() => setOpen(false)} className="px-2.5 py-1 text-xs">
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function DetailKV({ label, value, valueClass }: { label: string; value: string; valueClass?: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="text-[11px] uppercase tracking-wide text-quaternary">{label}</span>
      <span className={cn('text-primary', valueClass)}>{value}</span>
    </span>
  )
}

export const FINDING_STATUSES = ['open', 'triage', 'confirmed', 'false_positive', 'remediated']

export const STATUS_DOT: Record<string, string> = {
  open: 'bg-secondaryfg',
  triage: 'bg-medium',
  confirmed: 'bg-critical',
  false_positive: 'bg-subtlefg',
  remediated: 'bg-accent',
}

export const STATUS_TEXT: Record<string, string> = {
  open: 'text-tertiary',
  triage: 'text-medium',
  confirmed: 'text-critical',
  false_positive: 'text-quaternary',
  remediated: 'text-accent',
}

export function StatusLabel({ status }: { status: string }) {
  return (
    <span className={cn('flex items-center gap-2', STATUS_TEXT[status] ?? 'text-tertiary')}>
      <span className={cn('size-2 shrink-0 rounded-full', STATUS_DOT[status] ?? 'bg-secondaryfg')} />
      {statusLabel(status)}
    </span>
  )
}

export function FindingStatusControl({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<'' | 'failed' | 'conflict'>('')

  async function change(status: string) {
    if (status === finding.status) return
    setBusy(true)
    setNote('')
    try {
      onUpdated(await api.updateFindingStatus(engagementId, finding.id, status, finding.version))
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setNote('conflict')
        onReload() // someone else moved it – pull the latest
      } else {
        setNote('failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Select
        value={finding.status}
        onValueChange={change}
        disabled={busy}
        size="sm"
        ariaLabel={`Triage status for ${finding.title}`}
        className="min-w-[9.5rem]"
        options={FINDING_STATUSES.map((s) => ({ value: s, label: <StatusLabel status={s} /> }))}
      />
      {busy && <Loading01 className="size-3.5 shrink-0 animate-spin text-tertiary" />}
      {note === 'failed' && <span className="text-xs text-critical">failed</span>}
      {note === 'conflict' && (
        <span className="inline-flex items-center gap-1 text-xs font-medium text-medium">
          <AlertTriangle className="size-3" /> reloaded
        </span>
      )}
    </div>
  )
}

export function FindingsViewToggle({ view, onChange }: { view: 'table' | 'board'; onChange: (v: 'table' | 'board') => void }) {
  return (
    <div role="radiogroup" aria-label="Findings view" className="inline-flex h-9 items-center rounded-lg border border-secondary bg-secondary p-0.5">
      {(['table', 'board'] as const).map((v) => (
        <button
          key={v}
          role="radio"
          aria-checked={view === v}
          onClick={() => onChange(v)}
          className={cn(
            'h-full rounded-md px-3 text-sm font-medium capitalize transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40',
            view === v ? 'bg-primary text-primary shadow-sm' : 'text-tertiary hover:text-primary',
          )}
        >
          {v}
        </button>
      ))}
    </div>
  )
}

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export const COMMON_CWES: { id: string; label: string }[] = [
  { id: 'CWE-79', label: 'Cross-site Scripting' },
  { id: 'CWE-89', label: 'SQL Injection' },
  { id: 'CWE-22', label: 'Path Traversal' },
  { id: 'CWE-352', label: 'CSRF' },
  { id: 'CWE-918', label: 'SSRF' },
  { id: 'CWE-78', label: 'OS Command Injection' },
  { id: 'CWE-287', label: 'Improper Authentication' },
  { id: 'CWE-862', label: 'Missing Authorization' },
  { id: 'CWE-502', label: 'Deserialization of Untrusted Data' },
  { id: 'CWE-200', label: 'Exposure of Sensitive Information' },
]

export const WRITEUP_NONE = '__none__'

function NewFindingForm({ engagementId, onCreated, onCancel }: { engagementId: string; onCreated: () => void; onCancel: () => void }) {
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

  // Insert a library template: prefill the finding text (the report is later
  // templated from this stored finding, no model in the path).
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

  return (
    <Card
      title="New finding"
      actions={
        <div className="flex gap-2">
          <Button variant="ghost" onClick={onCancel} className="px-3 py-1.5">
            Cancel
          </Button>
          <Button loading={busy} onClick={submit} className="px-3 py-1.5">
            <Plus className="size-4" /> Create
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        {writeups.length > 0 && (
          <Field label="Start from library" hint="Optional – prefills the fields below with a reusable writeup">
            <Select
              value={writeupId}
              onValueChange={applyWriteup}
              ariaLabel="Insert a finding writeup template"
              options={[
                { value: WRITEUP_NONE, label: <span className="text-tertiary">Blank finding…</span> },
                ...writeups.map((w) => ({
                  value: w.id,
                  label: (
                    <span className="flex items-center gap-2">
                      <span className="text-[10px] uppercase tracking-wide text-quaternary">{w.category}</span>
                      {w.title}
                    </span>
                  ),
                })),
              ]}
            />
          </Field>
        )}
        <Field label="Title" htmlFor="nf-title">
          <Input id="nf-title" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Reflected XSS in search" />
        </Field>
        <Field label="Description" htmlFor="nf-desc">
          <textarea
            id="nf-desc"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
            className="input-inset w-full rounded-lg border border-secondary bg-secondary px-3.5 py-2.5 text-sm text-primary outline-none transition-colors placeholder:text-quaternary focus:border-brand focus:ring-2 focus:ring-brand/40"
            placeholder="Impact, reproduction, remediation…"
          />
        </Field>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Severity" hint={vector.trim() ? 'set by the CVSS vector below' : undefined}>
            <Select
              value={severity}
              onValueChange={setSeverity}
              ariaLabel="Severity"
              disabled={!!vector.trim()}
              options={SEVERITIES.map((s) => ({ value: s, label: <SevBadge sev={s} /> }))}
            />
          </Field>
          <Field label="CWE" htmlFor="nf-cwe">
            <Input id="nf-cwe" value={cwe} onChange={(e) => setCwe(e.target.value)} placeholder="CWE-79" list="cwe-list" />
            <datalist id="cwe-list">
              {COMMON_CWES.map((c) => (
                <option key={c.id} value={c.id} label={c.label} />
              ))}
            </datalist>
          </Field>
        </div>
        <CvssBuilder onChange={setVector} />
      </div>
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
    </Card>
  )
}

export function CvssBuilder({ onChange }: { onChange: (v: string) => void }) {
  const [enabled, setEnabled] = useState(false)
  const [metrics, setMetrics] = useState<Record<string, string>>({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' })
  const [preview, setPreview] = useState<{ score: number; severity: string } | null>(null)
  const [scoring, setScoring] = useState(false)
  const [failed, setFailed] = useState(false)

  const built = 'CVSS:3.1/' + CVSS_METRICS.map((m) => `${m.key}:${metrics[m.key]}`).join('/')

  useEffect(() => {
    if (!enabled) return
    onChange(built)
    let live = true
    setScoring(true)
    setFailed(false)
    api
      .cvssScore(built)
      .then((r) => {
        if (live) {
          setPreview(r)
          setScoring(false)
        }
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [built, enabled])

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
        <input type="checkbox" checked={enabled} onChange={(e) => toggle(e.target.checked)} className="size-4 accent-brand" />
        <span className="font-medium text-primary">Score with CVSS v3.1</span>
        {scoring ? (
          <Loading01 className="ml-auto size-4 animate-spin text-tertiary" />
        ) : failed ? (
          <span className="ml-auto text-xs text-critical">score unavailable</span>
        ) : preview ? (
          <span className="ml-auto font-mono text-sm tabular-nums">
            <span className={cn('font-semibold', sevText[preview.severity as Severity] ?? 'text-primary')}>{preview.score.toFixed(1)}</span>{' '}
            <span className="text-tertiary">{preview.severity}</span>
          </span>
        ) : null}
      </label>
      {enabled && (
        <>
          <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {CVSS_METRICS.map((m) => (
              <Field key={m.key} label={m.label}>
                <Select
                  size="sm"
                  value={metrics[m.key]}
                  onValueChange={(v) => setMetrics((cur) => ({ ...cur, [m.key]: v }))}
                  ariaLabel={m.label}
                  options={m.options.map((o) => ({ value: o.v, label: o.l }))}
                />
              </Field>
            ))}
          </div>
          <p className="mt-2 break-all font-mono text-[11px] text-quaternary">{built}</p>
        </>
      )}
    </div>
  )
}

export function FindingsBoard({
  findings,
  engagementId,
  onUpdated,
  onReload,
}: {
  findings: Finding[]
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
      {FINDING_STATUSES.map((status) => {
        const col = findings.filter((f) => f.status === status)
        return (
          <div key={status} className="rounded-xl border border-secondary bg-primary">
            <div className="flex items-center justify-between border-b border-secondary px-3 py-2">
              <StatusLabel status={status} />
              <span className="font-mono text-xs tabular-nums text-quaternary">{col.length}</span>
            </div>
            <div className="space-y-2 p-2">
              {col.length === 0 && <p className="px-1 py-3 text-center text-xs text-quaternary">–</p>}
              {col.slice(0, 25).map((f) => (
                <BoardCard key={f.id} finding={f} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
              ))}
              {col.length > 25 && (
                <p className="px-1 py-2 text-center text-xs text-quaternary">+{col.length - 25} more – switch to Table view</p>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

export function BoardCard({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  return (
    <div className="rounded-lg border border-secondary bg-primary p-2.5">
      <div className="mb-1.5 flex items-center gap-1.5">
        <PriorityBadge priority={finding.priority} />
        <SevBadge sev={finding.severity} />
        {finding.kev && <KevBadge />}
      </div>
      <p className="line-clamp-2 text-sm font-medium text-primary" title={finding.title}>
        {finding.title}
      </p>
      {finding.assignee && <p className="mt-1 text-[11px] text-tertiary">@{finding.assignee}</p>}
      <div className="mt-2">
        <FindingStatusControl finding={finding} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
      </div>
    </div>
  )
}

export function FindingCollab({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-secondary bg-primary p-3">
      <AssigneeControl finding={finding} engagementId={engagementId} onUpdated={onUpdated} onReload={onReload} />
      <CommentsPanel engagementId={engagementId} findingId={finding.id} />
      <RetestPanel finding={finding} engagementId={engagementId} onUpdated={onUpdated} />
    </div>
  )
}

export const RETEST_OUTCOMES: { value: RetestOutcome; label: string }[] = [
  { value: 'remediated', label: 'Remediated' },
  { value: 'still_vulnerable', label: 'Still vulnerable' },
  { value: 'not_reproducible', label: 'Not reproducible' },
]

export function RetestOutcomeBadge({ outcome }: { outcome: RetestOutcome }) {
  const tone: Record<RetestOutcome, string> = {
    remediated: 'bg-accent/10 text-accent ring-accent/25',
    still_vulnerable: 'bg-critical/10 text-critical ring-critical/25',
    not_reproducible: 'bg-secondary text-tertiary ring-secondary',
  }
  const label: Record<RetestOutcome, string> = {
    remediated: 'Remediated',
    still_vulnerable: 'Still vuln',
    not_reproducible: 'Not repro',
  }
  return (
    <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ring-1 ring-inset', tone[outcome])}>
      {label[outcome]}
    </span>
  )
}

export function RetestPanel({ finding, engagementId, onUpdated }: { finding: Finding; engagementId: string; onUpdated: (f: Finding) => void }) {
  const [list, setList] = useState<Retest[]>([])
  const [outcome, setOutcome] = useState<RetestOutcome>('remediated')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useFetch(
    () => api.findingRetests(engagementId, finding.id).then((r) => { setList(r); return r }).catch(() => [] as Retest[]),
    { deps: [engagementId, finding.id] },
  )

  async function submit() {
    setBusy(true)
    setErr(null)
    try {
      const { retest, finding: updated } = await api.recordRetest(engagementId, finding.id, outcome, note, finding.version)
      setList((prev) => [...prev, retest])
      setNote('')
      onUpdated(updated)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setErr('Finding changed – reload and retry.')
      else setErr(e instanceof Error ? e.message : 'Failed to record retest')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-2 border-t border-secondary pt-3">
      <div className="flex items-center gap-1.5 text-xs font-medium text-tertiary">
        <RefreshCcw01 className="size-3.5" /> Retests
      </div>
      {list.length > 0 && (
        <ul className="space-y-1">
          {list.map((r) => (
            <li key={r.id} className="flex items-center gap-2 text-xs">
              <RetestOutcomeBadge outcome={r.outcome} />
              <span className="text-tertiary">{r.tester}</span>
              {r.note && <span className="truncate text-quaternary">– {r.note}</span>}
              <span className="ml-auto shrink-0 tabular-nums text-quaternary">{r.at ? new Date(r.at).toLocaleDateString() : ''}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={outcome}
          onValueChange={(v) => setOutcome(v as RetestOutcome)}
          ariaLabel="Retest outcome"
          size="sm"
          options={RETEST_OUTCOMES.map((o) => ({ value: o.value, label: o.label }))}
        />
        <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="note (optional)" className="h-8 flex-1 text-sm" />
        <Button loading={busy} onClick={submit} className="px-3 py-1.5 text-sm">
          Record
        </Button>
      </div>
      {err && <p className="text-xs text-critical">{err}</p>}
    </div>
  )
}

export function AssigneeControl({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [value, setValue] = useState(finding.assignee)
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<'' | 'saved' | 'failed' | 'conflict'>('')

  useEffect(() => {
    setValue(finding.assignee)
  }, [finding.assignee, finding.version])

  async function save() {
    if (value.trim() === finding.assignee) return
    setBusy(true)
    setNote('')
    try {
      onUpdated(await api.setFindingAssignee(engagementId, finding.id, value.trim(), finding.version))
      setNote('saved')
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setNote('conflict')
        onReload()
      } else {
        setNote('failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-[11px] uppercase tracking-wide text-quaternary">Assignee</span>
      <Input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onBlur={save}
        placeholder="unassigned"
        aria-label={`Assignee for ${finding.title}`}
        className="h-8 max-w-[14rem] text-sm"
      />
      {busy && <Loading01 className="size-3.5 animate-spin text-tertiary" />}
      {note === 'saved' && <span className="text-xs text-accent">saved</span>}
      {note === 'failed' && <span className="text-xs text-critical">failed</span>}
      {note === 'conflict' && (
        <span className="inline-flex items-center gap-1 text-xs font-medium text-medium">
          <AlertTriangle className="size-3" /> reloaded
        </span>
      )}
    </div>
  )
}

export function CommentsPanel({ engagementId, findingId }: { engagementId: string; findingId: string }) {
  const [comments, setComments] = useState<FindingComment[] | null>(null)
  const [body, setBody] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const { refetch: reload } = useFetch(
    () => api.findingComments(engagementId, findingId).then((c) => { setComments(c); return c }).catch(() => { setComments([]); return [] }),
    { deps: [engagementId, findingId] },
  )

  async function add() {
    if (!body.trim()) return
    setBusy(true)
    setErr(null)
    try {
      await api.addFindingComment(engagementId, findingId, body.trim())
      setBody('')
      reload()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to add comment')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <div className="mb-1.5 text-[11px] uppercase tracking-wide text-quaternary">Comments</div>
      <div className="space-y-1.5">
        {comments === null ? (
          <span className="text-xs text-quaternary">Loading…</span>
        ) : comments.length === 0 ? (
          <span className="text-xs text-quaternary">No comments yet.</span>
        ) : (
          comments.map((c) => (
            <div key={c.id} className="rounded-md bg-secondary px-2.5 py-1.5 text-xs">
              <span className="font-medium text-primary">{c.author}</span>
              <span className="text-quaternary"> · {c.createdAt ? new Date(c.createdAt).toLocaleString() : ''}</span>
              <p className="mt-0.5 whitespace-pre-line text-tertiary">{c.body}</p>
            </div>
          ))
        )}
      </div>
      <div className="mt-2 flex items-center gap-2">
        <Input
          value={body}
          onChange={(e) => setBody(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.nativeEvent.isComposing && !busy) add()
          }}
          placeholder="Add a comment…"
          aria-label="New comment"
          className="h-8 flex-1 text-sm"
        />
        <Button loading={busy} onClick={add} variant="secondary" className="h-8 px-3">
          Post
        </Button>
      </div>
      {err && <p className="mt-1 text-xs text-critical">{err}</p>}
    </div>
  )
}
