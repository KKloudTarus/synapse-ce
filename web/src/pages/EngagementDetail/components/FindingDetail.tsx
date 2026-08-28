import { ChevronRight, CheckVerified01, Shield01, ShieldTick } from '@untitledui/icons'
import { useState } from 'react'
import { Button, cn } from '../../../components/ui'
import { ApiError, api } from '../../../lib/api'
import type { Finding, Vulnerability } from '../../../lib/types'
import { ConfidenceBadge, DetectedBy, shortPkg } from '../VulnsTab'
import { AssigneeControl, CommentsPanel, RetestPanel } from './FindingCollab'
import { EVIDENCE_BAR, ExplainJudgments } from './FindingJudgments'

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
      <CheckVerified01 aria-hidden className="size-3.5 shrink-0 text-fg-tertiary" />
      <span aria-hidden className="text-[11px] font-bold uppercase tracking-wide text-secondary">
        Compliance
      </span>
      {controls.map((c) => (
        <span
          key={`${c.framework}:${c.id}`}
          role="listitem"
          className="inline-flex items-center gap-1.5 rounded-md border border-secondary bg-primary px-2 py-0.5 text-xs text-secondary"
        >
          <span className="text-tertiary">{frameworkShort(c.framework)}</span>
          <span className="font-mono font-bold tabular-nums text-primary">{c.id}</span>
          <span className="text-tertiary">{c.title}</span>
        </span>
      ))}
    </div>
  )
}

export function DetailKV({ label, value, valueClass }: { label: string; value: string; valueClass?: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="text-[11px] font-bold uppercase tracking-wide text-tertiary">{label}:</span>
      <span className={cn('font-semibold text-primary', valueClass)}>{value}</span>
    </span>
  )
}

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
        setErr('This finding changed: reloading latest state.')
        onReload()
      } else {
        setErr(e instanceof ApiError ? e.message : 'Verify failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="rounded-lg border border-secondary bg-primary p-3 shadow-2xs">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
        <span className="flex items-center gap-1.5">
          {proven ? (
            <ShieldTick className="size-4 text-success-primary" />
          ) : (
            <Shield01 className="size-4 text-warning-primary" />
          )}
          <span className={cn('font-semibold', proven ? 'text-success-primary' : 'text-warning-primary')}>
            {proven ? 'Verified (Reportable)' : 'Unproven (Not reportable)'}
          </span>
        </span>
        <DetailKV label="evidence" value={`${finding.evidenceScore}/${EVIDENCE_BAR}`} valueClass="font-mono font-bold tabular-nums" />
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
              <p className="text-[11px] text-tertiary">
                Record an adversarial verdict. The verifier must be a different person than the proposer; the verdict is
                sealed into the evidence chain. A score ≥ {EVIDENCE_BAR} makes it promotable.
              </p>
              <label htmlFor="evidence-score-input" className="flex items-center gap-2 text-xs">
                <span className="text-secondary font-medium">Score</span>
                <input
                  id="evidence-score-input"
                  type="number"
                  min={0}
                  max={100}
                  value={score}
                  onChange={(e) => setScore(Math.max(0, Math.min(100, Number(e.target.value))))}
                  className="w-20 rounded-md border border-secondary bg-secondary px-2 py-1 font-mono tabular-nums text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
                />
              </label>
              <textarea
                value={rationale}
                onChange={(e) => setRationale(e.target.value)}
                placeholder="Rationale (how it was reproduced / refuted)"
                aria-label="Verdict rationale"
                rows={2}
                className="w-full rounded-md border border-secondary bg-secondary px-2.5 py-1.5 text-xs text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
              />
              {err && <p className="text-xs text-error-primary">{err}</p>}
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
    <div className="grid grid-cols-1 items-stretch gap-4 lg:grid-cols-12">
      {/* Left Column (7 cols): Technical Analysis & Remediation Specs */}
      <div className="space-y-3.5 lg:col-span-7">
        {/* Description & Remediation Section */}
        {finding.description && (
          <div className="rounded-lg border border-secondary bg-primary p-3.5 shadow-2xs">
            <div className="mb-1 text-xs font-bold uppercase tracking-wider text-secondary">
              Vulnerability Description &amp; Impact
            </div>
            <p className="whitespace-pre-line text-xs leading-relaxed text-secondary font-sans">
              {finding.description}
            </p>
          </div>
        )}

        {/* Advisory & Package Metrics Ribbon */}
        {vuln ? (
          <div className="rounded-lg border border-secondary bg-primary p-3.5 shadow-2xs space-y-3">
            <div className="text-xs font-bold uppercase tracking-wider text-secondary">
              Advisory &amp; Dependency Metrics
            </div>

            {/* 4-Stat Metric Strip */}
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <div className="rounded-lg border border-secondary bg-secondary p-2.5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-tertiary">CVSS Score</span>
                <div className="mt-0.5 font-mono text-base font-bold tabular-nums text-primary">
                  {vuln.cvssScore > 0 ? vuln.cvssScore.toFixed(1) : '0.0'}
                </div>
              </div>
              <div className="rounded-lg border border-secondary bg-secondary p-2.5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-tertiary">EPSS Score</span>
                <div className="mt-0.5 font-mono text-base font-bold tabular-nums text-primary">
                  {vuln.epss > 0 ? `${(vuln.epss * 100).toFixed(1)}%` : '0.0%'}
                </div>
              </div>
              <div className="rounded-lg border border-secondary bg-secondary p-2.5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-tertiary">Installed</span>
                <div className="mt-0.5 truncate font-mono text-xs font-bold text-primary" title={`${vuln.component}@${vuln.version}`}>
                  {vuln.component}@{vuln.version}
                </div>
              </div>
              <div className="rounded-lg border border-secondary bg-secondary p-2.5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-tertiary">Fixed In</span>
                <div className="mt-0.5 flex items-center gap-1.5 font-mono text-xs font-bold">
                  {vuln.fixedVersion ? (
                    <span className="text-success-primary font-bold">{vuln.fixedVersion}</span>
                  ) : (
                    <span className="text-quaternary font-normal">None</span>
                  )}
                </div>
              </div>
            </div>

            {/* Detection & Path */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-secondary pt-2.5 text-xs">
              <span className="flex items-center gap-2">
                <span className="text-[11px] font-bold uppercase tracking-wide text-tertiary">Detected By:</span>
                <DetectedBy sources={vuln.sources} />
              </span>
              <span className="flex items-center gap-2">
                <span className="text-[11px] font-bold uppercase tracking-wide text-tertiary">Confidence:</span>
                <ConfidenceBadge confidence={vuln.confidence} />
              </span>
            </div>

            {vuln.path.length > 1 && (
              <div className="border-t border-secondary pt-2.5 text-xs">
                <span className="text-[11px] font-bold uppercase tracking-wide text-tertiary">Dependency Path:</span>
                <div className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-xs text-secondary">
                  {vuln.path.map((p, i) => (
                    <span key={i} className="flex items-center gap-1.5">
                      {i > 0 && <ChevronRight className="size-3 text-fg-quaternary" />}
                      <span className={i === vuln.path.length - 1 ? 'font-bold text-primary' : ''}>
                        {shortPkg(p)}
                      </span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="rounded-lg border border-secondary bg-primary p-3 text-xs text-tertiary">
            {finding.dedupKey.startsWith('license:')
              ? 'License-policy finding: Review module licensing compliance below.'
              : 'No matching scanner advisory detail found for this finding.'}
          </div>
        )}

        {/* Compliance Controls */}
        <ComplianceChips controls={finding.complianceControls} />

        {/* Evidence Gate for Exploitation findings */}
        {finding.kind === 'exploitation' && (
          <EvidenceGate
            finding={finding}
            engagementId={engagementId}
            onUpdated={onUpdated}
            onReload={onReload}
          />
        )}

        {/* Explain Judgments / AI Analysis */}
        <ExplainJudgments engagementId={engagementId} findingId={finding.id} />
      </div>

      {/* Right Column (5 cols): Collaboration, Assignment & Retests */}
      <div className="space-y-3.5 lg:col-span-5">
        {/* Assignment & Status Box */}
        <div className="rounded-lg border border-secondary bg-primary p-3.5 shadow-2xs space-y-3">
          <div className="text-xs font-bold uppercase tracking-wider text-secondary">
            Triage &amp; Assignment
          </div>
          <AssigneeControl
            finding={finding}
            engagementId={engagementId}
            onUpdated={onUpdated}
            onReload={onReload}
          />
        </div>

        {/* Retests History & Form */}
        <div className="rounded-lg border border-secondary bg-primary p-3.5 shadow-2xs space-y-3">
          <RetestPanel finding={finding} engagementId={engagementId} onUpdated={onUpdated} />
        </div>

        {/* Comments Thread */}
        <div className="rounded-lg border border-secondary bg-primary p-3.5 shadow-2xs space-y-3">
          <CommentsPanel engagementId={engagementId} findingId={finding.id} />
        </div>
      </div>
    </div>
  )
}
