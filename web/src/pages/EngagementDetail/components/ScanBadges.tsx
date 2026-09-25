import { AlertTriangle, Check, Copy01, ShieldTick } from '@untitledui/icons'
import { copyText } from '../../../lib/clipboard'
import { useState } from 'react'
import { cn } from '../../../components/ui'
import { useFetch } from '../../../hooks'
import { api } from '../../../lib/api'
import { kindLabel } from '../../../lib/format'

export function ScopeBadge({ target }: { target: { kind: string; value: string } }) {
  const [copied, setCopied] = useState(false)
  const displayValue =
    target.kind === 'repo' && target.value.includes('/')
      ? target.value.split('/').slice(-1)[0].replace(/\.git$/, '')
      : target.value

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation()
    copyText(target.value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md border border-utility-blue-200 bg-utility-blue-50 py-0.5 pl-1.5 pr-1 text-xs text-utility-blue-700 font-medium"
      title={target.value}
    >
      <span className="rounded bg-utility-blue-100 px-1 py-0.2 text-[9px] font-bold uppercase tracking-wide text-utility-blue-700">
        {kindLabel(target.kind)}
      </span>
      <span className="font-mono font-semibold text-primary">{displayValue}</span>
      <button
        type="button"
        onClick={handleCopy}
        className="inline-flex size-4 items-center justify-center rounded transition-colors hover:bg-utility-blue-200 hover:text-utility-blue-800 focus-visible:outline-none"
        title={copied ? 'Copied full URL!' : 'Copy full URL'}
      >
        {copied ? (
          <Check className="size-3 text-success-primary" />
        ) : (
          <Copy01 className="size-3 text-fg-tertiary hover:text-primary" />
        )}
      </button>
    </span>
  )
}

/**
 * The evidence chain has three answers, and all three are shown.
 *
 * Rendering nothing on failure was the fourth, silent one: an unreachable evidence service looked
 * exactly like an engagement with a clean chain, because a reader takes the absence of a tamper
 * badge as the absence of tampering. The chain is hash-linked and a break blocks the report, so
 * "could not check" has to be visible rather than collapsed into silence.
 */
export function EvidenceBadge({ engagementId }: { engagementId: string }) {
  const { data: ev, error } = useFetch(
    () =>
      api.evidence(engagementId).then((e) =>
        e && e.verified > 0 ? { intact: e.intact, verified: e.verified, keyId: e.attestation?.key_id } : null,
      ),
    { deps: [engagementId] },
  )

  if (error) {
    return (
      <span
        className="inline-flex items-center gap-1.5 rounded-full border border-warning bg-warning-primary px-2.5 py-0.5 text-xs font-semibold text-warning-primary"
        title={`The evidence chain could not be checked: ${error}. This is not a statement that the chain is intact.`}
      >
        <AlertTriangle className="size-3.5" />
        <span>Evidence unchecked</span>
      </span>
    )
  }
  if (!ev) return null
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold',
        ev.intact
          ? 'border-utility-green-300 bg-success-primary text-success-primary'
          : 'border-error bg-error-primary text-error-primary',
      )}
      title={
        ev.intact
          ? `${ev.verified} verified links in hash chain${ev.keyId ? ` (signed by ${ev.keyId})` : ''}`
          : 'Evidence integrity compromised'
      }
    >
      <ShieldTick className="size-3.5" />
      <span>{ev.intact ? 'Evidence verified' : 'Evidence tampered'}</span>
    </span>
  )
}
