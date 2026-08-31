import { Check, Copy01, ShieldTick } from '@untitledui/icons'
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

export function EvidenceBadge({ engagementId }: { engagementId: string }) {
  const { data: ev } = useFetch(
    () =>
      api.evidence(engagementId).then((e) =>
        e && e.verified > 0 ? { intact: e.intact, verified: e.verified, keyId: e.attestation?.key_id } : null,
      ),
    { deps: [engagementId] },
  )
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
