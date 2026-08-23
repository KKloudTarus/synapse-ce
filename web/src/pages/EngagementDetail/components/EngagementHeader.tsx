import { useState, type FC } from 'react'
import { Link } from 'react-router-dom'
import {
  ChevronRight,
  LayersThree01,
  Target01,
  Calendar,
  Edit01,
  Copy01,
  Check,
  CheckCircle,
  AlertCircle,
  FileCheck02,
} from '@untitledui/icons'
import { api } from '../../../lib/api'
import { useFetch } from '../../../hooks'
import { kindLabel } from '../../../lib/format'
import { StatusPill } from '../../Engagements'
import { ExportButtons } from '../ExportButtons'
import { fmtWindow } from '../VulnsTab'
import { cx } from '@/utils/cx'
import type { BusinessAsset, Engagement, ScanResult } from '../../../lib/types'

export interface EngagementHeaderProps {
  engagement: Engagement
  scan: ScanResult | null
  onChanged: () => void
  onGoToSettings?: () => void
}

export const EngagementHeader: FC<EngagementHeaderProps> = ({
  engagement,
  scan,
  onChanged,
  onGoToSettings,
}) => {
  const [copiedId, setCopiedId] = useState(false)

  const copyId = (e: React.MouseEvent) => {
    e.stopPropagation()
    navigator.clipboard.writeText(engagement.id)
    setCopiedId(true)
    setTimeout(() => setCopiedId(false), 2000)
  }

  const primaryTarget =
    engagement.inScope.find((s) => s.kind === 'repo')?.value ||
    engagement.inScope[0]?.value ||
    null

  return (
    <div className="space-y-4">
      {/* 5.1 Breadcrumb */}
      <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-xs text-tertiary">
        <Link
          to="/engagements"
          className="font-medium text-secondary transition-colors hover:text-primary"
        >
          Engagements
        </Link>
        <ChevronRight className="size-3.5 shrink-0 text-quaternary" aria-hidden="true" />
        <span
          className="max-w-[280px] truncate font-semibold text-primary"
          aria-current="page"
          title={engagement.name}
        >
          {engagement.name || 'Untitled Engagement'}
        </span>
      </nav>

      {/* 5.2 Header Title & Actions */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 space-y-1.5">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="max-w-2xl truncate text-2xl font-bold tracking-tight text-primary sm:text-display-xs">
              {engagement.name || 'Untitled Engagement'}
            </h1>
            <StatusPill status={engagement.status} />
            <EvidenceBadge engagementId={engagement.id} />
          </div>

          {/* Primary Repo/Target with copy affordance */}
          <div className="flex flex-wrap items-center gap-2 pt-0.5 text-xs text-tertiary font-mono">
            <span>ID:</span>
            <span className="text-secondary" title={engagement.id}>
              {engagement.id}
            </span>
            <button
              type="button"
              onClick={copyId}
              title="Copy ID"
              aria-label={`Copy ID ${engagement.id}`}
              className="rounded p-0.5 text-quaternary hover:text-primary focus:outline-none"
            >
              {copiedId ? (
                <Check className="size-3 text-utility-green-600 dark:text-utility-green-400" />
              ) : (
                <Copy01 className="size-3" />
              )}
            </button>
            {primaryTarget && (
              <>
                <span className="text-quaternary">·</span>
                <span className="text-secondary truncate max-w-md font-mono" title={primaryTarget}>
                  {primaryTarget}
                </span>
              </>
            )}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5">
          {engagement.status !== 'archived' && onGoToSettings && (
            <button
              type="button"
              onClick={onGoToSettings}
              className="inline-flex items-center gap-1.5 rounded-lg border border-secondary bg-primary px-3 py-2 text-xs font-semibold text-secondary shadow-xs transition hover:bg-secondary hover:text-primary focus:outline-none focus:ring-2 focus:ring-brand/30"
            >
              <Edit01 className="size-3.5 text-tertiary" />
              Edit
            </button>
          )}

          <ExportButtons engagementId={engagement.id} scan={scan} onChanged={onChanged} />
        </div>
      </div>

      {/* Metadata Row */}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-secondary border-t border-secondary pt-3">
        {engagement.client && (
          <span className="flex items-center gap-1.5 text-secondary">
            <span className="text-tertiary">Client:</span>
            <strong className="font-semibold text-primary">{engagement.client}</strong>
          </span>
        )}

        {engagement.businessAssetId ? (
          <Link
            to={`/assets/${encodeURIComponent(engagement.businessAssetId)}`}
            className="inline-flex items-center gap-1.5 font-medium text-brand-secondary hover:text-brand-primary transition-colors"
          >
            <LayersThree01 className="size-3.5 text-brand-secondary" />
            Asset: {engagement.businessAssetId}
          </Link>
        ) : (
          <span className="inline-flex items-center gap-1.5 text-tertiary">
            <LayersThree01 className="size-3.5 text-quaternary" />
            Unassigned Asset
          </span>
        )}

        <span className="inline-flex items-center gap-1.5 text-secondary">
          <Target01 className="size-3.5 text-tertiary" />
          <span>{engagement.inScope.length} in scope</span>
        </span>

        {(engagement.authorizedFrom || engagement.authorizedTo) && (
          <span className="inline-flex items-center gap-1.5 text-secondary font-mono">
            <Calendar className="size-3.5 text-tertiary" />
            {fmtWindow(engagement.authorizedFrom, engagement.authorizedTo)}
          </span>
        )}
      </div>

      {/* Asset Assignment Inline Bar */}
      <AssetAssignment engagement={engagement} onChanged={onChanged} />

      {/* In-Scope Target Badges */}
      {engagement.inScope.length > 0 && (
        <div className="flex flex-wrap gap-2 pt-1">
          {engagement.inScope.map((t, i) => (
            <span
              key={i}
              className="inline-flex items-center gap-2 rounded-lg border border-secondary bg-secondary/50 py-1 pl-2 pr-2.5 text-xs text-secondary"
            >
              <span className="rounded bg-brand-primary/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-brand-secondary">
                {kindLabel(t.kind)}
              </span>
              <span className="font-mono text-primary truncate max-w-xs">{t.value}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

function AssetAssignment({
  engagement,
  onChanged,
}: {
  engagement: Engagement
  onChanged: () => void
}) {
  const { data: assets } = useFetch(
    () => api.listBusinessAssets('limit=200').then((r) => r.items).catch(() => [] as BusinessAsset[]),
    { deps: [] },
  )
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function assign(assetId: string) {
    setSaving(true)
    setError(null)
    try {
      await api.assignEngagementAsset(engagement.id, assetId)
      onChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to assign Asset')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2.5 text-xs">
      <span className="font-semibold text-tertiary uppercase tracking-wider text-[10px]">
        Assign Asset:
      </span>
      <select
        value={engagement.businessAssetId}
        onChange={(e) => assign(e.target.value)}
        disabled={saving}
        className="cursor-pointer rounded-lg border border-secondary bg-primary px-2.5 py-1 text-xs font-medium text-secondary shadow-xs outline-none focus:border-brand disabled:opacity-50"
      >
        <option value="">Unassigned</option>
        {(assets ?? []).map((a) => (
          <option key={a.id} value={a.id}>
            {a.name} ({a.key})
          </option>
        ))}
      </select>
      {error && <span className="text-xs text-utility-red-600 dark:text-utility-red-400">{error}</span>}
    </div>
  )
}

function EvidenceBadge({ engagementId }: { engagementId: string }) {
  const { data: ev } = useFetch(
    () =>
      api.evidence(engagementId).then((e) =>
        e && e.verified > 0 ? { intact: e.intact, verified: e.verified, keyId: e.attestation?.key_id } : null,
      ),
    { deps: [engagementId] },
  )
  if (!ev) return null
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={cx(
          'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset',
          ev.intact
            ? 'bg-utility-green-50 text-utility-green-700 ring-utility-green-200 dark:bg-utility-green-950/40 dark:text-utility-green-300 dark:ring-utility-green-800'
            : 'bg-utility-red-50 text-utility-red-700 ring-utility-red-200 dark:bg-utility-red-950/40 dark:text-utility-red-300 dark:ring-utility-red-800',
        )}
        title={`${ev.verified} evidence link(s) in the hash chain`}
      >
        {ev.intact ? (
          <CheckCircle className="size-3.5 text-utility-green-600 dark:text-utility-green-400" />
        ) : (
          <AlertCircle className="size-3.5 text-utility-red-600 dark:text-utility-red-400" />
        )}
        {ev.intact ? 'Evidence verified' : 'Evidence tampered'}
      </span>
      {ev.intact && ev.keyId && (
        <span
          className="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-0.5 font-mono text-xs text-tertiary ring-1 ring-inset ring-secondary"
          title={`Chain head signed (ed25519) by key ${ev.keyId} – proves origin, not just integrity`}
        >
          <FileCheck02 className="size-3.5 text-quaternary" />
          {ev.keyId}
        </span>
      )}
    </span>
  )
}
