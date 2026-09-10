import type { UploadedSourcePackage } from '../../lib/types'

function formatTime(value?: string | null) {
  if (!value) return 'Unknown time'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString()
}

export function SourcePackageSummary({ source, compact = false }: { source: UploadedSourcePackage; compact?: boolean }) {
  return <div className="min-w-0 space-y-1 text-xs text-tertiary">
    <p className="break-words font-medium text-primary">{source.filename || 'Source archive'}</p>
    <p>{source.size.toLocaleString()} bytes{source.reusedFromVersionId ? ' · Reused source' : ''}</p>
    <p className="break-all font-mono" aria-label={`Source SHA-256 ${source.sha256}`}>SHA-256: {source.sha256 || 'Unavailable'}</p>
    {!compact ? <>
      {source.versionId ? <p className="break-all font-mono">Version: {source.versionId}</p> : null}
      <p className="break-words">Uploaded by {source.uploadedBy || 'Unknown actor'} · {formatTime(source.uploadedAt)}</p>
      {source.associatedAt ? <p className="break-words">Associated by {source.associatedBy || 'Unknown actor'} · {formatTime(source.associatedAt)}</p> : null}
    </> : null}
  </div>
}
