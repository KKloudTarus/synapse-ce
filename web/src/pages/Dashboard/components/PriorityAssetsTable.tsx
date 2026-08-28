import type { FC } from 'react'
import { Link } from 'react-router-dom'
import { CheckCircle } from '@untitledui/icons'
import type { BusinessAsset } from '../../../lib/types'
import { PostureBadge } from '../../Assets/Assets'

export interface PriorityAssetsTableProps {
  assets: BusinessAsset[]
  hasTotalAssets: boolean
}

export const PriorityAssetsTable: FC<PriorityAssetsTableProps> = ({ assets, hasTotalAssets }) => {
  if (assets.length === 0) {
    return (
      <div className="flex min-h-52 flex-col items-center justify-center p-6 text-center">
        <span className="flex size-10 items-center justify-center rounded-full bg-secondary text-fg-tertiary">
          <CheckCircle className="size-5" />
        </span>
        <p className="mt-3 text-sm font-semibold text-primary">No priority Assets</p>
        <p className="mt-1 max-w-sm text-xs leading-5 text-tertiary">
          {hasTotalAssets ? 'All loaded Assets report good posture.' : 'Create an Asset to begin posture tracking.'}
        </p>
      </div>
    )
  }

  return (
    <div className="divide-y divide-secondary">
      {assets.map((asset) => (
        <Link
          key={asset.id}
          to={`/assets/${encodeURIComponent(asset.id)}`}
          className="group flex items-center justify-between gap-3 px-4 py-3 transition-colors hover:bg-primary_hover sm:px-5"
        >
          <div className="min-w-0 flex-1">
            <h3 className="truncate text-sm font-medium text-primary group-hover:text-brand-secondary">
              {asset.name}
            </h3>
            <p className="mt-0.5 truncate text-xs text-tertiary">
              {asset.owner || 'Owner not set'} · {labelize(asset.lifecycle)}
            </p>
          </div>
          <div className="shrink-0">
            <PostureBadge rating={asset.posture ?? 'unknown'} />
          </div>
        </Link>
      ))}
    </div>
  )
}

function labelize(value: string) {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}
