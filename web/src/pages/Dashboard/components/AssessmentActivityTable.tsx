import type { FC } from 'react'
import { Link } from 'react-router-dom'
import { Target01 } from '@untitledui/icons'
import type { Engagement } from '../../../lib/types'
import { StatusPill } from '../../Engagements'

export interface AssessmentActivityTableProps {
  engagements: Engagement[]
  assetNames: Record<string, string>
}

export const AssessmentActivityTable: FC<AssessmentActivityTableProps> = ({
  engagements,
  assetNames,
}) => {
  if (engagements.length === 0) {
    return (
      <div className="flex min-h-52 flex-col items-center justify-center p-6 text-center">
        <span className="flex size-10 items-center justify-center rounded-full bg-secondary text-fg-tertiary">
          <Target01 className="size-5" />
        </span>
        <p className="mt-3 text-sm font-semibold text-primary">No Engagements yet</p>
        <p className="mt-1 max-w-sm text-xs leading-5 text-tertiary">
          Create an Engagement to define an authorized assessment scope.
        </p>
      </div>
    )
  }

  return (
    <div className="divide-y divide-secondary">
      {engagements.map((engagement) => (
        <Link
          key={engagement.id}
          to={`/engagements/${encodeURIComponent(engagement.id)}`}
          className="group grid gap-3 p-4 transition-colors hover:bg-secondary/50 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center sm:px-5"
        >
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="truncate font-semibold text-primary group-hover:text-brand-secondary">
                {engagement.name || 'Untitled Engagement'}
              </h3>
              <StatusPill status={engagement.status} />
            </div>
            <p className="mt-1 truncate text-xs text-secondary">
              {assetNames[engagement.businessAssetId] ||
                (engagement.businessAssetId ? engagement.businessAssetId : 'Unassigned Asset')}
            </p>
          </div>
          <div className="flex items-center gap-1.5 text-xs text-tertiary">
            <Target01 className="size-3.5" aria-hidden="true" />
            <span>{engagement.inScope.length} in scope</span>
          </div>
        </Link>
      ))}
    </div>
  )
}
