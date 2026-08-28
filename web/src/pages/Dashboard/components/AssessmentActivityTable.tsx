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
    <div className="max-h-[400px] divide-y divide-secondary overflow-y-auto">
      {engagements.map((engagement) => (
        <Link
          key={engagement.id}
          to={`/engagements/${encodeURIComponent(engagement.id)}`}
          className="group flex items-start gap-3 px-4 py-3 transition-colors hover:bg-primary_hover"
        >
          <Target01 className="mt-0.5 size-5 shrink-0 text-fg-quaternary group-hover:text-fg-secondary" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="truncate text-sm font-medium text-primary group-hover:text-brand-secondary">
                {engagement.name || 'Untitled Engagement'}
              </span>
              <StatusPill status={engagement.status} />
            </div>
            <p className="mt-0.5 truncate text-xs text-tertiary">
              {assetNames[engagement.businessAssetId] ||
                (engagement.businessAssetId ? engagement.businessAssetId : 'Unassigned')}
              {engagement.inScope && engagement.inScope.length > 0 && ` · ${engagement.inScope.length} in scope`}
            </p>
          </div>
        </Link>
      ))}
    </div>
  )
}
