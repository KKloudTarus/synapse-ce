import type { FC } from 'react'
import { Badge } from '../../../components/base/badges/badges'
import type { BadgeColors } from '../../../components/base/badges/badge-types'
import { cx } from '@/utils/cx'

export interface StatusPillProps {
  status: string
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

export const StatusPill: FC<StatusPillProps> = ({ status, size = 'sm', className }) => {
  const normalized = (status || 'draft').toLowerCase()

  let color: BadgeColors = 'gray'

  if (normalized === 'active') {
    color = 'blue'
  } else if (normalized === 'completed') {
    color = 'success'
  } else if (normalized === 'archived') {
    color = 'gray'
  } else {
    // Draft or other
    color = 'gray'
  }

  const label = normalized.charAt(0).toUpperCase() + normalized.slice(1)

  return (
    <Badge
      size={size}
      color={color}
      type="pill-color"
      className={cx(
        'font-medium capitalize',
        normalized === 'archived' && 'opacity-60',
        normalized === 'draft' && 'bg-utility-neutral-100/60 ring-utility-neutral-300 dark:bg-utility-neutral-900/60 dark:ring-utility-neutral-700',
        className,
      )}
    >
      {label}
    </Badge>
  )
}
