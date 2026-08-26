import type { FC, ElementType } from 'react'
import { cx } from '@/utils/cx'

export interface EngagementStatCardProps {
  label: string
  value: number | string
  icon: ElementType
  tone?: 'default' | 'info' | 'accent' | 'brand' | 'warning' | 'high'
}

const TONE_CLASSES: Record<NonNullable<EngagementStatCardProps['tone']>, string> = {
  default: 'text-tertiary',
  info: 'text-utility-blue-600 dark:text-utility-blue-400',
  accent: 'text-utility-indigo-600 dark:text-utility-indigo-400',
  brand: 'text-brand-secondary',
  warning: 'text-warning-primary',
  high: 'text-critical',
}

export const EngagementStatCard: FC<EngagementStatCardProps> = ({
  label,
  value,
  icon: Icon,
  tone = 'default',
}) => {
  return (
    <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <span className="block truncate text-sm font-semibold text-secondary">{label}</span>
          <div className="mt-2 font-mono text-3xl font-bold tabular-nums text-primary sm:text-4xl">
            {value}
          </div>
        </div>
        <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary shadow-2xs">
          <Icon className={cx('size-5', TONE_CLASSES[tone])} aria-hidden="true" />
        </span>
      </div>
    </div>
  )
}
