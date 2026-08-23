import type { FC, ElementType } from 'react'
import { cx } from '@/utils/cx'

export interface EngagementStatCardProps {
  label: string
  value: number | string
  icon: ElementType
  hint?: string
  tone?: 'default' | 'info' | 'accent' | 'brand' | 'warning' | 'high'
}

const TONE_CLASSES: Record<NonNullable<EngagementStatCardProps['tone']>, string> = {
  default: 'text-tertiary',
  info: 'text-utility-blue-600 dark:text-utility-blue-400',
  accent: 'text-utility-indigo-600 dark:text-utility-indigo-400',
  brand: 'text-utility-brand-600 dark:text-utility-brand-400',
  warning: 'text-utility-yellow-600 dark:text-utility-yellow-400',
  high: 'text-utility-orange-600 dark:text-utility-orange-400',
}

export const EngagementStatCard: FC<EngagementStatCardProps> = ({
  label,
  value,
  icon: Icon,
  hint,
  tone = 'default',
}) => {
  return (
    <div className="flex flex-col justify-between rounded-xl border border-secondary bg-primary p-5 shadow-xs transition-colors hover:border-border-primary">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-semibold text-secondary">{label}</span>
        <Icon className={cx('size-5 shrink-0', TONE_CLASSES[tone])} aria-hidden="true" />
      </div>
      <div className="mt-3 flex items-baseline justify-between gap-2">
        <div className="text-3xl font-bold tabular-nums tracking-tight text-primary sm:text-4xl">
          {value}
        </div>
      </div>
      {hint && <p className="mt-1 text-[11px] text-tertiary">{hint}</p>}
    </div>
  )
}
