import type { FC } from 'react'
import { cx } from '@/utils/cx'
import type { StatCardProps } from '../types'

export const StatCard: FC<StatCardProps> = ({
  icon: Icon,
  label,
  value,
  hint,
  tone = 'muted',
  className,
}) => {
  const iconTone = {
    muted: 'text-fg-tertiary',
    brand: 'text-utility-brand-600 dark:text-utility-brand-400',
    critical: 'text-utility-red-600 dark:text-utility-red-400',
    high: 'text-utility-orange-600 dark:text-utility-orange-400',
    medium: 'text-utility-yellow-600 dark:text-utility-yellow-400',
    accent: 'text-utility-green-600 dark:text-utility-green-400',
    info: 'text-utility-blue-600 dark:text-utility-blue-400',
  }[tone]

  return (
    <div
      aria-label={`${label}: ${value}`}
      className={cx(
        'rounded-xl border border-secondary bg-primary p-4 shadow-xs transition duration-150 hover:border-primary',
        className,
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <span className="truncate block text-sm font-semibold text-secondary">{label}</span>
          <div className="mt-2 font-mono text-3xl font-bold tabular-nums text-primary sm:text-4xl">
            {typeof value === 'number' ? value.toLocaleString() : value}
          </div>
        </div>
        {Icon && (
          <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary text-secondary shadow-2xs">
            <Icon className={cx('size-5', iconTone)} aria-hidden="true" />
          </span>
        )}
      </div>
      {hint && (
        <p className="mt-2 truncate text-xs text-tertiary" title={hint}>
          {hint}
        </p>
      )}
    </div>
  )
}
