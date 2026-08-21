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
    muted: 'bg-secondary text-fg-tertiary',
    brand: 'bg-utility-brand-50 text-utility-brand-700 dark:bg-utility-brand-950/50 dark:text-utility-brand-300',
    critical: 'bg-utility-red-50 text-utility-red-700 dark:bg-utility-red-950/50 dark:text-utility-red-300',
    high: 'bg-utility-orange-50 text-utility-orange-700 dark:bg-utility-orange-950/50 dark:text-utility-orange-300',
    medium: 'bg-utility-yellow-50 text-utility-yellow-700 dark:bg-utility-yellow-950/50 dark:text-utility-yellow-300',
    accent: 'bg-utility-green-50 text-utility-green-700 dark:bg-utility-green-950/50 dark:text-utility-green-300',
  }[tone]

  return (
    <div
      aria-label={`${label}: ${value}`}
      className={cx(
        'rounded-xl border border-border bg-card p-4 shadow-xs transition duration-150 hover:border-borderstrong',
        className,
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-2xl font-bold tabular-nums text-primary sm:text-3xl">
            {typeof value === 'number' ? value.toLocaleString() : value}
          </div>
          <div className="mt-1 text-xs font-semibold text-secondary sm:text-sm">{label}</div>
        </div>
        <span className={cx('flex size-9 shrink-0 items-center justify-center rounded-lg', iconTone)}>
          <Icon className="size-4.5" aria-hidden="true" />
        </span>
      </div>
      <p className="mt-3 truncate text-xs text-tertiary" title={hint}>
        {hint}
      </p>
    </div>
  )
}
