import type { FC } from 'react'
import { cx } from '@/utils/cx'

export interface PageLoadingProps {
  variant?: 'table' | 'card' | 'detail'
  className?: string
}

export const PageLoading: FC<PageLoadingProps> = ({ variant = 'table', className }) => {
  if (variant === 'card') {
    return (
      <div
        data-testid="page-loading-card"
        className={cx('grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 w-full animate-pulse', className)}
      >
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-border bg-card p-5 space-y-3">
            <div className="h-5 w-1/2 rounded-md bg-secondary" />
            <div className="h-3.5 w-3/4 rounded-md bg-secondary/80" />
            <div className="h-3.5 w-full rounded-md bg-secondary/60" />
            <div className="pt-2">
              <div className="h-7 w-1/3 rounded-lg bg-secondary" />
            </div>
          </div>
        ))}
      </div>
    )
  }

  if (variant === 'detail') {
    return (
      <div data-testid="page-loading-detail" className={cx('w-full space-y-6 animate-pulse', className)}>
        {/* Header Block */}
        <div className="rounded-xl border border-border bg-card p-6 space-y-3">
          <div className="h-7 w-1/3 rounded-md bg-secondary" />
          <div className="h-4 w-1/2 rounded-md bg-secondary/80" />
        </div>

        {/* Content + Sidebar Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 rounded-xl border border-border bg-card p-6 space-y-4">
            <div className="h-5 w-1/4 rounded-md bg-secondary" />
            <div className="h-3.5 w-full rounded-md bg-secondary/80" />
            <div className="h-3.5 w-5/6 rounded-md bg-secondary/80" />
            <div className="h-3.5 w-4/6 rounded-md bg-secondary/80" />
            <div className="pt-4 space-y-3">
              <div className="h-4 w-1/3 rounded-md bg-secondary" />
              <div className="h-3.5 w-full rounded-md bg-secondary/70" />
              <div className="h-3.5 w-3/4 rounded-md bg-secondary/70" />
            </div>
          </div>
          <div className="rounded-xl border border-border bg-card p-6 space-y-4">
            <div className="h-5 w-1/2 rounded-md bg-secondary" />
            <div className="h-3.5 w-full rounded-md bg-secondary/80" />
            <div className="h-3.5 w-2/3 rounded-md bg-secondary/80" />
            <div className="h-3.5 w-4/5 rounded-md bg-secondary/80" />
          </div>
        </div>
      </div>
    )
  }

  // Default: 'table'
  return (
    <div data-testid="page-loading-table" className={cx('w-full rounded-xl border border-border bg-card p-5 space-y-4 animate-pulse', className)}>
      {/* Table Header skeleton */}
      <div className="flex items-center gap-4 py-2 border-b border-border">
        <div className="h-4 w-1/4 rounded-md bg-secondary" />
        <div className="h-4 w-1/4 rounded-md bg-secondary" />
        <div className="h-4 w-1/4 rounded-md bg-secondary" />
        <div className="h-4 w-1/4 rounded-md bg-secondary" />
      </div>
      {/* 5 Table Rows */}
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 py-3 border-b border-border/50 last:border-0">
          <div className="h-3.5 w-1/4 rounded-md bg-secondary/80" />
          <div className="h-3.5 w-1/3 rounded-md bg-secondary/70" />
          <div className="h-3.5 w-1/6 rounded-md bg-secondary/60" />
          <div className="h-3.5 w-1/6 rounded-md bg-secondary/60" />
        </div>
      ))}
    </div>
  )
}
