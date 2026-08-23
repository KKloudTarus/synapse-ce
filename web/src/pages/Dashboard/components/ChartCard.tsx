import type { FC, ReactNode } from 'react'
import { cx } from '@/utils/cx'

export interface ChartCardProps {
  title: string
  description: string
  action?: ReactNode
  children: ReactNode
  className?: string
}

export const ChartCard: FC<ChartCardProps> = ({ title, description, action, children, className }) => {
  return (
    <section className={cx("flex flex-col rounded-xl border border-secondary bg-primary shadow-xs", className)}>
      <header className="flex items-center justify-between gap-3 border-b border-secondary px-5 py-4 sm:px-6">
        <div>
          <h2 className="text-base font-bold text-primary sm:text-lg">{title}</h2>
          <p className="mt-0.5 text-xs text-tertiary sm:text-sm">{description}</p>
        </div>
        {action && <div>{action}</div>}
      </header>
      <div className="p-5 sm:p-6">{children}</div>
    </section>
  )
}
