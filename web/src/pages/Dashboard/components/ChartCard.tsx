import type { FC, ReactNode } from 'react'

export interface ChartCardProps {
  title: string
  description: string
  action?: ReactNode
  children: ReactNode
}

export const ChartCard: FC<ChartCardProps> = ({ title, description, action, children }) => {
  return (
    <section className="flex flex-col rounded-xl border border-secondary bg-primary shadow-xs">
      <header className="flex items-center justify-between gap-3 border-b border-secondary px-5 py-4 sm:px-6">
        <div>
          <h2 className="text-sm font-semibold text-primary">{title}</h2>
          <p className="mt-0.5 text-xs text-tertiary">{description}</p>
        </div>
        {action && <div>{action}</div>}
      </header>
      <div className="p-5 sm:p-6">{children}</div>
    </section>
  )
}
