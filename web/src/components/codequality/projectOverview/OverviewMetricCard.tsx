import {
  AlertCircle,
  Copy01,
  FileCode01,
  PieChart01,
  Shield01,
  Target04,
} from '@untitledui/icons'
import type { FC, SVGProps } from 'react'
import { Link } from 'react-router-dom'
import type { OverviewDetailTarget } from '../../../lib/projectOverviewDetailTargets'
import type { OverviewGrade } from '../../../lib/projectOverview'
import type { OverviewMetricCardModel } from '../../../lib/projectOverviewPresentation'
import {
  availabilityLabel,
  formatOverviewPercentage,
  unavailableReasonText,
} from '../../../lib/projectOverviewPresentation'
import { Card, cn } from '../../ui'

const icons: Record<OverviewMetricCardModel['key'], FC<SVGProps<SVGSVGElement>>> = {
  security: Shield01,
  reliability: AlertCircle,
  maintainability: FileCode01,
  securityHotspotsReviewed: Target04,
  coverage: PieChart01,
  duplications: Copy01,
}

function getRatingColor(grade: OverviewGrade | null): string {
  switch (grade) {
    case 'A':
      return 'text-success-primary'
    case 'B':
      return 'text-utility-blue-600'
    case 'C':
      return 'text-warning-primary'
    case 'D':
      return 'text-utility-orange-600'
    case 'E':
      return 'text-error-primary'
    default:
      return 'text-primary'
  }
}

function getPercentageColor(key: OverviewMetricCardModel['key'], val: number | null): string {
  if (val === null) return 'text-tertiary'
  if (key === 'duplications') {
    if (val <= 3.5) return 'text-success-primary'
    if (val <= 10) return 'text-utility-orange-600'
    return 'text-error-primary'
  }
  if (key === 'coverage') {
    if (val >= 80) return 'text-success-primary'
    if (val >= 50) return 'text-utility-blue-600'
    return 'text-error-primary'
  }
  if (key === 'securityHotspotsReviewed') {
    if (val >= 80) return 'text-success-primary'
    if (val >= 50) return 'text-brand-secondary'
    return 'text-error-primary'
  }
  return 'text-primary'
}

function getProgressBarColor(key: OverviewMetricCardModel['key'], val: number | null): string {
  if (val === null) return 'bg-secondary'
  if (key === 'duplications') {
    if (val <= 3.5) return 'bg-utility-green-600'
    if (val <= 10) return 'bg-utility-orange-600'
    return 'bg-utility-pink-600'
  }
  if (key === 'coverage') {
    if (val >= 80) return 'bg-utility-green-600'
    if (val >= 50) return 'bg-utility-blue-600'
    return 'bg-utility-orange-600'
  }
  if (key === 'securityHotspotsReviewed') {
    if (val >= 80) return 'bg-utility-green-600'
    if (val >= 50) return 'bg-brand-solid'
    return 'bg-utility-orange-600'
  }
  return 'bg-brand-solid'
}

export function OverviewMetricCard({
  card,
  detailTarget,
  lensLabel,
}: {
  card: OverviewMetricCardModel
  detailTarget: OverviewDetailTarget | null
  lensLabel: string
}) {
  const Icon = icons[card.key]
  const metric = card.metric
  const available = metric.availability === 'available'
  const isNotSupplied = metric.availability === 'not_supplied'
  
  const value = card.kind === 'rating'
    ? available ? card.metric.grade : isNotSupplied ? 'Not supplied' : null
    : available && card.metric.value !== null ? formatOverviewPercentage(card.metric.value) : isNotSupplied ? 'Not supplied' : null

  const status = available
    ? card.kind === 'rating'
      ? `Grade ${card.metric.grade}`
      : `Measured on ${lensLabel}`
    : availabilityLabel(metric.availability)

  const reason = !available && metric.unavailableReason ? unavailableReasonText(metric.unavailableReason) : null

  const colorClass = card.kind === 'rating'
    ? available ? getRatingColor(card.metric.grade) : 'text-tertiary'
    : available ? getPercentageColor(card.key, card.metric.value) : 'text-tertiary'

  const progressPercent = card.kind === 'percentage' && available && card.metric.value !== null
    ? Math.min(100, Math.max(0, card.metric.value))
    : 0

  const content = (
    <Card className="group/card flex h-full flex-col justify-between p-4 shadow-xs transition-all hover:border-brand-solid hover:shadow-md">
      <div className="flex h-full flex-col gap-3">
        {/* Header: Label on left, Icon on right */}
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-primary">{card.label}</h3>
            <p className="mt-0.5 text-xs text-tertiary">{status}</p>
            {reason && <p className="mt-0.5 text-xs text-quaternary">{reason}</p>}
          </div>
          <span className="inline-flex size-8 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary text-secondary transition-colors group-hover/card:border-brand-solid group-hover/card:bg-brand-primary group-hover/card:text-brand-secondary">
            <Icon className="size-4" aria-hidden="true" />
          </span>
        </div>

        {/* Center: Main value display */}
        <div className="my-1 flex items-baseline gap-2">
          <div className={cn('font-mono text-3xl font-bold tabular-nums tracking-tight', colorClass)}>
            {value ?? (
              <>
                <span>0</span>
                <span className="sr-only">—</span>
              </>
            )}
          </div>
        </div>

        {/* Progress Bar for Percentage Metrics */}
        {card.kind === 'percentage' && available && card.metric.value !== null && (
          <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
            <div
              className={cn('h-full transition-all duration-300', getProgressBarColor(card.key, card.metric.value))}
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        )}

        {!detailTarget && <span className="sr-only">Details not available yet</span>}
      </div>
    </Card>
  )

  if (detailTarget) {
    return (
      <Link
        to={detailTarget.to}
        aria-label={detailTarget.label}
        className="group block rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
      >
        {content}
      </Link>
    )
  }

  return <div className="rounded-xl">{content}</div>
}
