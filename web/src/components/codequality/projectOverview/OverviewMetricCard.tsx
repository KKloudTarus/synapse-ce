// Forced aliases: @untitledui/icons has no bug glyph, so the reliability metric
// renders an alert octagon (`Bug` is kept as the local name for readability).
import { ArrowRight, AlertOctagon as Bug, Copy01 as Copy, Eye, Speedometer04 as Gauge, Shield01 as Shield, Tool01 as Wrench } from '@untitledui/icons'
import type { FC, SVGProps } from 'react'
import { Link } from 'react-router-dom'
import type { OverviewDetailTarget } from '../../../lib/projectOverviewDetailTargets'
import type { OverviewMetricCardModel } from '../../../lib/projectOverviewPresentation'
import {
  availabilityLabel,
  formatOverviewPercentage,
  unavailableReasonText,
} from '../../../lib/projectOverviewPresentation'
import { Card, cn } from '../../ui'

const icons: Record<OverviewMetricCardModel['key'], FC<SVGProps<SVGSVGElement>>> = {
  security: Shield,
  reliability: Bug,
  maintainability: Wrench,
  securityHotspotsReviewed: Eye,
  coverage: Gauge,
  duplications: Copy,
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
  const value = card.kind === 'rating'
    ? available ? card.metric.grade : null
    : available && card.metric.value !== null ? formatOverviewPercentage(card.metric.value) : null
  const status = available ? (card.kind === 'rating' ? `Grade ${card.metric.grade}` : `Measured on ${lensLabel}`) : availabilityLabel(metric.availability)
  const reason = !available && metric.unavailableReason ? unavailableReasonText(metric.unavailableReason) : null

  return (
    <Card className="min-h-44">
      <div className="flex h-full flex-col gap-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-foreground">{card.label}</h3>
            <p className="mt-1 text-xs text-mutedfg">{status}</p>
          </div>
          <span className="inline-flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-elevated text-mutedfg">
            <Icon className="size-4" aria-hidden="true" />
          </span>
        </div>
        <div className={cn('font-mono text-4xl font-semibold tabular-nums', available ? 'text-foreground' : 'text-mutedfg')}>
          {value ?? '—'}
        </div>
        {reason && <p className="text-sm text-mutedfg">{reason}</p>}
        {detailTarget ? (
          <Link
            to={detailTarget.to}
            aria-label={detailTarget.label}
            className="mt-auto inline-flex w-fit items-center gap-1.5 rounded-md text-sm font-medium text-branddim hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-card"
          >
            View details <ArrowRight className="size-4" aria-hidden="true" />
          </Link>
        ) : (
          <p className="mt-auto text-xs text-subtlefg">Details not available yet</p>
        )}
      </div>
    </Card>
  )
}
