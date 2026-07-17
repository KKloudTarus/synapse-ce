import { Bug, Copy, Eye, Gauge, Shield, Wrench, type LucideIcon } from 'lucide-react'
import type { OverviewMetricCardModel } from '../../../lib/projectOverviewPresentation'
import {
  availabilityLabel,
  formatOverviewPercentage,
  unavailableReasonText,
} from '../../../lib/projectOverviewPresentation'
import { Card, cn } from '../../ui'

const icons: Record<OverviewMetricCardModel['key'], LucideIcon> = {
  security: Shield,
  reliability: Bug,
  maintainability: Wrench,
  securityHotspotsReviewed: Eye,
  coverage: Gauge,
  duplications: Copy,
}

export function OverviewMetricCard({ card, lensLabel }: { card: OverviewMetricCardModel; lensLabel: string }) {
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
        {!card.detailTarget && <p className="mt-auto text-xs text-subtlefg">Details not available yet</p>}
      </div>
    </Card>
  )
}
