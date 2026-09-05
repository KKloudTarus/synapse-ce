import type { FC, ElementType } from 'react'
import { Metric, type MetricTone } from '@/components/synapse/Metric'

export interface EngagementStatCardProps {
  label: string
  value: number | string
  icon: ElementType
  tone?: 'default' | 'info' | 'accent' | 'brand' | 'warning' | 'high'
}

const TONE: Record<NonNullable<EngagementStatCardProps['tone']>, MetricTone> = {
  default: 'muted', info: 'info', accent: 'accent', brand: 'brand', warning: 'warning', high: 'critical',
}

// A figure in the engagements strip. The icon prop is kept for callers and not rendered.
export const EngagementStatCard: FC<EngagementStatCardProps> = ({ label, value, tone = 'default' }) => (
  <Metric label={label} value={value} tone={TONE[tone]} />
)
