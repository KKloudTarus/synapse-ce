import type { FC } from 'react'
import { Metric, type MetricTone } from '@/components/synapse/Metric'
import type { StatCardProps } from '../types'

// A dashboard figure. The icon prop stays in the type for callers, but a decorative icon box adds
// nothing an operator reads, so it is not rendered.
export const StatCard: FC<StatCardProps> = ({ label, value, hint, tone = 'muted', className }) => (
  <Metric label={label} value={value} hint={hint} tone={tone as MetricTone} className={className} />
)
