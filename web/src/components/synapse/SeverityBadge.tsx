import type { FC } from 'react'
import { Badge, BadgeWithDot } from '../base/badges/badges'
import type { BadgeColors } from '../base/badges/badge-types'

export interface SeverityBadgeProps {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  size?: 'sm' | 'md'
  showIcon?: boolean
  className?: string
}

const SEVERITY_COLORS: Record<SeverityBadgeProps['severity'], BadgeColors> = {
  critical: 'error',
  high: 'warning',
  medium: 'gray',
  low: 'success',
  info: 'gray',
}

const SEVERITY_LABELS: Record<SeverityBadgeProps['severity'], string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

export const SeverityBadge: FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showIcon = true,
  className,
}) => {
  const color = SEVERITY_COLORS[severity] ?? 'gray'
  const label = SEVERITY_LABELS[severity] ?? (severity ? severity.charAt(0).toUpperCase() + severity.slice(1) : '')

  if (showIcon) {
    return (
      <BadgeWithDot size={size} color={color} type="pill-color" className={className}>
        {label}
      </BadgeWithDot>
    )
  }

  return (
    <Badge size={size} color={color} type="pill-color" className={className}>
      {label}
    </Badge>
  )
}
