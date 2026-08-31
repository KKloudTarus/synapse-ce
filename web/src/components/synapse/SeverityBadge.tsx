import type { FC } from 'react'
import { Badge, BadgeWithDot } from '../base/badges/badges'
import type { BadgeColors } from '../base/badges/badge-types'

export interface SeverityBadgeProps {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  size?: 'sm' | 'md'
  showIcon?: boolean
  className?: string
}

// Prominence must decrease monotonically: critical > high > medium > low > info.
// Green on `low` would read as "safe" and outrank `medium`, so `low` uses blue — a distinct,
// lower-urgency hue (cooler than amber) that is neither green nor a dull monochrome grey. `info`
// (the truly lowest, purely informational) stays neutral grey.
const SEVERITY_COLORS: Record<SeverityBadgeProps['severity'], BadgeColors> = {
  critical: 'error',
  high: 'orange',
  medium: 'warning',
  low: 'blue',
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
