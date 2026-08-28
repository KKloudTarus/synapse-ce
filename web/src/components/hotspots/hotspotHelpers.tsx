import {
  AlertTriangle,
  CheckCircle as CheckCircle2,
  Shield01 as Shield,
  ShieldTick as ShieldCheck,
  ShieldZap as ShieldAlert,
} from '@untitledui/icons'
import { cn } from '../ui'
import type { HotspotStatus, Severity } from '../../lib/types'

export function StatusIcon({ status, className }: { status: HotspotStatus; className?: string }) {
  switch (status) {
    case 'to_review': return <ShieldAlert className={cn('text-warning-primary', className)} />
    case 'acknowledged': return <AlertTriangle className={cn('text-utility-blue-600 dark:text-utility-blue-400', className)} />
    case 'fixed': return <CheckCircle2 className={cn('text-utility-purple-600 dark:text-utility-purple-400', className)} />
    case 'safe': return <ShieldCheck className={cn('text-success-primary', className)} />
    default: return <Shield className={className} />
  }
}

export function formatHotspotStatus(status: HotspotStatus) {
  switch (status) {
    case 'to_review': return 'To review'
    case 'acknowledged': return 'Acknowledged'
    case 'fixed': return 'Fixed'
    case 'safe': return 'Safe'
    default: return status
  }
}

export function statusBadgeStyle(status: HotspotStatus) {
  switch (status) {
    case 'to_review':
      return 'bg-warning-primary/10 text-warning-primary border-warning-primary/25'
    case 'acknowledged':
      return 'bg-utility-blue-50 text-utility-blue-700 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 border-utility-blue-200'
    case 'fixed':
      return 'bg-utility-purple-50 text-utility-purple-700 dark:bg-utility-purple-950/40 dark:text-utility-purple-300 border-utility-purple-200'
    case 'safe':
      return 'bg-success-primary/10 text-success-primary border-success-primary/25'
    default:
      return 'bg-secondary text-secondary border-secondary'
  }
}

export function severityBadgeStyle(severity: Severity | 'blocker' | 'major' | 'minor') {
  switch (severity) {
    case 'blocker':
    case 'critical':
      return 'bg-error-primary/10 text-error-primary border-error-primary/25'
    case 'major':
    case 'high':
      return 'bg-utility-orange-50 text-utility-orange-700 dark:bg-utility-orange-950/40 dark:text-utility-orange-300 border-utility-orange-200'
    case 'medium':
      return 'bg-warning-primary/10 text-warning-primary border-warning-primary/25'
    case 'low':
    case 'minor':
    case 'info':
      return 'bg-secondary text-secondary border-secondary'
    default:
      return 'bg-secondary text-secondary border-secondary'
  }
}

export function parseDescription(desc: string) {
  if (!desc) return []
  const lines = desc.split('\n').filter((l) => l.trim().length > 0)
  const items: Array<{ key: string; text: string }> = []
  for (const line of lines) {
    const trimmed = line.trim().replace(/^[-*]\s*/, '')
    const match = trimmed.match(/^([^:]+):\s*(.*)$/)
    if (match) {
      items.push({ key: match[1].trim(), text: match[2].trim() })
    } else {
      items.push({ key: '', text: trimmed })
    }
  }
  return items
}
