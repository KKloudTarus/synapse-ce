import { ShieldTick, Tool01, Virus } from '@untitledui/icons'
import type { IssueStatus, ProjectIssue, RuleType, Severity } from '../../../lib/types'

export const DEFAULT_FILE_LIMIT = 5

export function typeMeta(t: RuleType) {
  switch (t) {
    case 'vulnerability':
      return {
        label: 'Security',
        icon: ShieldTick,
        tone: 'text-error-primary',
        badge: 'bg-error-primary/10 text-error-primary border-error-primary/25',
      }
    case 'bug':
      return {
        label: 'Reliability',
        icon: Virus,
        tone: 'text-warning-primary',
        badge: 'bg-warning-primary/10 text-warning-primary border-warning-primary/25',
      }
    case 'code_smell':
    default:
      return {
        label: 'Maintainability',
        icon: Tool01,
        tone: 'text-utility-blue-600 dark:text-utility-blue-400',
        badge: 'bg-utility-blue-50 text-utility-blue-700 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 border-utility-blue-200',
      }
  }
}

export function severityBadge(sev: Severity | 'blocker' | 'major' | 'minor') {
  switch (sev) {
    case 'blocker':
    case 'critical':
      return 'bg-error-primary/10 text-error-primary border-error-primary/25'
    case 'high':
    case 'major':
      return 'bg-utility-orange-50 text-utility-orange-700 dark:bg-utility-orange-950/40 dark:text-utility-orange-300 border-utility-orange-200'
    case 'medium':
      return 'bg-warning-primary/10 text-warning-primary border-warning-primary/25'
    case 'low':
    case 'minor':
    case 'info':
    default:
      return 'bg-secondary text-secondary border-secondary'
  }
}

export function statusBadge(st: IssueStatus) {
  switch (st) {
    case 'open':
      return 'bg-warning-primary/10 text-warning-primary border-warning-primary/25'
    case 'accepted':
      return 'bg-utility-blue-50 text-utility-blue-700 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 border-utility-blue-200'
    case 'false_positive':
      return 'bg-success-primary/10 text-success-primary border-success-primary/25'
    case 'wont_fix':
      return 'bg-secondary text-tertiary border-secondary'
    default:
      return 'bg-secondary text-secondary border-secondary'
  }
}

export function cleanIssueTitle(title: string): string {
  if (!title) return ''
  return title.replace(/\s*\([^)]+:\d+\)$/, '')
}

export function extractLine(location: string): string | null {
  const match = /:(\d+)$/.exec(location)
  return match ? match[1] : null
}

export function groupIssuesByFile(issues: ProjectIssue[]) {
  const groups: Record<string, ProjectIssue[]> = {}
  for (const it of issues) {
    const file = it.file || it.location.split(':')[0] || 'General'
    if (!groups[file]) groups[file] = []
    groups[file].push(it)
  }
  return groups
}
