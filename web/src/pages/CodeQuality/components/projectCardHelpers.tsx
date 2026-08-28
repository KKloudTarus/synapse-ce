import { cn } from '../../../components/ui'
import type { Grade, Project } from '../../../lib/types'

export type Health = 'all' | 'failing' | 'passing' | 'analyzing' | 'failed' | 'unanalyzed'
export type SortOption = 'recent' | 'name' | 'issues' | 'failed'

export function formatLang(key: string): string {
  const map: Record<string, string> = {
    go: 'Go',
    golang: 'Go',
    ts: 'TypeScript',
    typescript: 'TypeScript',
    js: 'JavaScript',
    javascript: 'JavaScript',
    python: 'Python',
    py: 'Python',
    java: 'Java',
    csharp: 'C#',
    cs: 'C#',
    cpp: 'C++',
    rust: 'Rust',
    rs: 'Rust',
    php: 'PHP',
    ruby: 'Ruby',
    rb: 'Ruby',
    swift: 'Swift',
    kotlin: 'Kotlin',
    kt: 'Kotlin',
    terraform: 'Terraform',
    yaml: 'YAML',
    dockerfile: 'Docker',
  }
  return map[key.toLowerCase()] || key.charAt(0).toUpperCase() + key.slice(1)
}

export function projectHealth(project: Project): Exclude<Health, 'all'> {
  if (project.latestJob?.status === 'running') return 'analyzing'
  if (project.latestJob?.status === 'failed') return 'failed'
  if (!project.latestAnalysis) return 'unanalyzed'
  return project.latestAnalysis.gate.passed ? 'passing' : 'failing'
}

export function gradeStyle(grade: Grade) {
  switch (grade) {
    case 'A':
      return 'bg-success-primary/15 text-success-primary ring-success-primary/30 border border-success-primary/20'
    case 'B':
      return 'bg-utility-blue-50 text-utility-blue-700 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 ring-utility-blue-200 dark:ring-utility-blue-800'
    case 'C':
      return 'bg-warning-primary/15 text-warning-primary ring-warning-primary/30 border border-warning-primary/20'
    case 'D':
      return 'bg-utility-orange-50 text-utility-orange-700 dark:bg-utility-orange-950/40 dark:text-utility-orange-300 ring-utility-orange-200 dark:ring-utility-orange-800'
    case 'E':
      return 'bg-error-primary/15 text-error-primary ring-error-primary/30 border border-error-primary/20'
    default:
      return 'bg-secondary text-tertiary ring-secondary'
  }
}

export function formatDate(value: string) {
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export function slugify(value: string): string {
  return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
}

export function StatPill({ count, label, tone }: { count: number; label: string; tone: 'critical' | 'low' | 'brand' | 'muted' }) {
  const colors = {
    critical: 'text-critical',
    low: 'text-low',
    brand: 'text-brand-secondary',
    muted: 'text-tertiary',
  }
  return (
    <span className="flex items-center gap-2 text-sm">
      <span className={cn('font-mono text-lg font-bold tabular-nums', colors[tone])}>{count}</span>
      <span className="font-medium text-secondary">{label}</span>
    </span>
  )
}
