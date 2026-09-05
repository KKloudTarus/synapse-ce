import type { Severity, Verdict } from './types'

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

const RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 }
export const sevRank = (s: Severity): number => RANK[s] ?? 0

/**
 * Text colour per severity. These are the `*text` token pair, not the solid fill
 * token: the fills are tuned for dots and bars and fall under WCAG AA as 12px
 * text on a light surface.
 */
export const sevText: Record<Severity, string> = {
  critical: 'text-criticaltext',
  high: 'text-hightext',
  medium: 'text-mediumtext',
  low: 'text-lowtext',
  info: 'text-infosevtext',
  unknown: 'text-infosevtext',
}

/** Solid background (dots, bars). */
export const sevBg: Record<Severity, string> = {
  critical: 'bg-critical',
  high: 'bg-high',
  medium: 'bg-medium',
  low: 'bg-low',
  info: 'bg-infosev',
  unknown: 'bg-infosev',
}

/** Bar fill: a horizontal gradient of the severity color + a faint outer glow. */
export const sevFill: Record<Severity, string> = {
  critical: 'bg-gradient-to-r from-critical to-critical/70 shadow-[0_0_8px_-1px] shadow-critical/50',
  high: 'bg-gradient-to-r from-high to-high/70 shadow-[0_0_8px_-1px] shadow-high/50',
  medium: 'bg-gradient-to-r from-medium to-medium/70 shadow-[0_0_8px_-1px] shadow-medium/50',
  low: 'bg-gradient-to-r from-low to-low/70 shadow-[0_0_8px_-1px] shadow-low/50',
  info: 'bg-gradient-to-r from-infosev to-infosev/70',
  unknown: 'bg-gradient-to-r from-infosev to-infosev/70',
}

/** Soft, ringed badge style per severity. */
export const sevSoft: Record<Severity, string> = {
  critical: 'bg-critical/10 text-criticaltext ring-critical/25',
  high: 'bg-high/10 text-hightext ring-high/25',
  medium: 'bg-medium/10 text-mediumtext ring-medium/25',
  low: 'bg-low/10 text-lowtext ring-low/25',
  info: 'bg-infosev/15 text-infosevtext ring-infosev/25',
  unknown: 'bg-infosev/15 text-infosevtext ring-infosev/25',
}

export const VERDICT_STYLE: Record<Verdict, { label: string; soft: string; dot: string }> = {
  allow: { label: 'Allow', soft: 'bg-accent/10 text-accent ring-accent/25', dot: 'bg-accent' },
  warn: { label: 'Warn', soft: 'bg-medium/10 text-medium ring-medium/25', dot: 'bg-medium' },
  deny: { label: 'Deny', soft: 'bg-high/10 text-high ring-high/25', dot: 'bg-high' },
}

export const CATEGORY_LABEL: Record<string, string> = {
  permissive: 'Permissive',
  'weak-copyleft': 'Weak copyleft',
  copyleft: 'Copyleft',
  proprietary: 'Proprietary',
  unknown: 'Unknown',
}

/** Sort a severity-bearing list highest-first, stable on a secondary key. */
export function bySeverityDesc<T>(get: (x: T) => Severity): (a: T, b: T) => number {
  return (a, b) => sevRank(get(b)) - sevRank(get(a))
}
