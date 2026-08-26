import { Award01, FileCode01, Percent01, ShieldZap } from '@untitledui/icons'
import type { QualityGateCondition } from '../../../lib/types'

export const metrics = [
  'new_critical',
  'new_high',
  'new_medium',
  'new_secret',
  'new_vulnerability',
  'new_issues',
  'total_critical',
  'coverage',
  'new_coverage',
  'duplication_density',
  'new_duplication',
  'security_rating',
  'reliability_rating',
  'maintainability_rating',
  'security_hotspots_reviewed',
  'new_security_hotspots_reviewed',
]

export const operators: QualityGateCondition['op'][] = ['<=', '>=', '==', '<', '>']

export const blankCondition = (metric = 'new_high'): QualityGateCondition => ({ metric, op: '<=', threshold: 0 })

export type MetricCategory = 'security' | 'rating' | 'coverage' | 'duplication'
export type TypeFilter = 'all' | 'builtin' | 'custom'
export type SortOption = 'name-asc' | 'name-desc' | 'conditions-desc' | 'conditions-asc'

export function getMetricCategory(metric: string): MetricCategory {
  if (['new_critical', 'new_high', 'new_medium', 'new_secret', 'new_vulnerability', 'total_critical'].includes(metric)) {
    return 'security'
  }
  if (
    [
      'security_rating',
      'reliability_rating',
      'maintainability_rating',
      'security_hotspots_reviewed',
      'new_security_hotspots_reviewed',
    ].includes(metric)
  ) {
    return 'rating'
  }
  if (['coverage', 'new_coverage'].includes(metric)) {
    return 'coverage'
  }
  return 'duplication'
}

export function getMetricCategoryStyle(category: MetricCategory) {
  switch (category) {
    case 'security':
      return {
        cardBg: 'border-utility-pink-200 bg-utility-pink-50 dark:border-utility-pink-800 dark:bg-utility-pink-950',
        icon: ShieldZap,
        iconBg: 'bg-utility-pink-100 text-utility-pink-700 dark:bg-utility-pink-900 dark:text-utility-pink-300',
      }
    case 'rating':
      return {
        cardBg: 'border-utility-orange-200 bg-utility-orange-50 dark:border-utility-orange-800 dark:bg-utility-orange-950',
        icon: Award01,
        iconBg: 'bg-utility-orange-100 text-utility-orange-700 dark:bg-utility-orange-900 dark:text-utility-orange-300',
      }
    case 'coverage':
      return {
        cardBg: 'border-utility-green-200 bg-utility-green-50 dark:border-utility-green-800 dark:bg-utility-green-950',
        icon: Percent01,
        iconBg: 'bg-utility-green-100 text-utility-green-700 dark:bg-utility-green-900 dark:text-utility-green-300',
      }
    case 'duplication':
    default:
      return {
        cardBg: 'border-utility-blue-200 bg-utility-blue-50 dark:border-utility-blue-800 dark:bg-utility-blue-950',
        icon: FileCode01,
        iconBg: 'bg-utility-blue-100 text-utility-blue-700 dark:bg-utility-blue-900 dark:text-utility-blue-300',
      }
  }
}
