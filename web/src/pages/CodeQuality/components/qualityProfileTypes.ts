import type { Severity } from '../../../lib/types'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']
export const RULE_RENDER_CAP = 100

export type TypeFilter = 'all' | 'builtin' | 'custom'
export type RuleFilter = 'all' | 'active' | 'inactive'
