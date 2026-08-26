import type {
  RuleDetail,
  RuleListFilters,
  RuleQuality,
  RuleSeverity,
  RuleSummary,
  RuleType,
  RuleDetection,
} from '../types'
import { req } from './client'

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map((v) => asString(v)) : []
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' ? value : fallback
}

function asRuleType(value: unknown): RuleType {
  const s = asString(value)
  return ['bug', 'vulnerability', 'code_smell', 'security_hotspot'].includes(s) ? (s as RuleType) : 'code_smell'
}

function asRuleQualityArray(value: unknown): RuleQuality[] {
  const arr = asStringArray(value)
  return arr.filter((s) => ['security', 'reliability', 'maintainability'].includes(s)) as RuleQuality[]
}

function asRuleSeverity(value: unknown): RuleSeverity {
  const s = asString(value)
  return ['low', 'medium', 'high', 'critical'].includes(s) ? (s as RuleSeverity) : 'medium'
}

function asRuleDetection(value: unknown): RuleDetection {
  const s = asString(value)
  return s === 'ast' || s === 'pattern' || s === 'metric' ? s : 'pattern'
}

function mapRuleSummary(raw: any): RuleSummary {
  return {
    key: asString(raw?.key),
    name: asString(raw?.name),
    language: asString(raw?.language),
    type: asRuleType(raw?.type),
    qualities: asRuleQualityArray(raw?.qualities),
    defaultSeverity: asRuleSeverity(raw?.default_severity),
    tags: asStringArray(raw?.tags),
    cwe: asStringArray(raw?.cwe),
    owasp: asStringArray(raw?.owasp),
    description: asString(raw?.description),
    remediationEffort: asNumber(raw?.remediation_effort),
    detection: asRuleDetection(raw?.detection),
  }
}

function mapRuleDetail(raw: any): RuleDetail {
  return {
    ...mapRuleSummary(raw),
    rationale: asString(raw?.rationale),
    remediation: asString(raw?.remediation),
    compliantExample: asString(raw?.compliant_example),
    noncompliantExample: asString(raw?.noncompliant_example),
  }
}

export const rulesApi = {
  listRules: async (filters: Partial<RuleListFilters> = {}): Promise<RuleSummary[]> => {
    const q = new URLSearchParams()
    if (filters.query?.trim()) q.set('q', filters.query.trim())
    for (const value of filters.languages ?? []) q.append('language', value)
    for (const value of filters.types ?? []) q.append('type', value)
    for (const value of filters.severities ?? []) q.append('severity', value)
    for (const value of filters.tags ?? []) q.append('tag', value)
    for (const value of filters.cwe ?? []) q.append('cwe', value)
    const qs = q.toString()
    const res = await req(`/rules${qs ? `?${qs}` : ''}`)
    return Array.isArray(res) ? res.map(mapRuleSummary) : []
  },

  getRule: async (key: string): Promise<RuleDetail> => {
    return mapRuleDetail(await req(`/rules/${encodeURIComponent(key)}`))
  },
}
