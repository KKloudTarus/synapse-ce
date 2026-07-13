import type { RuleSummary, RuleFacets, RuleType, RuleQuality, RuleSeverity, RuleDetection } from './types'

export function formatRuleType(value: RuleType): string {
  switch (value) {
    case 'code_smell': return 'Code smell'
    case 'security_hotspot': return 'Security hotspot'
    case 'vulnerability': return 'Vulnerability'
    case 'bug': return 'Bug'
    default: return value || 'Unknown'
  }
}

export function formatRuleQuality(value: RuleQuality): string {
  switch (value) {
    case 'security': return 'Security'
    case 'reliability': return 'Reliability'
    case 'maintainability': return 'Maintainability'
    default: return value || 'Unknown'
  }
}

export function formatRuleSeverity(value: RuleSeverity): string {
  if (!value) return 'Unknown'
  return value.charAt(0).toUpperCase() + value.slice(1)
}

export function formatRuleDetection(value: RuleDetection): string {
  switch (value) {
    case 'ast': return 'AST'
    case 'pattern': return 'Pattern'
    case 'metric': return 'Metric'
    default: return value || 'Unknown'
  }
}

export function formatRemediationEffort(minutes: number): string {
  if (!minutes || minutes <= 0) return 'Not estimated'
  if (minutes < 60) return `${minutes} min`
  const h = Math.floor(minutes / 60)
  const m = minutes % 60
  if (m === 0) return `${h}h`
  return `${h}h ${m}m`
}

const TYPE_ORDER: Record<RuleType, number> = {
  vulnerability: 1,
  security_hotspot: 2,
  bug: 3,
  code_smell: 4,
}

const SEVERITY_ORDER: Record<RuleSeverity, number> = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
}

function parseCweNumber(cwe: string): number {
  const match = /^CWE-(\d+)$/i.exec(cwe)
  return match ? parseInt(match[1], 10) : Infinity
}

export function deriveRuleFacets(rules: RuleSummary[]): RuleFacets {
  const facets: RuleFacets = {
    languages: [],
    types: [],
    severities: [],
    tags: [],
    cwe: [],
  }

  const lMap = new Map<string, string>()
  const tSet = new Set<RuleType>()
  const sSet = new Set<RuleSeverity>()
  const tgMap = new Map<string, string>()
  const cSet = new Set<string>()

  for (const r of rules) {
    if (r.language?.trim()) {
      const v = r.language.trim()
      if (!lMap.has(v.toLowerCase())) lMap.set(v.toLowerCase(), v)
    }
    if (r.type) tSet.add(r.type)
    if (r.defaultSeverity) sSet.add(r.defaultSeverity)
    for (const tag of r.tags ?? []) {
      if (tag?.trim()) {
        const v = tag.trim()
        if (!tgMap.has(v.toLowerCase())) tgMap.set(v.toLowerCase(), v)
      }
    }
    for (const c of r.cwe ?? []) {
      if (c?.trim()) cSet.add(c.trim())
    }
  }

  facets.languages = Array.from(lMap.values()).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }))
  facets.tags = Array.from(tgMap.values()).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }))

  facets.types = Array.from(tSet).sort((a, b) => {
    const o1 = TYPE_ORDER[a] ?? 999
    const o2 = TYPE_ORDER[b] ?? 999
    if (o1 !== o2) return o1 - o2
    return a.localeCompare(b)
  })

  facets.severities = Array.from(sSet).sort((a, b) => {
    const o1 = SEVERITY_ORDER[a] ?? 999
    const o2 = SEVERITY_ORDER[b] ?? 999
    if (o1 !== o2) return o1 - o2
    return a.localeCompare(b)
  })

  facets.cwe = Array.from(cSet).sort((a, b) => {
    const n1 = parseCweNumber(a)
    const n2 = parseCweNumber(b)
    if (n1 !== n2) return n1 - n2
    return a.localeCompare(b, undefined, { sensitivity: 'base' })
  })

  return facets
}
