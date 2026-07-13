import type { RuleListFilters, RuleType, RuleSeverity } from './types'

const KNOWN_TYPES = new Set<RuleType>(['bug', 'vulnerability', 'code_smell', 'security_hotspot'])
const KNOWN_SEVERITIES = new Set<RuleSeverity>(['low', 'medium', 'high', 'critical'])

const MAX_QUERY_LEN = 256
const MAX_FILTER_LEN = 128
const MAX_PER_DIMENSION = 32
const MAX_TOTAL_FACETS = 64

function safeTrimLimit(v: string, limit: number): string {
  const t = v.trim()
  return Array.from(t).slice(0, limit).join('')
}

export function parseRuleFilters(params: URLSearchParams): RuleListFilters {
  const filters: RuleListFilters = {
    query: '',
    languages: [],
    types: [],
    severities: [],
    tags: [],
    cwe: [],
  }

  let facetCount = 0

  const q = params.get('q')
  if (q && q.trim()) {
    filters.query = safeTrimLimit(q, MAX_QUERY_LEN)
  }

  const parseDimension = <T extends string>(
    key: string,
    target: T[],
    canonicalize: (val: string) => string | null = (v) => v,
  ) => {
    const values = params.getAll(key)
    const seen = new Set<string>()

    for (const val of values) {
      if (facetCount >= MAX_TOTAL_FACETS) break
      if (target.length >= MAX_PER_DIMENSION) break

      const trimmed = safeTrimLimit(val, MAX_FILTER_LEN)
      if (!trimmed) continue

      const canonical = canonicalize(trimmed)
      if (!canonical) continue

      const lower = canonical.toLowerCase()
      if (seen.has(lower)) continue

      seen.add(lower)
      target.push(canonical as T)
      facetCount++
    }
  }

  parseDimension('language', filters.languages)
  parseDimension('type', filters.types, (v) => {
    const lower = v.toLowerCase()
    return KNOWN_TYPES.has(lower as RuleType) ? lower : null
  })
  parseDimension('severity', filters.severities, (v) => {
    const lower = v.toLowerCase()
    return KNOWN_SEVERITIES.has(lower as RuleSeverity) ? lower : null
  })
  parseDimension('tag', filters.tags)
  parseDimension('cwe', filters.cwe, (v) => {
    // 89, cwe-89, CWE-89 -> CWE-89
    const match = v.match(/^(?:cwe-)?(\d+)$/i)
    if (!match) return null
    return `CWE-${match[1]}`
  })

  return filters
}

export function serializeRuleFilters(filters: RuleListFilters): URLSearchParams {
  const p = new URLSearchParams()
  if (filters.query?.trim()) {
    p.set('q', filters.query.trim())
  }

  const appendUnique = (key: string, values: string[], canonicalize: (val: string) => string | null = (v) => v) => {
    if (!values) return
    const seen = new Set<string>()
    const sorted = [...values]
      .map(v => v.trim())
      .map(v => canonicalize(v))
      .filter((v): v is string => Boolean(v))
      .filter((v) => {
        const lower = v.toLowerCase()
        if (seen.has(lower)) return false
        seen.add(lower)
        return true
      })
      .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }))

    for (const val of sorted) {
      p.append(key, val)
    }
  }

  appendUnique('language', filters.languages)
  appendUnique('type', filters.types, (v) => {
    const lower = v.toLowerCase()
    return KNOWN_TYPES.has(lower as RuleType) ? lower : null
  })
  appendUnique('severity', filters.severities, (v) => {
    const lower = v.toLowerCase()
    return KNOWN_SEVERITIES.has(lower as RuleSeverity) ? lower : null
  })
  appendUnique('tag', filters.tags)
  appendUnique('cwe', filters.cwe, (v) => {
    const match = v.match(/^(?:cwe-)?(\d+)$/i)
    if (!match) return null
    return `CWE-${match[1]}`
  })

  return p
}

export function hasActiveRuleFilters(filters: RuleListFilters): boolean {
  if (filters.query?.trim()) return true
  if (filters.languages?.length) return true
  if (filters.types?.length) return true
  if (filters.severities?.length) return true
  if (filters.tags?.length) return true
  if (filters.cwe?.length) return true
  return false
}
