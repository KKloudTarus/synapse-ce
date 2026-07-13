import { describe, it, expect } from 'vitest'
import { parseRuleFilters, serializeRuleFilters, hasActiveRuleFilters } from './ruleFilters'

describe('parseRuleFilters', () => {
  it('handles empty URL', () => {
    const params = new URLSearchParams()
    const filters = parseRuleFilters(params)
    expect(filters.query).toBe('')
    expect(filters.languages).toEqual([])
  })

  it('parses query only', () => {
    const params = new URLSearchParams('q=test')
    const filters = parseRuleFilters(params)
    expect(filters.query).toBe('test')
  })

  it('parses repeated filters', () => {
    const params = new URLSearchParams('language=go&language=python&type=bug&type=vulnerability')
    const filters = parseRuleFilters(params)
    expect(filters.languages).toEqual(['go', 'python'])
    expect(filters.types).toEqual(['bug', 'vulnerability'])
  })

  it('removes duplicate values case-insensitively with first casing wins', () => {
    const params = new URLSearchParams('language=Go&language=go&language=GO')
    const filters = parseRuleFilters(params)
    expect(filters.languages).toEqual(['Go'])
  })

  it('ignores invalid type and severity', () => {
    const params = new URLSearchParams('type=invalid&severity=super_high&severity=high')
    const filters = parseRuleFilters(params)
    expect(filters.types).toEqual([])
    expect(filters.severities).toEqual(['high'])
  })

  it('canonicalizes type and severity', () => {
    const params = new URLSearchParams()
    params.append('type', 'VULNERABILITY')
    params.append('type', 'BuG')
    params.append('severity', 'HIGH')

    const filters = parseRuleFilters(params)
    expect(filters.types).toEqual(['vulnerability', 'bug'])
    expect(filters.severities).toEqual(['high'])
  })

  it('canonicalizes CWE forms', () => {
    const params = new URLSearchParams()
    params.append('cwe', '89')
    params.append('cwe', 'cwe-79')
    params.append('cwe', 'CWE-20')
    params.append('cwe', 'invalid')

    const filters = parseRuleFilters(params)
    expect(filters.cwe).toEqual(['CWE-89', 'CWE-79', 'CWE-20'])
  })

  it('removes empty values', () => {
    const params = new URLSearchParams('language=  &language=&type=bug')
    const filters = parseRuleFilters(params)
    expect(filters.languages).toEqual([])
    expect(filters.types).toEqual(['bug'])
  })

  it('enforces 256 char limit on query', () => {
    const long = 'a'.repeat(300)
    const params = new URLSearchParams(`q=${long}`)
    const filters = parseRuleFilters(params)
    expect(filters.query.length).toBe(256)
  })

  it('enforces 128 char limit on filter values', () => {
    const long = 'b'.repeat(150)
    const params = new URLSearchParams(`language=${long}`)
    const filters = parseRuleFilters(params)
    expect(filters.languages[0].length).toBe(128)
  })

  it('enforces 32 items per dimension boundary', () => {
    const params = new URLSearchParams()
    for (let i = 0; i < 40; i++) params.append('tag', `tag${i}`)
    const filters = parseRuleFilters(params)
    expect(filters.tags.length).toBe(32)
  })

  it('enforces 64 total facets boundary', () => {
    const params = new URLSearchParams()
    for (let i = 0; i < 40; i++) params.append('tag', `tag${i}`)
    for (let i = 0; i < 40; i++) params.append('cwe', `CWE-${i}`)
    const filters = parseRuleFilters(params)
    expect(filters.tags.length + filters.cwe.length).toBe(64)
  })
})

describe('serializeRuleFilters', () => {
  it('serializes deterministically', () => {
    const filters: any = {
      query: 'inj',
      languages: ['python', 'Go'],
      types: [],
      severities: ['high'],
      tags: [],
      cwe: [],
    }
    const params = serializeRuleFilters(filters)
    expect(params.toString()).toBe('q=inj&language=Go&language=python&severity=high')
  })

  it('serializes canonical forms', () => {
    const filters: any = {
      query: '',
      languages: [],
      types: ['VULNERABILITY', 'invalid'],
      severities: ['HIGH'],
      tags: [],
      cwe: ['89', 'cwe-79'],
    }
    const params = serializeRuleFilters(filters)
    expect(params.getAll('type')).toEqual(['vulnerability'])
    expect(params.getAll('severity')).toEqual(['high'])
    expect(params.getAll('cwe')).toEqual(['CWE-79', 'CWE-89']) // sorted
  })

  it('deduplicates and sorts values', () => {
    const filters = {
      query: '',
      languages: ['b', 'A', 'a', 'C'],
      types: [],
      severities: [],
      tags: [],
      cwe: [],
    }
    const params = serializeRuleFilters(filters as any)
    expect(params.toString()).toBe('language=A&language=b&language=C')
  })

  it('parse -> serialize -> parse stability', () => {
    const initial = new URLSearchParams('severity=high&language=python&language=go&q=test&tag=Security')
    const parsed = parseRuleFilters(initial)
    const serialized = serializeRuleFilters(parsed)
    const reparsed = parseRuleFilters(serialized)
    parsed.languages.sort()
    reparsed.languages.sort()
    expect(reparsed).toEqual(parsed)
  })
})

describe('hasActiveRuleFilters', () => {
  it('returns false for empty filters', () => {
    expect(hasActiveRuleFilters({ query: '', languages: [], types: [], severities: [], tags: [], cwe: [] } as any)).toBe(false)
  })

  it('returns true if any filter is active', () => {
    expect(hasActiveRuleFilters({ query: 'a' } as any)).toBe(true)
    expect(hasActiveRuleFilters({ languages: ['go'] } as any)).toBe(true)
  })
})
