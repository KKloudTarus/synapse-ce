import { describe, it, expect } from 'vitest'
import {
  formatRuleType,
  formatRuleSeverity,
  formatRuleQuality,
  formatRuleDetection,
  formatRemediationEffort,
  deriveRuleFacets
} from './ruleFormat'
import type { RuleSummary } from './types'

describe('Formatters', () => {
  it('formats rule type', () => {
    expect(formatRuleType('code_smell')).toBe('Code smell')
    expect(formatRuleType('security_hotspot')).toBe('Security hotspot')
    expect(formatRuleType('vulnerability')).toBe('Vulnerability')
    expect(formatRuleType('bug')).toBe('Bug')
    expect(formatRuleType('unknown' as any)).toBe('unknown')
  })

  it('formats rule severity', () => {
    expect(formatRuleSeverity('critical')).toBe('Critical')
    expect(formatRuleSeverity('high')).toBe('High')
    expect(formatRuleSeverity('medium')).toBe('Medium')
    expect(formatRuleSeverity('low')).toBe('Low')
  })

  it('formats rule quality', () => {
    expect(formatRuleQuality('security')).toBe('Security')
    expect(formatRuleQuality('reliability')).toBe('Reliability')
    expect(formatRuleQuality('maintainability')).toBe('Maintainability')
  })

  it('formats rule detection', () => {
    expect(formatRuleDetection('ast')).toBe('AST')
    expect(formatRuleDetection('pattern')).toBe('Pattern')
    expect(formatRuleDetection('metric')).toBe('Metric')
  })

  it('formats remediation effort', () => {
    expect(formatRemediationEffort(0)).toBe('Not estimated')
    expect(formatRemediationEffort(1)).toBe('1 min')
    expect(formatRemediationEffort(30)).toBe('30 min')
    expect(formatRemediationEffort(60)).toBe('1h')
    expect(formatRemediationEffort(90)).toBe('1h 30m')
    expect(formatRemediationEffort(120)).toBe('2h')
  })
})

describe('deriveRuleFacets', () => {
  it('derives facets properly from rules', () => {
    const rules: RuleSummary[] = [
      {
        key: '1', name: '', description: '',
        language: 'go', type: 'bug', defaultSeverity: 'high', tags: ['b', 'a'], cwe: ['CWE-79', 'CWE-89'],
        qualities: [], owasp: [], remediationEffort: 0, detection: 'ast'
      },
      {
        key: '2', name: '', description: '',
        language: 'python', type: 'vulnerability', defaultSeverity: 'critical', tags: ['a'], cwe: ['CWE-22'],
        qualities: [], owasp: [], remediationEffort: 0, detection: 'pattern'
      },
      {
        key: '3', name: '', description: '',
        language: 'Go', type: 'bug', defaultSeverity: 'high', tags: ['c'], cwe: ['CWE-89'],
        qualities: [], owasp: [], remediationEffort: 0, detection: 'pattern'
      }
    ]

    const facets = deriveRuleFacets(rules)

    expect(facets.languages).toEqual(['go', 'python'])
    expect(facets.types).toEqual(['vulnerability', 'bug'])
    expect(facets.severities).toEqual(['critical', 'high'])
    expect(facets.tags).toEqual(['a', 'b', 'c'])
    expect(facets.cwe).toEqual(['CWE-22', 'CWE-79', 'CWE-89'])
  })

  it('does not mutate input array', () => {
    const rules: RuleSummary[] = []
    deriveRuleFacets(rules)
    expect(rules).toEqual([])
  })

  it('handles empty values', () => {
    const rules: Partial<RuleSummary>[] = [
      { language: ' ', type: undefined, defaultSeverity: undefined, tags: [' ', 'valid'] }
    ]
    const facets = deriveRuleFacets(rules as any)
    expect(facets.languages).toEqual([])
    expect(facets.tags).toEqual(['valid'])
  })
})
