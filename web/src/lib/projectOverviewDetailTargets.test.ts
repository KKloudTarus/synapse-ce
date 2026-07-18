import { describe, expect, it } from 'vitest'
import type { MetricAvailability, ProjectOverviewLens, UnavailableReason } from './projectOverview'
import { overviewDetailTarget } from './projectOverviewDetailTargets'
import { metricCardsForLens, type OverviewMetricCardModel } from './projectOverviewPresentation'

describe('overviewDetailTarget', () => {
  const cards = metricCardsForLens(availableLens())

  it('maps every truthful Overall Code destination', () => {
    const expected = {
      security: 'security',
      reliability: 'reliability',
      maintainability: 'maintainability',
      securityHotspotsReviewed: null,
      coverage: 'coverage',
      duplications: 'duplications',
    } as const

    for (const card of cards) {
      const target = overviewDetailTarget('synapse', 'overall', card)
      expect(target?.focus ?? null).toBe(expected[card.key])
      if (target) {
        expect(target.lens).toBe('overall')
        expect(target.to).toBe(`/code-quality/projects/synapse/analysis?focus=${target.focus}&lens=overall`)
        expect(target.label).toBe(`View ${card.label} details`)
      }
    }
  })

  it('maps only truthful New Code rating destinations', () => {
    const expected = new Set(['security', 'reliability', 'maintainability'])
    for (const card of cards) {
      const target = overviewDetailTarget('synapse', 'new-code', card)
      expect(target !== null).toBe(expected.has(card.key))
      if (target) {
        expect(target.focus).toBe(card.key)
        expect(target.lens).toBe('new-code')
      }
    }
  })

  it.each(['unavailable', 'not_supplied', 'not_applicable'] as const)(
    'returns no target for any %s metric',
    (availability) => {
      for (const card of cards) {
        expect(overviewDetailTarget('synapse', 'overall', withAvailability(card, availability))).toBeNull()
        expect(overviewDetailTarget('synapse', 'new-code', withAvailability(card, availability))).toBeNull()
      }
    },
  )

  it('returns no target when an available metric has no typed value', () => {
    const security = cards.find((card) => card.key === 'security')
    const coverage = cards.find((card) => card.key === 'coverage')
    if (!security || security.kind !== 'rating') throw new Error('Security rating fixture is missing')
    if (!coverage || coverage.kind !== 'percentage') throw new Error('Coverage percentage fixture is missing')

    expect(overviewDetailTarget('synapse', 'overall', {
      ...security,
      metric: { availability: 'available', grade: null, unavailableReason: null },
    })).toBeNull()
    expect(overviewDetailTarget('synapse', 'overall', {
      ...coverage,
      metric: { availability: 'available', value: null, unavailableReason: null },
    })).toBeNull()
  })

  it('keeps Hotspots and New Code measures non-interactive even if unexpectedly available', () => {
    const byKey = Object.fromEntries(cards.map((card) => [card.key, card])) as Record<OverviewMetricCardModel['key'], OverviewMetricCardModel>
    expect(overviewDetailTarget('synapse', 'overall', byKey.securityHotspotsReviewed)).toBeNull()
    expect(overviewDetailTarget('synapse', 'new-code', byKey.coverage)).toBeNull()
    expect(overviewDetailTarget('synapse', 'new-code', byKey.duplications)).toBeNull()
  })

  it('URL-encodes Project keys and is deterministic', () => {
    const security = cards[0]
    const first = overviewDetailTarget('team/demo project/đ', 'overall', security)
    const second = overviewDetailTarget('team/demo project/đ', 'overall', security)
    expect(first).toEqual(second)
    expect(first?.to).toBe('/code-quality/projects/team%2Fdemo%20project%2F%C4%91/analysis?focus=security&lens=overall')
  })
})

function availableLens(): ProjectOverviewLens {
  return {
    security: { availability: 'available', grade: 'A', unavailableReason: null },
    reliability: { availability: 'available', grade: 'B', unavailableReason: null },
    maintainability: { availability: 'available', grade: 'C', unavailableReason: null },
    securityHotspotsReviewed: { availability: 'available', value: 95, unavailableReason: null },
    coverage: { availability: 'available', value: 72.34, unavailableReason: null },
    duplications: { availability: 'available', value: 4.2, unavailableReason: null },
  }
}

function withAvailability(
  card: OverviewMetricCardModel,
  availability: Exclude<MetricAvailability, 'available'>,
): OverviewMetricCardModel {
  const unavailableReason: UnavailableReason = 'changed_line_metrics_not_available'
  return card.kind === 'rating'
    ? { ...card, metric: { availability, grade: null, unavailableReason } }
    : { ...card, metric: { availability, value: null, unavailableReason } }
}
