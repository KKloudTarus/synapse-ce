import { act, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { DashboardTrendPoint } from '../../lib/types'
import { FindingsTrendChart, niceStep } from './DashboardCharts'

const series = [
  { key: 'critical', label: 'Critical', value: 0, color: 'red' },
  { key: 'high', label: 'High', value: 0, color: 'orange' },
]

const points: DashboardTrendPoint[] = Array.from({ length: 30 }, (_, i) => ({
  date: `2026-08-${String(i + 1).padStart(2, '0')}`,
  counts: { critical: i % 3, high: i % 5 },
}))

/** Drives the ResizeObserver the chart installs, with a controllable width. */
function installViewport(width: number) {
  const callbacks: (() => void)[] = []
  class FakeResizeObserver {
    constructor(private cb: () => void) {
      callbacks.push(() => this.cb())
    }
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  const original = globalThis.ResizeObserver
  vi.stubGlobal('ResizeObserver', FakeResizeObserver as unknown as typeof ResizeObserver)
  const descriptor = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientWidth')
  Object.defineProperty(HTMLElement.prototype, 'clientWidth', { configurable: true, value: width })
  return {
    fire: () => act(() => callbacks.forEach((cb) => cb())),
    restore: () => {
      vi.stubGlobal('ResizeObserver', original)
      if (descriptor) Object.defineProperty(HTMLElement.prototype, 'clientWidth', descriptor)
      else delete (HTMLElement.prototype as unknown as Record<string, unknown>).clientWidth
    },
  }
}

describe('FindingsTrendChart', () => {
  let viewport: ReturnType<typeof installViewport> | null = null

  beforeEach(() => {
    viewport = null
  })
  afterEach(() => {
    viewport?.restore()
  })

  it('sizes its viewBox from the measured card width', () => {
    viewport = installViewport(358)
    render(<FindingsTrendChart points={points} series={series} />)
    viewport.fire()

    const svg = screen.getByRole('img', { name: /Findings created by day/ })
    expect(svg.getAttribute('viewBox')).toBe('0 0 358 260')
  })

  it('carries no min-width that would overflow a 390px viewport', () => {
    viewport = installViewport(358)
    render(<FindingsTrendChart points={points} series={series} />)
    viewport.fire()

    const svg = screen.getByRole('img', { name: /Findings created by day/ })
    expect(svg.getAttribute('class')).not.toMatch(/min-w-/)
    const figure = svg.closest('figure')!
    expect(figure.getAttribute('class')).not.toMatch(/overflow-x-auto/)
  })

  it('keeps the last point inside the plot area', () => {
    viewport = installViewport(358)
    render(<FindingsTrendChart points={points} series={series} />)
    viewport.fire()

    const svg = screen.getByRole('img', { name: /Findings created by day/ })
    const [, , widthAttr] = (svg.getAttribute('viewBox') ?? '').split(' ')
    const labels = Array.from(svg.querySelectorAll('text')).map((t) => Number(t.getAttribute('x')))
    expect(Math.max(...labels)).toBeLessThanOrEqual(Number(widthAttr))
  })

  it('falls back to a usable width when nothing can be measured', () => {
    render(<FindingsTrendChart points={points} series={series} />)
    const svg = screen.getByRole('img', { name: /Findings created by day/ })
    expect(svg.getAttribute('viewBox')).toBe('0 0 840 260')
  })

  // Every Y-axis label off the rendered SVG, in document order, which is the axis read upward.
  const axisLabels = () =>
    [...document.querySelectorAll('svg text')]
      .map((node) => node.textContent ?? '')
      .filter((text) => /^\d+$/.test(text))

  // The axis used four fixed fractions of the maximum, so a maximum under 4 rounded several grid
  // lines to the same number: an empty 30-day window drew five lines reading 0, 0, 1, 1, 1 and
  // put three different heights at the same stated count.
  it('labels every grid line with a distinct count when the window is empty', () => {
    viewport = installViewport(900)
    const empty: DashboardTrendPoint[] = points.map((point) => ({ date: point.date, counts: { critical: 0, high: 0 } }))
    render(<FindingsTrendChart points={empty} series={series} />)
    viewport.fire()
    const labels = axisLabels()
    expect(labels).toEqual(['0', '1'])
    expect(new Set(labels).size).toBe(labels.length)
  })

  it('keeps the labels distinct for a small non-zero maximum', () => {
    viewport = installViewport(900)
    const small: DashboardTrendPoint[] = points.map((point, index) => ({ date: point.date, counts: { critical: index % 3, high: 0 } }))
    render(<FindingsTrendChart points={small} series={series} />)
    viewport.fire()
    const labels = axisLabels()
    expect(labels).toEqual(['0', '1', '2'])
  })
})

describe('niceStep', () => {
  it('rounds a raw step up to 1, 2 or 5 times a power of ten', () => {
    expect(niceStep(0.25)).toBe(0.5)
    expect(niceStep(1)).toBe(1)
    expect(niceStep(1.75)).toBe(2)
    expect(niceStep(2.5)).toBe(5)
    expect(niceStep(6)).toBe(10)
    expect(niceStep(200)).toBe(200)
    expect(niceStep(250)).toBe(500)
  })

  it('never returns zero, which would divide the axis by nothing', () => {
    expect(niceStep(0)).toBe(1)
    expect(niceStep(-3)).toBe(1)
    expect(niceStep(Number.NaN)).toBe(1)
  })
})
