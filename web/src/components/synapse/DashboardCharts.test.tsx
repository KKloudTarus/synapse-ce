import { act, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { DashboardTrendPoint } from '../../lib/types'
import { FindingsTrendChart } from './DashboardCharts'

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
})
