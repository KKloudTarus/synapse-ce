import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import { VirtualRuleCards } from './VirtualRuleCards'
import type { RuleSummary } from '../../lib/types'

describe('VirtualRuleCards', () => {
  const mockRules: RuleSummary[] = Array.from({ length: 150 }).map((_, i) => ({
    key: `rule-${i}`,
    name: `Virtual Rule ${i}`,
    language: 'go',
    type: 'vulnerability',
    qualities: ['security'],
    defaultSeverity: 'high',
    tags: ['owasp'],
    cwe: ['CWE-89'],
    owasp: ['A03:2021'],
    description: `Description for rule ${i}`,
    remediationEffort: 30,
    detection: 'pattern',
  }))

  const originalGetBoundingClientRect = Element.prototype.getBoundingClientRect

  beforeEach(() => {
    window.ResizeObserver = class ResizeObserver {
      constructor(private cb: ResizeObserverCallback) {}
      observe(target: Element) {
        this.cb([{ target, contentRect: target.getBoundingClientRect() } as ResizeObserverEntry], this)
      }
      unobserve() {}
      disconnect() {}
    }

    // Mock bounding client rect to give the container a height of 800px
    Element.prototype.getBoundingClientRect = vi.fn(() => ({
      width: 400,
      height: 800,
      top: 0,
      left: 0,
      bottom: 800,
      right: 400,
      x: 0,
      y: 0,
      toJSON: () => {},
    }))
    
    // Mock element height properties
    Object.defineProperty(HTMLElement.prototype, 'offsetHeight', { configurable: true, value: 800 })
    Object.defineProperty(HTMLElement.prototype, 'clientHeight', { configurable: true, value: 800 })
  })

  afterEach(() => {
    Element.prototype.getBoundingClientRect = originalGetBoundingClientRect
    delete (window as any).ResizeObserver
  })

  it('renders a windowed subset for 100+ rules', () => {
    render(
      <MemoryRouter>
        <VirtualRuleCards rules={mockRules} detailFrom="?q=test" />
      </MemoryRouter>
    )

    const renderedCards = screen.getAllByRole('heading', { name: /Virtual Rule/ })
    // With 800px height and 220px estimated item height + overscan, it should be well under 150
    expect(renderedCards.length).toBeGreaterThan(0)
    expect(renderedCards.length).toBeLessThan(150)
  })

  it('does not render all cards simultaneously', () => {
    render(
      <MemoryRouter>
        <VirtualRuleCards rules={mockRules} detailFrom="?q=test" />
      </MemoryRouter>
    )

    expect(screen.queryByText('Virtual Rule 149')).not.toBeInTheDocument()
  })

  it('the first visible cards contain correct data', () => {
    render(
      <MemoryRouter>
        <VirtualRuleCards rules={mockRules} detailFrom="?q=test" />
      </MemoryRouter>
    )

    expect(screen.getByText('Virtual Rule 0')).toBeInTheDocument()
    expect(screen.getByText('rule-0')).toBeInTheDocument()
    expect(screen.getByText('Description for rule 0')).toBeInTheDocument()
  })

  it('scrolling changes the rendered window', async () => {
    render(
      <MemoryRouter>
        <VirtualRuleCards rules={mockRules} detailFrom="?q=test" />
      </MemoryRouter>
    )

    expect(screen.getByText('Virtual Rule 0')).toBeInTheDocument()

    // Simulate scrolling down
    const container = screen.getByLabelText('Rule results')
    container.scrollTop = 20000
    fireEvent.scroll(container)

    // Give the virtualizer a moment to update
    await waitFor(() => {
      // At scrollTop 20000, indices around 45-60 are in view.
      expect(screen.queryByText('Virtual Rule 50')).toBeInTheDocument()
    })
  })

  it('detail links preserve encoded keys and from state', async () => {
    const LocationSpy = () => {
      const location = useLocation()
      return <div data-testid="location-state">{JSON.stringify(location.state)}</div>
    }

    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<VirtualRuleCards rules={mockRules} detailFrom="?q=test" />} />
          <Route path="/rules/:key" element={<LocationSpy />} />
        </Routes>
      </MemoryRouter>
    )

    const firstLink = screen.getByRole('link', { name: /Virtual Rule 0/ })
    expect(firstLink).toHaveAttribute('href', '/rules/rule-0')
    
    fireEvent.click(firstLink)
    
    await waitFor(() => {
      expect(screen.getByTestId('location-state')).toHaveTextContent('{"from":"?q=test"}')
    })
  })

  it('total virtual height represents the complete collection', () => {
    render(
      <MemoryRouter>
        <VirtualRuleCards rules={mockRules} detailFrom="?q=test" />
      </MemoryRouter>
    )

    // Find the relative wrapper div that applies the total height
    // It is the child of the container with aria-rowcount
    const container = screen.getByLabelText('Rule results')
    const wrapper = container.firstChild as HTMLElement
    
    // Total height should be roughly 150 * 220 = 33000px
    const styleHeight = wrapper.style.height
    const heightValue = parseInt(styleHeight, 10)
    expect(heightValue).toBeGreaterThan(30000)
  })

  it('empty input does not crash', () => {
    render(
      <MemoryRouter>
        <VirtualRuleCards rules={[]} detailFrom="?q=test" />
      </MemoryRouter>
    )

    const container = screen.getByLabelText('Rule results')
    expect(container).toHaveAttribute('aria-rowcount', '0')
  })
})
