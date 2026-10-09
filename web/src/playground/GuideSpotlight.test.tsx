import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { GuideSpotlight, visibleGuideBox, findGuideContext, measureGuideBox, scrollGuideTarget } from './GuideSpotlight'
import { guidePlacement } from './guide-placement'
import { GuideToggle } from './GuideToggle'

describe('Shared walkthrough spotlight', () => {
  it('returns to the start of a long target rather than the middle of its results', () => {
    render(<section data-testid="inventory">Recorded inventory</section>)
    const target = screen.getByTestId('inventory')
    target.scrollIntoView = vi.fn()
    scrollGuideTarget(target)
    expect(target.scrollIntoView).toHaveBeenCalledWith({ block: 'start', inline: 'nearest', behavior: 'instant' })
  })
  it('reveals page content as well as its navigation anchor', () => {
    render(<><aside><nav><a href="/assets">Assets</a></nav></aside><main><h1>Assets inventory</h1></main></>)
    const anchor = screen.getByRole('link'), heading = screen.getByRole('heading')
    anchor.scrollIntoView = vi.fn(); heading.scrollIntoView = vi.fn()
    vi.spyOn(heading, 'getClientRects').mockReturnValue([{}] as unknown as DOMRectList)
    scrollGuideTarget(anchor)
    expect(heading.scrollIntoView).toHaveBeenCalledOnce()
    expect(anchor.scrollIntoView).toHaveBeenCalledOnce()
  })
  it('repositions the current target on expand, without scrolling when minimizing', () => {
    const toggle = vi.fn()
    const { rerender } = render(<><section data-demo-focus>Current step</section><GuideToggle minimized onToggle={toggle} /></>)
    const target = screen.getByText('Current step')
    target.scrollIntoView = vi.fn()
    fireEvent.click(screen.getByRole('button', { name: 'Expand guide' }))
    expect(target.scrollIntoView).toHaveBeenCalledOnce()
    expect(toggle).toHaveBeenCalledOnce()
    rerender(<><section data-demo-focus>Current step</section><GuideToggle minimized={false} onToggle={toggle} /></>)
    fireEvent.click(screen.getByRole('button', { name: 'Minimize guide' }))
    expect(target.scrollIntoView).toHaveBeenCalledOnce()
  })
  it('anchors an unscoped review to the closest visible navigation module, with a mobile heading fallback', () => {
    const rects = vi.spyOn(HTMLElement.prototype, 'getClientRects').mockReturnValue([{}] as unknown as DOMRectList)
    const { rerender } = render(<><nav aria-label="Primary navigation"><a href="/fleet">Fleet</a><a href="/fleet/hosts">Hosts</a></nav><main><h1>Host details</h1></main></>)
    expect(findGuideContext('/fleet/hosts/demo')).toBe(screen.getByRole('link', { name: 'Hosts' }))
    rerender(<><nav hidden aria-label="Primary navigation"><a href="/fleet/hosts">Hosts</a></nav><main><h1>Host details</h1></main></>)
    expect(findGuideContext('/fleet/hosts/demo')).toBe(screen.getByRole('heading', { name: 'Host details' }))
    rects.mockRestore()
  })
  it('clips the ring to nested scroll containers instead of highlighting through the header', () => {
    const { container } = render(<div style={{ overflowY: 'auto' }}><section>Long inventory</section></div>)
    const parent = container.firstElementChild as HTMLElement, target = parent.firstElementChild as HTMLElement
    vi.spyOn(parent, 'getBoundingClientRect').mockReturnValue(new DOMRect(0, 100, 400, 300))
    vi.spyOn(target, 'getBoundingClientRect').mockReturnValue(new DOMRect(20, -50, 200, 900))
    expect(measureGuideBox(target)).toEqual({ left: 15, top: 100, width: 210, height: 300 })
  })
  it('keeps the top of a large result readable when every placement overlaps', () => {
    expect(guidePlacement({ left: 260, top: 200, width: 750, height: 900 }, 1040, 1017).bottom).toBe(16)
  })
  it('clips large and partially scrolled targets to the visible viewport', () => {
    expect(visibleGuideBox({ left: -20, top: -80, width: 1000, height: 1400 }, 390, 844)).toEqual({ left: 6, top: 6, width: 378, height: 832 })
    expect(visibleGuideBox({ left: 10, top: 900, width: 100, height: 30 }, 390, 844)).toBeNull()
  })
  it('removes the dimming and ring when minimized and keeps the page interactive', () => {
    const box = { left: 50, top: 150, width: 200, height: 60 }
    const { container, rerender } = render(<><button>Page action</button><GuideSpotlight box={box} minimized={false} /></>)
    expect(container.querySelector('[data-guide-ring]')).toHaveStyle({ left: '50px', width: '200px' })
    expect(container.querySelector('[data-guide-spotlight]')).toHaveClass('pointer-events-none')
    expect(screen.getByRole('button', { name: 'Page action' })).toBeEnabled()
    rerender(<GuideSpotlight box={box} minimized />)
    expect(container.querySelector('[data-guide-spotlight]')).toBeNull()
  })
  it('centers the card like the Overview and moves it away from a lower target', () => {
    expect(guidePlacement(null, 1280, 800)).toMatchObject({ left: 384, bottom: 16 })
    const placement = guidePlacement({ left: 350, top: 620, width: 580, height: 100 }, 1280, 800)
    expect(placement.top).toBe(80)
    expect(placement.bottom).toBeUndefined()
  })
})
