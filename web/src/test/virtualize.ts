import { vi } from 'vitest'

// installVirtualViewport gives jsdom a non-zero viewport so @tanstack/react-virtual actually renders
// rows in tests (otherwise the scroll element measures 0×0 and no virtual items mount). Returns a
// teardown to restore the originals. Mirrors the stub in VirtualRuleCards.test.tsx.
export function installVirtualViewport(): () => void {
  const originalGetBoundingClientRect = Element.prototype.getBoundingClientRect

  window.ResizeObserver = class ResizeObserver {
    constructor(private cb: ResizeObserverCallback) {}
    observe(target: Element) {
      this.cb([{ target, contentRect: target.getBoundingClientRect() } as ResizeObserverEntry], this)
    }
    unobserve() {}
    disconnect() {}
  }

  Element.prototype.getBoundingClientRect = vi.fn(() => ({
    width: 800,
    height: 800,
    top: 0,
    left: 0,
    bottom: 800,
    right: 800,
    x: 0,
    y: 0,
    toJSON: () => {},
  })) as unknown as typeof Element.prototype.getBoundingClientRect

  Object.defineProperty(HTMLElement.prototype, 'offsetHeight', { configurable: true, value: 800 })
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', { configurable: true, value: 800 })

  return () => {
    Element.prototype.getBoundingClientRect = originalGetBoundingClientRect
    delete (window as { ResizeObserver?: unknown }).ResizeObserver
  }
}
