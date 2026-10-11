import type { GuideBox } from './guide-placement'

// Enter a step at its beginning, including its page content when the ring marks navigation.
export function scrollGuideTarget(target: HTMLElement | null) {
  if (!target) return
  if (target.closest('aside, nav, [role="complementary"]') && !target.closest('main')) {
    const heading = [...document.querySelectorAll<HTMLElement>('main h1, main h2')]
      .find(el => el.getClientRects().length > 0)
    heading?.scrollIntoView({ block: 'start', inline: 'nearest', behavior: 'instant' })
  }
  target.scrollIntoView({ block: 'start', inline: 'nearest', behavior: 'instant' })
}

// Review-only steps can describe an entire module rather than a specific control.
export function findGuideContext(pathname: string, doc = document): HTMLElement | null {
  const visible = (el: HTMLElement) => el.getClientRects().length > 0 && !el.closest('[data-guided-demo], [aria-hidden="true"], [inert], [hidden]')
  const modalHeading = [...doc.querySelectorAll<HTMLElement>('[role="dialog"] h1, [role="dialog"] h2')].find(visible)
  if (modalHeading) return modalHeading
  const links = [...doc.querySelectorAll<HTMLAnchorElement>('nav[aria-label="Primary navigation"] a[href]')]
    .filter(el => visible(el) && (pathname === el.pathname || pathname.startsWith(`${el.pathname}/`)))
    .sort((a, b) => b.pathname.length - a.pathname.length)
  return links[0] ?? [...doc.querySelectorAll<HTMLElement>('main h1, main h2')].find(visible) ?? null
}

// Respect nested scrolling surfaces, including the sidebar, tables and modal bodies.
export function measureGuideBox(target: HTMLElement | null): GuideBox | null {
  if (!target) return null
  const rect = target.getBoundingClientRect()
  let left = rect.left - 5, top = rect.top - 5, right = rect.right + 5, bottom = rect.bottom + 5
  for (let parent = target.parentElement; parent && parent !== document.body; parent = parent.parentElement) {
    const style = getComputedStyle(parent), bounds = parent.getBoundingClientRect()
    if (/(auto|scroll|hidden|clip)/.test(style.overflowX)) { left = Math.max(left, bounds.left); right = Math.min(right, bounds.right) }
    if (/(auto|scroll|hidden|clip)/.test(style.overflowY)) { top = Math.max(top, bounds.top); bottom = Math.min(bottom, bounds.bottom) }
  }
  return right > left && bottom > top ? { left, top, width: right - left, height: bottom - top } : null
}

// Clip large tables and scrolled targets to the visible viewport so the ring never disappears offscreen.
export function visibleGuideBox(box: GuideBox, width: number, height: number): GuideBox | null {
  const left = Math.max(6, box.left), top = Math.max(6, box.top)
  const right = Math.min(width - 6, box.left + box.width), bottom = Math.min(height - 6, box.top + box.height)
  return right > left && bottom > top ? { left, top, width: right - left, height: bottom - top } : null
}

export function GuideSpotlight({ box, minimized, layerClass = 'z-[110]' }: { box: GuideBox | null; minimized: boolean; layerClass?: string }) {
  if (minimized || !box) return null
  const visible = visibleGuideBox(box, window.innerWidth, window.innerHeight)
  if (!visible) return null
  const { left, top, width, height } = visible
  return <div data-guide-spotlight aria-hidden="true" className={`pointer-events-none fixed inset-0 ${layerClass}`}>
    <div className="absolute inset-x-0 top-0 bg-black/20" style={{ height: top }} />
    <div className="absolute inset-x-0 bottom-0 bg-black/20" style={{ top: top + height }} />
    <div className="absolute left-0 bg-black/20" style={{ top, height, width: left }} />
    <div className="absolute right-0 bg-black/20" style={{ top, height, left: left + width }} />
    <div data-guide-ring className="absolute rounded-lg ring-2 ring-brand-solid ring-offset-2 ring-offset-transparent" style={visible} />
  </div>
}

export function GuideProgress({ index, total }: { index: number; total: number }) {
  return <div className="hidden w-44 shrink gap-0.5 sm:flex" role="progressbar" aria-label="Walkthrough progress" aria-valuemin={0} aria-valuemax={total} aria-valuenow={index + 1}>
    {Array.from({ length: total }, (_, i) => <span key={i} className={`h-1.5 min-w-0 flex-1 rounded-full ${i === index ? 'bg-brand-solid' : 'bg-quaternary'}`} />)}
  </div>
}
