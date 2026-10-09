import type { CSSProperties } from 'react'
export interface GuideBox { top: number; left: number; width: number; height: number }
// Match the Overview by preferring the center; move aside when it would cover the spotlight.
export function guidePlacement(box: GuideBox | null, width = window.innerWidth, height = window.innerHeight): CSSProperties {
  const panelWidth = Math.min(512, width - 16), panelHeight = Math.min(height * .5, 448), top = 80, bottom = height - panelHeight - 16
  const candidates = [
    { left: (width - panelWidth) / 2, top: bottom }, { left: (width - panelWidth) / 2, top },
    { left: width - panelWidth - 8, top: bottom }, { left: 8, top: bottom },
    { left: width - panelWidth - 8, top }, { left: 8, top },
  ]
  const overlap = (p: { left: number; top: number }) => box ? Math.max(0, Math.min(p.left + panelWidth, box.left + box.width) - Math.max(p.left, box.left)) * Math.max(0, Math.min(p.top + panelHeight, box.top + box.height) - Math.max(p.top, box.top)) * (box.height > height * .6 && p.top === top ? 2 : 1) : 0
  const best = candidates.reduce((best, candidate) => overlap(candidate) < overlap(best) ? candidate : best)
  return { left: best.left, top: best.top === top ? top : undefined, bottom: best.top === top ? undefined : 16, transform: 'none' }
}
