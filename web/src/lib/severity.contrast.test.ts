import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { SEVERITY_ORDER, sevSoft, sevText } from './severity'

// The stylesheet is the single source of truth for these tokens, so the test
// measures the file rather than a copy of its values.
const CSS = readFileSync(resolve(import.meta.dirname, '../index.css'), 'utf8')

/**
 * The severity badges are the densest 12px text in the product. The solid
 * severity tokens are tuned as fills; used as text they fell to 2.95:1 (high)
 * and 4.04:1 (critical) on a light card. This locks the `*text` pair at WCAG AA
 * against the surfaces the badges actually sit on, in both themes.
 */

function block(startMarker: string): string {
  const start = CSS.indexOf(startMarker)
  expect(start, `missing block ${startMarker}`).toBeGreaterThan(-1)
  const open = CSS.indexOf('{', start)
  const end = CSS.indexOf('\n}', open)
  return CSS.slice(open, end)
}

const LIGHT = block('@theme {')
const DARK = block(":root[data-theme='dark']")

function token(scope: string, name: string): string {
  const match = new RegExp(`--color-${name}:\\s*(#[0-9a-fA-F]{6})`).exec(scope)
  expect(match, `missing --color-${name}`).not.toBeNull()
  return match![1]
}

function rgb(hex: string): [number, number, number] {
  const v = hex.replace('#', '')
  return [parseInt(v.slice(0, 2), 16), parseInt(v.slice(2, 4), 16), parseInt(v.slice(4, 6), 16)]
}

function luminance([r, g, b]: [number, number, number]): number {
  const channel = (c: number) => {
    const s = c / 255
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
  }
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

function contrast(fg: string, bg: [number, number, number]): number {
  const l1 = luminance(rgb(fg))
  const l2 = luminance(bg)
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05)
}

function blend(hex: string, alpha: number, base: [number, number, number]): [number, number, number] {
  const c = rgb(hex)
  return [0, 1, 2].map((i) => c[i] * alpha + base[i] * (1 - alpha)) as [number, number, number]
}

const AA_NORMAL_TEXT = 4.5

const THEMES = [
  { name: 'light', scope: LIGHT, surface: 'card' },
  { name: 'dark', scope: DARK, surface: 'card' },
] as const

describe('severity token contrast', () => {
  it.each(THEMES.map((t) => t.name))('clears AA on the soft badge in %s mode', (themeName) => {
    const theme = THEMES.find((t) => t.name === themeName)!
    // The dark block only redefines the tokens it changes; anything else falls
    // through to the light @theme block.
    const read = (name: string) => {
      try {
        return token(theme.scope, name)
      } catch {
        return token(LIGHT, name)
      }
    }
    const card = rgb(read('card'))

    for (const severity of SEVERITY_ORDER) {
      const fill = read(severity === 'info' || severity === 'unknown' ? 'infosev' : severity)
      const text = read(
        severity === 'info' || severity === 'unknown'
          ? 'infosevtext'
          : `${severity}text`,
      )
      const alpha = severity === 'info' || severity === 'unknown' ? 0.15 : 0.1
      const onBadge = contrast(text, blend(fill, alpha, card))
      const onCard = contrast(text, card)

      expect(
        onBadge,
        `${themeName} ${severity} badge text ${text} on its soft background is ${onBadge.toFixed(2)}:1`,
      ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT)
      expect(onCard, `${themeName} ${severity} text ${text} on the card is ${onCard.toFixed(2)}:1`).toBeGreaterThanOrEqual(
        AA_NORMAL_TEXT,
      )
    }
  })

  it('routes badge and text styles through the text token, never the fill token', () => {
    for (const severity of SEVERITY_ORDER) {
      expect(sevSoft[severity]).toMatch(/text-\w+text\b/)
      expect(sevText[severity]).toMatch(/^text-\w+text$/)
    }
  })
})
