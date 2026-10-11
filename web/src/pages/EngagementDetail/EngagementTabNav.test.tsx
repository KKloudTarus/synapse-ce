import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/**
 * A sticky bar must paint an opaque background, or page content scrolls through it. The bug this
 * guards was a background class naming a token that does not exist: `bg-secondary-subtle` produced
 * no CSS rule at all, so Tailwind emitted nothing and the bar stayed transparent while looking
 * styled in the source. Asserting the rendered class is not enough on its own, so this reads the
 * theme files too and requires the token behind the class to be defined.
 */
const src = (rel: string) =>
  readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8')

describe('EngagementTabNav sticky background', () => {
  const component = src('./EngagementTabNav.tsx')

  it('paints a background on the sticky container', () => {
    const sticky = component.match(/className="sticky[^"]*"/)
    expect(sticky, 'the sticky container should still be the first sticky className').not.toBeNull()
    expect(sticky![0]).toMatch(/\bbg-[a-z]/)
  })

  it('names a background token that the theme actually defines', () => {
    const sticky = component.match(/className="sticky[^"]*"/)![0]
    const token = sticky.match(/\bbg-([a-z][A-Za-z0-9_-]*)/)![1]
    const css = ['../../styles/theme.css', '../../index.css'].map(src).join('\n')
    const defined =
      css.includes(`--color-bg-${token}:`) || css.includes(`--color-${token}:`)
    expect(
      defined,
      `bg-${token} resolves to no --color token, so Tailwind emits no rule and the bar is transparent`,
    ).toBe(true)
  })
})
