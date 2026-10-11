// Walks the playground and clicks, rather than only navigating, because the screens that matter sit
// behind tabs and disclosure controls. Records every /api/v1 answer of 400 or worse, so the output is
// the exact list of routes a visitor can still reach an error on.
//
//   PLAY_BASE=http://127.0.0.1:4173 node scripts/playground-crawl.mjs
import { chromium } from '@playwright/test'
import { writeFileSync } from 'node:fs'

const BASE = process.env.PLAY_BASE ?? 'http://127.0.0.1:4173'
const OUT = process.env.PLAY_OUT ?? '/tmp/playground-crawl.json'
const ROUTES = JSON.parse(process.env.PLAY_ROUTES ?? '[]')
// A control that mutates, navigates away or signs out would end the crawl of that screen, and the
// playground's point is the read surfaces. Everything else is fair game.
const SKIP = /sign out|log ?out|delete|remove|revoke|purge|destroy|reset|run scan|new engagement|import|export|download|build report/i

const browser = await chromium.launch()
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
await context.addInitScript(() => {
  try {
    localStorage.setItem('synapse.playground.tour.seen', '1')
    sessionStorage.setItem('synapse.token', 'playground-demo')
  } catch {}
})

const failures = new Map()
const seen = new Set()

for (const route of ROUTES) {
  const page = await context.newPage()
  page.on('response', (r) => {
    const u = new URL(r.url(), BASE)
    if (!u.pathname.startsWith('/api/v1')) return
    seen.add(`${r.request().method()} ${u.pathname}`)
    if (r.status() >= 400) {
      const key = `${r.status()} ${r.request().method()} ${u.pathname}`
      if (!failures.has(key)) failures.set(key, route)
    }
  })
  try {
    await page.goto(BASE + route, { waitUntil: 'domcontentloaded', timeout: 20000 })
    await page.waitForTimeout(2500)

    // Tabs first: they are the main way a screen reveals another read surface.
    const tabs = await page.locator('[role="tab"]').all()
    for (const tab of tabs.slice(0, 14)) {
      try {
        const label = (await tab.innerText({ timeout: 1000 })).trim()
        if (SKIP.test(label)) continue
        await tab.click({ timeout: 3000 })
        await page.waitForTimeout(1200)
      } catch {}
    }

    // Then buttons that reveal rather than change: filters, disclosures, row openers.
    const buttons = await page.locator('button:visible').all()
    for (const button of buttons.slice(0, 20)) {
      try {
        const label = (await button.innerText({ timeout: 800 })).trim()
        if (!label || SKIP.test(label)) continue
        await button.click({ timeout: 2500 })
        await page.waitForTimeout(700)
      } catch {}
    }

    // Finally the first row of any table, which is how a detail pane opens.
    try {
      const row = page.locator('table tbody tr').first()
      if (await row.count()) {
        await row.click({ timeout: 2500 })
        await page.waitForTimeout(1500)
      }
    } catch {}
  } catch (e) {
    failures.set(`NAV ${route}`, String(e).slice(0, 120))
  }
  await page.close()
}

await browser.close()
const sorted = [...failures.entries()].sort()
writeFileSync(OUT, JSON.stringify({ routesExercised: [...seen].sort(), failures: sorted }, null, 2))
console.log(`api routes exercised: ${seen.size}`)
console.log(`distinct failures: ${sorted.length}`)
for (const [key, where] of sorted) console.log(`  ${key}   (first seen on ${where})`)
