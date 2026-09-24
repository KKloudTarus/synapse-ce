// Run as:  UI_AUDIT_TOKEN=<api token> UI_ROUTES='["/assets","/settings/team"]' pnpm ui:probe
//
// Reads each screen's main region and reports its real heading, tabs and controls, so a
// walkthrough can be written from what the screen actually says rather than from memory.
import { chromium } from '@playwright/test'
import { writeFileSync } from 'node:fs'

const BASE = process.env.UI_AUDIT_BASE ?? 'http://localhost:5173'
const TOKEN = process.env.UI_AUDIT_TOKEN ?? ''
if (!TOKEN) { console.error('set UI_AUDIT_TOKEN'); process.exit(1) }

const ROUTES = JSON.parse(process.env.UI_ROUTES ?? '[]')

const browser = await chromium.launch()
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
await context.addInitScript((t) => sessionStorage.setItem('synapse.token', t), TOKEN)

const out = []
for (const route of ROUTES) {
  const page = await context.newPage()
  try {
    await page.goto(BASE + route, { waitUntil: 'networkidle', timeout: 25000 })
  } catch { /* a screen that keeps a stream open still renders; read it anyway */ }
  await page.waitForTimeout(1000)
  const info = await page.evaluate(() => {
    // The sidebar is chrome; everything the walkthrough describes lives in the main region.
    const main = document.querySelector('main') ?? document.body
    const text = (el) => (el.textContent ?? '').replace(/\s+/g, ' ').trim()
    const uniq = (xs) => [...new Set(xs.filter(Boolean))]
    return {
      title: text(main.querySelector('h1') ?? main.querySelector('h2') ?? main),
      subtitle: text(main.querySelector('h1 + p, h1 ~ p') ?? document.createElement('i')).slice(0, 180),
      tabs: uniq([...main.querySelectorAll('[role="tab"]')].map(text)).slice(0, 14),
      buttons: uniq([...main.querySelectorAll('button')].map((b) => text(b) || b.getAttribute('aria-label') || '')).slice(0, 14),
      columns: uniq([...main.querySelectorAll('thead th')].map(text)).slice(0, 12),
      metrics: uniq([...main.querySelectorAll('[class*="uppercase"]')].map(text).filter((t) => t.length < 40)).slice(0, 8),
      empty: text(main).slice(0, 220),
    }
  })
  out.push({ route, ...info })
  await page.close()
}
await browser.close()
writeFileSync('/tmp/uiaudit/probe.json', JSON.stringify(out, null, 2))
for (const s of out) {
  console.log(`\n## ${s.route}`)
  console.log(`  title   : ${s.title.slice(0, 90)}`)
  if (s.tabs.length) console.log(`  tabs    : ${s.tabs.join(' | ')}`)
  if (s.buttons.length) console.log(`  buttons : ${s.buttons.join(' | ')}`)
  if (s.columns.length) console.log(`  columns : ${s.columns.join(' | ')}`)
  if (s.metrics.length) console.log(`  labels  : ${s.metrics.join(' | ')}`)
}
