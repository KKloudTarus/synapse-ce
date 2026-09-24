// Walks every static screen in a real browser, captures a screenshot at desktop and phone width,
// and records the things a screenshot cannot show: console errors, failed requests, a missing page
// heading, and horizontal overflow at phone width.
//
// Requires the dev server and a backend the token is valid for:
//
//   VITE_API_PROXY_TARGET=http://localhost:8080 pnpm dev
//   UI_AUDIT_TOKEN=<api token> pnpm ui:audit
//
// Without a valid token the app renders its sign-in screen on every route, and the audit says so
// rather than reporting 64 clean screens.
import { chromium } from '@playwright/test'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const BASE = process.env.UI_AUDIT_BASE ?? 'http://localhost:5173'
// A screenshot of a live tenant shows its findings, hosts, asset names and roster. A fixed path
// under /tmp is world-readable on a shared machine and can be pre-created as a symlink, so the
// default is a fresh 0700 directory and a caller who wants a stable path opts in explicitly.
const OUT = process.env.UI_AUDIT_OUT ?? mkdtempSync(join(tmpdir(), 'uiaudit-'))
// The dev server proxies /api to the real backend, so the audit needs a real token: a fake one
// walks 64 copies of the sign-in page and reports them as clean.
const TOKEN = process.env.UI_AUDIT_TOKEN ?? ''
if (!TOKEN) {
  console.error('set UI_AUDIT_TOKEN to a token the backend accepts')
  process.exit(1)
}

// Callers pass UI_ROUTES to sweep detail screens and their sub-tabs, which is where most of the
// dashboard actually lives; the list below is the default top-level sweep.
const ROUTES = process.env.UI_ROUTES ? JSON.parse(process.env.UI_ROUTES) : [
  '/dashboard',
  '/engagements',
  '/engagements/new',
  '/assessment-cycles',
  '/assets',
  '/code-quality',
  '/code-quality/gates',
  '/code-quality/profiles',
  '/fleet',
  '/fleet/agents',
  '/fleet/hosts',
  '/fleet/coverage-windows',
  '/fleet/workloads',
  '/fleet/asset-graph',
  '/fleet/incidents',
  '/blueteam/response',
  '/rules',
  '/ownership',
  '/settings',
  '/settings/team',
  '/settings/integrations',
  '/settings/connectors',
  '/settings/privacy',
  '/settings/relationships',
  '/settings/config',
  '/settings/sla',
  '/settings/offensive-policy',
  '/settings/alerting',
  '/settings/ownership',
  '/ai-triage/reviews',
  '/ai-triage/observability',
  '/vulnerability-intelligence',
]

const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'phone', width: 390, height: 844 },
]

mkdirSync(OUT, { recursive: true })

const browser = await chromium.launch()
const findings = []
// Every /api/v1 request the app makes while the sweep drives it. This is what the product really
// calls, so it needs no static extraction: a path built from a helper or behind a generic call
// signature is recorded the same as a literal one.
const apiCalls = new Set()

for (const viewport of VIEWPORTS) {
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    deviceScaleFactor: 1,
  })
  // The app gates every screen behind a token held in sessionStorage. Without this the audit walks
  // 64 copies of the sign-in page and reports them as clean.
  // Scoped to the origin under test: addInitScript runs in every page and frame the context
  // loads, so an unguarded write would hand a working API token to any other origin the app
  // ever embeds or redirects to.
  await context.addInitScript(({ token, origin }) => {
    if (location.origin === origin) sessionStorage.setItem('synapse.token', token)
  }, { token: TOKEN, origin: new URL(BASE).origin })
  for (const route of ROUTES) {
    const page = await context.newPage()
    const consoleErrors = []
    const failedRequests = []
    page.on('console', (m) => {
      if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 200))
    })
    page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${String(e).slice(0, 200)}`))
    page.on('request', (r) => {
      const u = new URL(r.url(), BASE)
      if (u.pathname.startsWith('/api/v1')) apiCalls.add(`${r.method()} ${u.pathname}`)
    })
    page.on('requestfailed', (r) => {
      const url = r.url()
      // An aborted request is the AbortController doing its job when a screen unmounts or a fetch
      // is superseded; it is not a failure the user ever sees.
      const why = r.failure()?.errorText ?? ''
      if (url.includes('/api/') && !why.includes('ERR_ABORTED')) {
        failedRequests.push(`${r.method()} ${url.replace(BASE, '')} (${why})`)
      }
    })
    // A non-2xx answer is what actually reaches the screen, so record those too.
    page.on('response', (r) => {
      const url = r.url()
      if (url.includes('/api/') && r.status() >= 400 && !url.endsWith('/api/auth/session')) {
        failedRequests.push(`HTTP ${r.status()} ${r.request().method()} ${url.replace(BASE, '')}`)
      }
    })

    const slug = route.replace(/\//g, '_') || '_root'
    let loadError = null
    try {
      await page.goto(BASE + route, { waitUntil: 'networkidle', timeout: 25000 })
    } catch (e) {
      loadError = String(e).slice(0, 160)
    }
    // Let late fetches settle without failing the run when a stream keeps the network busy.
    await page.waitForTimeout(1200)

    const probe = await page.evaluate(() => {
      const doc = document.documentElement
      const headings = [...document.querySelectorAll('h1, h2')].map((h) => h.textContent?.trim() ?? '').filter(Boolean)
      // Elements whose right edge is past the viewport are what make a phone scroll sideways.
      const overflowing = [...document.querySelectorAll('body *')]
        .filter((el) => {
          const r = el.getBoundingClientRect()
          return r.width > 0 && r.right > doc.clientWidth + 2
        })
        .slice(0, 5)
        .map((el) => `${el.tagName.toLowerCase()}.${String(el.className).split(' ').slice(0, 3).join('.')}`.slice(0, 110))
      const buttonsWithoutName = [...document.querySelectorAll('button')]
        .filter((b) => !(b.textContent ?? '').trim() && !b.getAttribute('aria-label') && !b.getAttribute('title'))
        .length
      // A screen that catches its own exception and renders it as text passes every other check
      // here: no console error, no failed request. That is how an Integrations screen showing
      // "Cannot read properties of null (reading 'map')" was captured and reported as clean.
      const main = document.querySelector('main') ?? document.body
      const shown = (main.innerText ?? '').replace(/\s+/g, ' ')
      const renderedError = [
        /Cannot read propert(y|ies)/i, /undefined is not/i, /is not a function/i,
        /Something went wrong/i, /\bTypeError\b/, /\bReferenceError\b/, /internal error/i,
      ].map((re) => shown.match(re)?.[0]).filter(Boolean)
      return {
        renderedError,
        scrollsSideways: doc.scrollWidth > doc.clientWidth + 2,
        overflowing,
        headings: headings.slice(0, 3),
        buttonsWithoutName,
        bodyText: (document.body.innerText ?? '').replace(/\s+/g, ' ').trim().slice(0, 160),
      }
    })

    await page.screenshot({ path: `${OUT}/${viewport.name}${slug}.png`, fullPage: false })

    if (/Sign in with your organization|Welcome back/.test(probe.bodyText)) {
      probe.headings = []
      probe.bodyText = 'NOT SIGNED IN: ' + probe.bodyText
    }
    findings.push({
      route,
      viewport: viewport.name,
      loadError,
      consoleErrors: [...new Set(consoleErrors)].slice(0, 4),
      failedRequests: [...new Set(failedRequests)].slice(0, 4),
      ...probe,
    })
    await page.close()
  }
  await context.close()
}

await browser.close()
writeFileSync(`${OUT}/findings.json`, JSON.stringify(findings, null, 2))
writeFileSync(`${OUT}/api-calls.json`, JSON.stringify([...apiCalls].sort(), null, 2))

const problems = findings.filter(
  (f) => f.loadError || f.renderedError?.length || f.consoleErrors.length || f.failedRequests.length || f.scrollsSideways || !f.headings.length || f.buttonsWithoutName > 0,
)
console.log(`distinct API routes exercised: ${apiCalls.size} (written to ${OUT}/api-calls.json)`)
console.log(`screens visited: ${findings.length} (${ROUTES.length} routes x ${VIEWPORTS.length} viewports)`)
console.log(`screens with something to look at: ${problems.length}\n`)
for (const p of problems) {
  console.log(`${p.viewport.padEnd(7)} ${p.route}`)
  if (p.loadError) console.log(`    load error: ${p.loadError}`)
  if (p.renderedError?.length) console.log(`    ERROR ON SCREEN: ${p.renderedError.join(' | ')}`)
  if (!p.headings.length) console.log(`    no h1/h2 heading; body starts: "${p.bodyText.slice(0, 80)}"`)
  if (p.scrollsSideways) console.log(`    scrolls sideways; widest: ${p.overflowing.join(' | ')}`)
  if (p.buttonsWithoutName) console.log(`    ${p.buttonsWithoutName} button(s) with no accessible name`)
  for (const e of p.consoleErrors) console.log(`    console: ${e}`)
  for (const r of p.failedRequests) console.log(`    request failed: ${r}`)
}
