// Production connection form, authoritative descriptors, synthetic local API only.
import { chromium } from '@playwright/test'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { resolve } from 'node:path'
import { createHash } from 'node:crypto'
const base = process.env.PROVIDER_PREVIEW_BASE ?? 'http://127.0.0.1:5188'
const descriptors = JSON.parse(readFileSync('../docs/evidence/remaining-providers/documents/provider-descriptors.json', 'utf8'))
const directory = resolve('../docs/evidence/remaining-providers/configuration')
mkdirSync(directory, { recursive: true })
const browser = await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] })
const captures = []
try {
 for (const descriptor of descriptors) for (const theme of ['light', 'dark']) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1100 } })
  const page = await context.newPage(); const errors = []
  page.on('pageerror', error => errors.push(error.message))
  await context.addInitScript(theme => localStorage.setItem('synapse-theme', theme), theme)
  await page.route('**/api/**', route => {
   const path = new URL(route.request().url()).pathname
   if (!path.startsWith('/api/')) return route.continue()
   let body = []
   if (path === '/api/auth/session') body = { authenticated: true, csrf_token: 'synthetic-preview' }
   if (path === '/api/v1/aup') body = { accepted: true, version: 'synthetic' }
   if (path === '/api/v1/me') body = { id: 'synthetic-admin', role: 'admin', tenant_id: 'synthetic-tenant' }
   if (path === '/api/v1/integration-providers') body = [descriptor]
   return route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) })
  })
  await page.goto(`${base}/settings/integrations/ci`)
  await page.getByLabel('HTTPS endpoint', { exact: true }).waitFor()
  const example = await page.getByLabel('HTTPS endpoint', { exact: true }).getAttribute('placeholder')
  await page.getByLabel('HTTPS endpoint', { exact: true }).fill(example)
  await page.getByLabel('Display name', { exact: true }).fill(`${descriptor.name} · synthetic preview`)
  for (const field of descriptor.secret_fields ?? []) {
   if (await page.getByLabel(field.label, { exact: true }).inputValue()) throw new Error('Secret field must be empty')
  }
  const file = `${descriptor.provider}-${theme}.png`
  await page.screenshot({ path: resolve(directory, file), fullPage: true })
  captures.push({ file, provider: descriptor.provider, theme, errors, source: 'Production configuration form, actual registered descriptors, synthetic API', sha256: createHash('sha256').update(readFileSync(resolve(directory, file))).digest('hex') })
  await context.close()
 }
} finally { await browser.close() }
writeFileSync(resolve(directory, 'manifest.json'), JSON.stringify({ provider_acceptance: false, captures }, null, 2) + '\n')
if (captures.some(capture => capture.errors.length)) throw new Error('Browser errors in configuration previews')
console.log(`Captured ${captures.length} document configuration forms; all secret fields empty.`)
