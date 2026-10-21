// Local console fixtures exercise production components. These captures do not
// establish native provider acceptance, which requires authorized live resources.
import { chromium, expect } from '@playwright/test'
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { resolve } from 'node:path'
const base = process.env.PROVIDER_PREVIEW_BASE ?? 'http://127.0.0.1:5188'
const output = resolve('../docs/evidence/remaining-providers/console')
mkdirSync(output, { recursive: true })
const providers = [
 ['github-issues', 'GitHub Issues', 'private_repository'],
 ['gitlab-issues', 'GitLab Issues', 'confidential_issue'],
 ['azure-boards', 'Azure Boards', 'provider_access'],
 ['servicenow', 'ServiceNow', 'provider_access'],
 ['linear', 'Linear', 'provider_access'],
].map(([provider, name, policy]) => ({ provider, name, policy, description: `${name} governed ticket destination.`, capabilities: ['tickets', 'test_connection'], config_fields: [], secret_fields: provider.endsWith('-issues') ? [] : [{ name: 'token', label: 'Access token', kind: 'password', required: true }] }))
const connections = providers.map((provider, index) => ({ id: provider.provider, provider: provider.provider, name: `${provider.name} sandbox`, endpoint: index === 0 ? 'https://github.com' : index === 1 ? 'https://gitlab.com' : 'https://provider.example.test', config: {}, enabled: true, archived: false, version: 1, connection_revision: 1, credential_revision: 0, credential_configured: true }))
const browser = await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] })
const captures = []
try {
 for (const theme of ['light', 'dark']) {
  for (const state of ['github-issues', 'gitlab-issues', 'azure-boards', 'servicenow', 'linear', 'loading', 'empty', 'orphan', 'error', 'permission']) {
   const context = await browser.newContext({ viewport: { width: 1440, height: 1100 } })
   const page = await context.newPage()
   const errors = []
   page.on('pageerror', error => errors.push(error.message))
   await context.addInitScript(theme => localStorage.setItem('synapse-theme', theme), theme)
   await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (!path.startsWith('/api/')) return route.continue()
    const respond = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/api/auth/session') return respond({ authenticated: true, csrf_token: 'synthetic-preview' })
    if (path === '/api/v1/aup') return respond({ accepted: true, version: 'preview', text: '' })
    if (path === '/api/v1/me') return respond({ id: 'preview-admin', name: 'Preview administrator', role: state === 'permission' ? 'readonly' : 'admin', tenant_id: 'preview-tenant' })
    if (path === '/api/v1/integration-providers') { if (state === 'loading') await new Promise(() => {}); return respond(providers) }
    if (path === '/api/v1/integrations') return respond(state === 'empty' || state === 'orphan' ? [] : connections)
    if (path === '/api/v1/engagements') return respond([{ id: 'preview-engagement', name: 'Dedicated test assessment', client: 'Synthetic fixture', state: 'active' }])
    if (path === '/api/v1/projects') return respond([])
    if (path === '/api/v1/ticket-mappings') return respond(state === 'orphan' ? [{ id: 'orphan-mapping', integration_id: 'removed-connection', scope: 'engagement', scope_id: 'preview-engagement', project_key: 'security/private', issue_type: 'issue', locale: 'en', data_class: 'summary', version: 1 }] : [])
    if (path.endsWith('/ticket-metadata')) {
     if (state === 'error') return respond({ code: 'provider_unavailable', error: 'SCM connector unavailable (synthetic fixture).' }, 503)
     const provider = providers.find(provider => path.includes(`/${provider.provider}/`)) ?? providers[0]
     return respond({ projects: [{ id: 'security/private', name: 'security/private' }], issue_types: [{ id: 'issue', name: 'Issue' }], security_policy: provider.policy, fields: [], priorities: [], components: [], security_levels: [], transitions: [], supports_grouping: false, supports_status_sync: false })
    }
    return respond({ items: [], capabilities: [] })
   })
   await page.goto(`${base}/settings/integrations/tickets`)
   if (state === 'loading') await page.getByText('Loading ticket providers…').waitFor()
   else if (state === 'permission') await page.getByText('Ticket settings require integration access').waitFor()
   else if (state === 'empty') { await page.getByText('No ticket provider connections').waitFor(); await page.getByText('No mappings for this scope.').waitFor() }
   else if (state === 'orphan') {
    await page.getByRole('button', { name: 'Unresolved ticket destination', exact: true }).click()
    await page.getByText('This saved mapping no longer resolves to a provider connection. Select a supported mapping or create a new one.', { exact: true }).waitFor()
    await expect(page.getByRole('button', { name: 'Save ticket mapping', exact: true })).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Delete mapping', exact: true })).toBeEnabled()
   } else {
    await page.getByLabel('Ticket connection', { exact: true }).waitFor().catch(async error => { console.log(await page.locator('body').innerText()); console.log(errors); await page.screenshot({path:'/tmp/synapse-provider-preview-failure.png'}); throw error })
    if (providers.some(provider => provider.provider === state) && await page.getByLabel('Ticket connection', { exact: true }).inputValue() !== state) await page.getByLabel('Ticket connection', { exact: true }).selectOption(state)
    if (state === 'error') await page.getByText('SCM connector unavailable (synthetic fixture).').waitFor()
    else {
     await page.getByLabel('Provider project', { exact: true }).selectOption('security/private')
     await page.getByLabel('Provider issue type', { exact: true }).selectOption('issue')
     await expect(page.getByRole('button', { name: 'Create ticket mapping', exact: true })).toBeEnabled()
    }
   }
   const file = `${state}-${theme}.png`
   await page.screenshot({ path: resolve(output, file), fullPage: true })
   captures.push({ file, state, theme, source: 'Production console, synthetic API fixtures', errors, sha256: createHash('sha256').update(readFileSync(resolve(output, file))).digest('hex') })
   if (state === 'orphan') {
    await page.getByRole('button', { name: 'Delete mapping', exact: true }).scrollIntoViewIfNeeded()
    const actionsFile = `orphan-actions-${theme}.png`
    await page.screenshot({ path: resolve(output, actionsFile), fullPage: true })
    captures.push({ file: actionsFile, state: 'orphan-actions', theme, source: 'Production console, synthetic API fixtures', errors, sha256: createHash('sha256').update(readFileSync(resolve(output, actionsFile))).digest('hex') })
   }
   if (state === 'github-issues' || state === 'permission') {
    await page.setViewportSize({ width: 390, height: 900 })
    if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)) throw new Error(`Horizontal overflow: ${state} ${theme}`)
    const mobileFile = `${state}-${theme}-mobile.png`
    await page.screenshot({ path: resolve(output, mobileFile), fullPage: true })
    captures.push({ file: mobileFile, state, theme, viewport: 'mobile', source: 'Production console, synthetic API fixtures', errors, sha256: createHash('sha256').update(readFileSync(resolve(output, mobileFile))).digest('hex') })
   }
   await context.close()
  }
 }
} finally { await browser.close() }
writeFileSync(resolve(output, 'manifest.json'), JSON.stringify({ provider_acceptance: false, captures }, null, 2) + '\n')
if (captures.some(capture => capture.errors.length)) throw new Error('Browser errors in console captures')
console.log(`Captured ${captures.length} console states with synthetic fixtures.`)
