// Captures console states with synthetic API fixtures, without provider credentials.
// Start Vite with an API proxy target, then run this from web/.
import { chromium } from '@playwright/test'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const base = process.env.NOTIFICATION_EVIDENCE_BASE ?? 'http://127.0.0.1:5177'
const output = resolve(process.env.NOTIFICATION_EVIDENCE_OUT ?? '../docs/guide/assets/ui/notification-channels')
mkdirSync(output, { recursive: true })
const types = ['webhook', 'slack', 'email', 'teams', 'telegram', 'google_chat', 'discord', 'mattermost', 'rocket_chat', 'pagerduty', 'jsm']
const settings = { revision: 2, relay_configured: false, domains: [], dns_txt_value: 'synapse-email-verification=test-tenant' }
const channel = { id: 'test-channel', name: 'Test Mattermost', type: 'mattermost', enabled: true, destination: 'https://chat.example.test/…', revision: 1, secret_version: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }
const browser = await chromium.launch(process.env.NOTIFICATION_EVIDENCE_BROWSER ? { channel: process.env.NOTIFICATION_EVIDENCE_BROWSER } : {})
const findings = []
try {
  for (const theme of ['light', 'dark']) {
    for (const state of ['channels-create', 'channels-create-rocket_chat', 'channels-create-pagerduty', 'channels-create-jsm', 'channels-edit', 'channels-edit-pagerduty', 'channels-edit-jsm', 'channels-test-success', 'channels-test-error', 'email-empty', 'email-create', 'email-create-google', 'email-create-microsoft', 'email-edit', 'email-loading', 'email-error', 'email-permission']) {
      const provider = state.endsWith('pagerduty') ? 'pagerduty' : state.endsWith('jsm') ? 'jsm' : state.endsWith('rocket_chat') ? 'rocket_chat' : 'mattermost'
      const labels = { mattermost: 'Mattermost', rocket_chat: 'Rocket.Chat', pagerduty: 'PagerDuty', jsm: 'Jira Service Management' }
      const existing = { ...channel, type: provider, name: `Test ${labels[provider]}`, destination: provider === 'pagerduty' ? 'https://events.pagerduty.com/…' : provider === 'jsm' ? 'https://api.atlassian.com/…' : channel.destination }
      const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } })
      const page = await context.newPage()
      const errors = []
      page.on('pageerror', error => errors.push(error.message))
      await context.addInitScript(theme => localStorage.setItem('synapse-theme', theme), theme)
      await page.route('**/api/**', async route => {
        const path = new URL(route.request().url()).pathname
        if (!path.startsWith('/api/')) return route.continue()
        const respond = (data, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) })
        if (path === '/api/auth/session') return respond({ authenticated: true, csrf_token: 'synthetic-test-csrf' })
        if (path === '/api/v1/aup') return respond({ accepted: true, version: 'test', text: '' })
        if (path === '/api/v1/me') return respond({ id: 'test-admin', name: 'Test administrator', role: state === 'email-permission' ? 'viewer' : 'admin', tenant_id: 'test-tenant' })
        if (path.endsWith('/capabilities')) return respond({ capabilities: [{ key: 'notifications', enabled: true }, { key: 'notifications.channel_types', enabled: true, values: types }] })
        if (path.endsWith('/email-settings')) {
          if (state === 'email-loading') await new Promise(resolve => setTimeout(resolve, 3000))
          if (state === 'email-error') return respond({ code: 'email_settings_unavailable', error: 'Email settings temporarily unavailable (test fixture).' }, 503)
          return respond(state === 'email-edit' ? { ...settings, relay_configured: true, relay_host: 'smtp.example.test', relay_port: 465, relay_from: 'sender@example.test', auth_mode: 'password' } : settings)
        }
        if (path.endsWith('/test-channel/test')) return state === 'channels-test-error' ? respond({ code: 'saturated', error: 'Notification channel test rate limit exceeded.' }, 503) : respond({ delivery_id: 'test-delivery' }, 202)
        if (path.endsWith('/notifications/channels')) return respond({ items: state.startsWith('channels-create') ? [] : [existing] })
        if (path.endsWith('/notifications/event-types') || path.endsWith('/notifications/rules') || path.endsWith('/notifications/deliveries') || path.endsWith('/notifications/quarantined-sources')) return respond({ items: [] })
        if (path.endsWith('/engagements')) return respond([])
        return respond({ items: [] })
      })
      await page.goto(`${base}/settings/${state.startsWith('email') ? 'email' : 'alerting'}`)
      if (state === 'email-loading') await page.getByText('Loading email delivery settings…').waitFor()
      else if (state === 'email-permission') await page.getByText('Only tenant administrators can manage the relay and verified domains.').waitFor()
      else if (state === 'email-error') await page.getByRole('button', { name: 'Retry', exact: true }).waitFor()
      else if (state.startsWith('email')) {
        await page.getByRole('button', { name: 'Save email settings' }).waitFor()
        if (state.startsWith('email-create') || state === 'email-edit') {
          await page.getByRole('checkbox', { name: state === 'email-edit' ? 'Replace tenant relay' : 'Configure tenant relay' }).check()
          if (state === 'email-create-google' || state === 'email-create-microsoft') {
            await page.getByRole('combobox', { name: 'Authentication', exact: true }).click()
            await page.getByRole('option', { name: state.endsWith('google') ? 'Google Workspace XOAUTH2' : 'Microsoft 365 XOAUTH2', exact: true }).click()
          }
        }
      } else {
        await page.getByRole('combobox', { name: 'Type', exact: true }).waitFor().catch(async error => {
          console.error(await page.locator('body').innerText())
          console.error(errors)
          throw error
        })
        if (state.startsWith('channels-edit')) await page.getByRole('button', { name: 'Edit channel', exact: true }).click()
        else if (state.startsWith('channels-test')) {
          await page.getByRole('button', { name: 'Test', exact: true }).click()
          await page.getByText(state === 'channels-test-success' ? 'Test queued as test-delivery.' : 'Notification channel test rate limit exceeded. (saturated)', { exact: true }).waitFor()
        } else {
          await page.getByRole('combobox', { name: 'Type', exact: true }).click()
          await page.getByRole('option', { name: labels[provider], exact: true }).click()
        }
      }
      const capture = async name => {
        const height = await page.locator('#main-content').evaluate(main => main.scrollHeight + 80)
        await page.setViewportSize({ width: page.viewportSize().width, height: Math.max(1000, height) })
        await page.locator('#main-content').evaluate(main => { main.scrollTop = 0 })
        await page.screenshot({ path: resolve(output, name), fullPage: true })
      }
      await capture(`${state}-${theme}-desktop.png`)
      if (state === 'email-create' || state.startsWith('channels-create')) {
        await page.setViewportSize({ width: 390, height: 844 })
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)
        if (overflow) errors.push('Horizontal overflow at 390px')
        await capture(`${state}-${theme}-mobile.png`)
      }
      findings.push({ state, theme, errors })
      await context.close()
    }
  }
} finally { await browser.close() }
writeFileSync(resolve(output, 'capture-results.json'), JSON.stringify({ source: 'Synthetic local console fixtures; no live provider delivery.', findings }, null, 2) + '\n')
if (findings.some(finding => finding.errors.length)) throw new Error('Browser evidence contains errors; inspect capture-results.json')
console.log(`Captured ${findings.length} console states without browser errors.`)
