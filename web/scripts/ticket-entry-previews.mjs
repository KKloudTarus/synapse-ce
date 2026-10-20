// Capture production ticket-entry UI states with local, synthetic API fixtures.
// These previews never contact an external ticket provider and are not live acceptance evidence.
import { chromium, expect } from '@playwright/test'
import { createHash } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { basename, resolve } from 'node:path'

const base = process.env.TICKET_ENTRY_PREVIEW_BASE ?? 'http://127.0.0.1:5188'
const output = resolve('../docs/evidence/remaining-providers/ticket-entry')
const temporary = mkdtempSync(resolve('.ticket-entry-preview-'))
const directory = basename(temporary)
mkdirSync(output, { recursive: true })

writeFileSync(resolve(temporary, 'index.html'), `<html><body><div id="root"></div><script type="module" src="/${directory}/entry.tsx"></script></body></html>`)
writeFileSync(resolve(temporary, 'entry.tsx'), `
import React from 'react'
import { createRoot } from 'react-dom/client'
import { MemoryRouter } from 'react-router-dom'
import { TicketsPanel } from '../src/pages/EngagementDetail/components/TicketsPanel'
import { BulkTicketsPanel } from '../src/pages/EngagementDetail/components/BulkTicketsPanel'
import { FindingsTab } from '../src/pages/EngagementDetail/FindingsTab'
import '../src/index.css'
import '../src/styles/globals.css'

const state = new URLSearchParams(location.search).get('state') || 'ticket-ready'
const theme = new URLSearchParams(location.search).get('theme') || 'light'
document.documentElement.dataset.theme = theme
if (theme === 'dark') document.documentElement.classList.add('dark-mode')
const finding = {
  id: 'finding-one', engagementId: 'preview-engagement', title: 'SQL injection in account search',
  description: 'Synthetic approved finding. It contains no customer evidence.', severity: 'high', cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  cwe: 'CWE-89', status: 'open', dedupKey: 'preview-sqli', kev: false, riskScore: 9.8,
  class: 'first_party', scope: 'app.example.test', reachability: 'reachable', impact: 'Synthetic preview only',
  priority: 1, assignee: '', version: 1, kind: 'sast', evidenceScore: 100, proposedBy: '', complianceControls: [],
}
function App() {
  if (state.startsWith('ticket-')) return <TicketsPanel engagementId="preview-engagement" findingId="finding-one" />
  if (state.startsWith('bulk-')) return <BulkTicketsPanel engagementId="preview-engagement" findingIds={['finding-one', 'finding-two']} onDone={() => {}} />
  return <MemoryRouter><FindingsTab findings={[finding] as any} scan={null} engagementId="preview-engagement" filter="all" setFilter={() => {}} focusedFindingId="" onUpdated={() => {}} onReload={() => {}} /></MemoryRouter>
}
createRoot(document.getElementById('root')!).render(<main className="min-h-screen bg-primary p-8"><p className="mb-4 text-sm text-tertiary">Local visual preview · synthetic fixtures · no live provider acceptance</p><App /></main>)
`)

const mapping = {
  id: 'mapping-preview', integration_id: 'github-issues', scope: 'engagement', scope_id: 'preview-engagement',
  project_key: 'security/private', issue_type: 'issue', component: '', labels: [], priority_map: {}, security_level: '',
  waiver_reason: '', data_class: 'summary', locale: 'en', summary_template: '', description_template: '', field_values: {},
  transition_id: '', status_transitions: {}, grouping_mode: 'finding', auto_push_enabled: false, auto_push_min_severity: 'high', version: 3,
}
const preview = {
  summary: 'SQL injection in account search', description: 'Approved synthetic finding for a private repository.', fields: {},
  data_class: 'summary', digest: 'synthetic-preview-digest', mapping_version: 3, marker_required: true,
  marker_format: 'synapse-intent:v1', wire: { title: 'SQL injection in account search', body: 'Approved synthetic finding for a private repository.', labels: ['security'] },
}
const tickets = {
  links: [{ id: 'link-preview', external_url: 'https://github.example.test/security/private/issues/23', external_id: '23', integration_id: 'github-issues', created_at: '2026-10-20T00:00:00Z' }],
  intents: [{ id: 'intent-preview', state: 'uncertain', error_code: 'ambiguous_create', version: 4, created_at: '2026-10-20T00:00:00Z' }],
  mappings: [mapping],
}
const browser = await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] })
const captures = []
const states = [
  'ticket-ready', 'ticket-preview', 'ticket-empty', 'ticket-loading', 'ticket-error', 'ticket-readonly',
  'bulk-ready', 'bulk-preview', 'bulk-empty', 'bulk-loading', 'bulk-error', 'bulk-readonly',
  'findings-bulk-selection',
]
const respond = (route, body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

try {
  for (const theme of ['light', 'dark']) {
    for (const state of states) {
      const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } })
      await context.addInitScript((value) => localStorage.setItem('synapse-theme', value), theme)
      const page = await context.newPage()
      const errors = []
      page.on('pageerror', (error) => errors.push(error.message))
      await page.route('**/api/**', async (route) => {
        const pathname = new URL(route.request().url()).pathname
        if (!pathname.startsWith('/api/')) return route.continue()
        if (pathname === '/api/v1/me') return respond(route, { id: 'preview-user', name: 'Preview user', tenant_id: 'preview-tenant', role: state.endsWith('readonly') ? 'readonly' : 'reviewer' })
        if (pathname.endsWith('/ticket-observations')) return respond(route, { observations: [{ remote_id: '23', status_category: 'open', deleted_or_unreadable: false, checked_at: '2026-10-20T00:00:00Z' }], proposals: [], comments: [] })
        if (pathname.endsWith('/tickets') && route.request().method() === 'GET') {
          if (state.endsWith('loading')) return new Promise(() => {})
          if (state.endsWith('error')) return respond(route, { error: 'Ticket delivery service unavailable (synthetic fixture).' }, 503)
          return respond(route, state.endsWith('empty') ? { links: [], intents: [], mappings: [] } : tickets)
        }
        if (pathname.endsWith('/ticket-preview')) return respond(route, { ...preview, summary: pathname.includes('finding-two') ? 'Missing authorization check' : preview.summary })
        return respond(route, [])
      })
      await page.goto(`${base}/${directory}/index.html?state=${state}&theme=${theme}`)
      if (state === 'ticket-ready') await page.getByRole('button', { name: 'Preview ticket' }).waitFor()
      else if (state === 'ticket-preview') { await page.getByRole('button', { name: 'Preview ticket' }).click(); await page.getByRole('button', { name: 'Submit ticket' }).waitFor(); await page.getByText('Exact provider request').click() }
      else if (state === 'ticket-empty') await page.getByText('No ticket mapping for this scope').waitFor()
      else if (state === 'ticket-loading') await page.getByText('Loading ticket links…').waitFor()
      else if (state === 'ticket-error') await page.getByText('Ticket delivery service unavailable (synthetic fixture).').waitFor()
      else if (state === 'ticket-readonly') await page.getByText('Ticket links are visible.').waitFor()
      else if (state === 'bulk-ready') await page.getByRole('button', { name: 'Prepare previews' }).waitFor()
      else if (state === 'bulk-preview') { await page.getByRole('button', { name: 'Prepare previews' }).click(); await page.getByLabel('Bulk ticket previews').waitFor(); await page.getByText('Exact provider request').first().click() }
      else if (state === 'bulk-empty') await page.getByText('No ticket mapping is configured for this engagement.').waitFor()
      else if (state === 'bulk-loading') await page.getByText('Loading Ticket mappings…').waitFor()
      else if (state === 'bulk-error') await page.getByText('Ticket delivery service unavailable (synthetic fixture).').waitFor()
      else if (state === 'bulk-readonly') { await page.getByText('must prepare and submit tickets.').waitFor(); await expect(page.getByRole('button', { name: 'Prepare previews' })).toBeDisabled() }
      else { await page.getByLabel('Select SQL injection in account search for ticket').check(); await page.getByRole('button', { name: 'Create tickets (1)' }).waitFor() }
      const file = `${state}-${theme}.png`
      const path = resolve(output, file)
      await page.screenshot({ path, fullPage: true })
      captures.push({ file, state, theme, source: 'Production components, synthetic local API fixtures', errors, sha256: createHash('sha256').update(readFileSync(path)).digest('hex') })
      await context.close()
    }
  }
} finally {
  await browser.close()
  rmSync(temporary, { recursive: true, force: true })
}

writeFileSync(resolve(output, 'manifest.json'), JSON.stringify({ provider_acceptance: false, captures }, null, 2) + '\n')
if (captures.some((capture) => capture.errors.length)) throw new Error('Browser errors in ticket-entry preview captures')
console.log(`Captured ${captures.length} production ticket-entry states with synthetic fixtures.`)
