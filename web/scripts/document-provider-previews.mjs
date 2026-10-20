// Render production publication and ticket-preview components with local fixtures.
// No request is sent to a native provider. HTML captures use actual adapter output.
import { chromium } from '@playwright/test'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { basename, resolve } from 'node:path'
import { createHash } from 'node:crypto'
const base = process.env.PROVIDER_PREVIEW_BASE ?? 'http://127.0.0.1:5188'
const output = resolve('../docs/evidence/remaining-providers')
const temporary = mkdtempSync(resolve('.provider-preview-'))
const directory = basename(temporary)
const captureDir = resolve(output, 'publication-console')
mkdirSync(captureDir, { recursive: true })
writeFileSync(resolve(temporary, 'index.html'), `<html><body><div id="root"></div><script type="module" src="/${directory}/entry.tsx"></script></body></html>`)
writeFileSync(resolve(temporary, 'entry.tsx'), `
import React from 'react'; import {createRoot} from 'react-dom/client';
import {DocumentPublishingPanel} from '../src/pages/EngagementDetail/components/DocumentPublishingPanel';
import {TicketPreviewView} from '../src/pages/EngagementDetail/components/TicketPreviewView';
import '../src/index.css'; import '../src/styles/globals.css';
const state=new URLSearchParams(location.search).get('state')||'document';
const preview={provider:state==='azure-preview'?'azure-boards':'github-issues',endpoint:state==='azure-preview'?'https://dev.azure.com/sandbox':'https://github.example.test',summary:'SQL injection — Tiếng Việt',description:'**Approved stored finding**\\n\\nLiteral <script> stays inert.\\n\\nBằng chứng đã được phê duyệt.',fields:{project:state==='azure-preview'?'org/security':'security/private',issuetype:state==='azure-preview'?'Bug':'issue'},dataClass:'summary',digest:'synthetic-preview',mappingVersion:1,markerRequired:true,markerFormat:'synapse-intent-…',wire:state==='azure-preview'?[{op:'add',path:'/fields/System.Title',value:'SQL injection — Tiếng Việt'},{op:'add',path:'/fields/System.Description',value:'Approved stored finding'}]:{title:'SQL injection — Tiếng Việt',body:'Approved stored finding',labels:[]}};
const theme=new URLSearchParams(location.search).get('theme')||'light';document.documentElement.dataset.theme=theme;if(theme==='dark')document.documentElement.classList.add('dark-mode');
createRoot(document.getElementById('root')!).render(<main className="min-h-screen bg-primary p-8"><p className="mb-4 text-sm text-tertiary">Local visual preview · synthetic fixtures · no live provider acceptance</p>{state.endsWith('preview')?<TicketPreviewView preview={preview as any}/>:<DocumentPublishingPanel engagementId="preview-engagement"/>}</main>);
`)
const browser = await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] })
const captures = []
const capture = async (page, file, state, theme, errors) => {
 const path = resolve(captureDir, file)
 await page.screenshot({ path, fullPage: true })
 captures.push({ file, state, theme, source: 'Production components, synthetic API fixtures', errors, sha256: createHash('sha256').update(readFileSync(path)).digest('hex') })
}
try {
 for (const theme of ['light', 'dark']) {
  for (const state of ['document', 'empty', 'loading', 'error', 'permission', 'restriction-lost', 'native-preview', 'azure-preview']) {
   const context = await browser.newContext({ viewport: { width: 1200, height: 840 } })
   const page = await context.newPage(); const errors = []
   page.on('pageerror', error => errors.push(error.message))
   await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname
    if (!path.startsWith('/api/')) return route.continue()
    const respond = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/api/v1/me') return respond({ id: 'synthetic-user', tenant_id: 'synthetic-tenant', role: state === 'permission' ? 'readonly' : 'reviewer' })
    if (path === '/api/v1/integrations') return respond(state === 'empty' ? [] : ['google-drive', 'sharepoint', 'onedrive'].map(provider => ({ id: provider, provider, name: `${provider} · restricted folder`, enabled: true, archived: false, credential_configured: true })))
    if (path.endsWith('/documents')) {
     if (state === 'loading') return new Promise(() => {})
     if (state === 'error') return respond({ error: 'Document links unavailable (synthetic fixture).' }, 503)
     if (state === 'empty') return respond([])
     return respond([{ id: 'synthetic-link', integration_id: 'sharepoint', source_kind: 'engagement_report', remote_url: 'https://tenant.sharepoint.com/sites/security', remote_version: 1, remote_revision_kind: 'opaque', revision: 3, content_hash: 'a'.repeat(64), restriction_status: state === 'restriction-lost' ? 'restriction_lost' : 'verified', restriction_checked_at: '2026-10-20T00:00:00Z' }])
    }
    return respond([])
   })
   await page.goto(`${base}/${directory}/index.html?state=${state}&theme=${theme}`)
   if (state.endsWith('preview')) { await page.getByText('Exact provider request').click(); await page.getByText('Submitting adds the correlation marker', { exact: false }).waitFor() }
   else if (state === 'loading') await page.getByText('Loading document publications…').waitFor()
   else if (state === 'error') await page.getByText('Document links unavailable (synthetic fixture).').waitFor()
   else if (state === 'permission') await page.getByText('A reviewer or administrator can request publication and unpublish a report.', { exact: true }).waitFor()
   else if (state === 'restriction-lost') await page.getByText('Restricted sharing lost').waitFor()
   else if (state === 'empty') await page.getByText('No enabled document connection with credentials is available.', { exact: false }).waitFor()
   else await page.getByLabel('Document connection').waitFor()
   await capture(page, `${state}-${theme}.png`, state, theme, errors)
   await context.close()
  }
 }
 const illustration = '<svg xmlns="http://www.w3.org/2000/svg" width="600" height="120"><rect width="600" height="120" fill="#f3f0ff"/><text x="20" y="48" font-family="sans-serif" font-size="22" fill="#513495">Synthetic evidence image</text><text x="20" y="84" font-family="sans-serif" font-size="17" fill="#513495">No live provider or finding data</text></svg>'
 for (const provider of ['drive', 'sharepoint']) for (const locale of ['en', 'vi']) {
  const page = await browser.newPage({ viewport: { width: 1100, height: 800 } })
  await page.route('**/*', route => {
   if (route.request().resourceType() === 'document') return route.fulfill({ contentType: 'text/html', body: readFileSync(resolve(output, 'documents', `${provider}-${locale}.html`), 'utf8') })
   if (route.request().resourceType() === 'image') return route.fulfill({ contentType: 'image/svg+xml', body: illustration })
   return route.abort()
  })
  await page.goto('http://document-preview.test/report.html')
  await page.locator('img').evaluate(image => image.decode())
  await page.locator('h1').waitFor()
  await page.screenshot({ path: resolve(output, 'documents', `${provider}-${locale}.png`), fullPage: true })
  await page.close()
 }
} finally {
 await browser.close(); rmSync(temporary, { recursive: true, force: true })
}
writeFileSync(resolve(captureDir, 'manifest.json'), JSON.stringify({ provider_acceptance: false, captures }, null, 2) + '\n')
if (captures.some(capture => capture.errors.length)) throw new Error('Browser errors in preview captures')
console.log(`Captured ${captures.length} production-component states and 4 actual adapter HTML previews.`)
