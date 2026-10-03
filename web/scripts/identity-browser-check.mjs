// Deterministic browser validation for the enterprise identity UI. It serves the production Vite
// build and fixture HTTP responses locally; it never contacts PostgreSQL or an identity provider.
// Run: cd web && node scripts/identity-browser-check.mjs
import { chromium, expect } from '@playwright/test'
import { createServer } from 'node:http'
import { existsSync, readFileSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { dirname, extname, join, normalize } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dist = join(root, 'dist')
if (!existsSync(join(dist, 'index.html'))) throw new Error('web/dist is missing; run pnpm build first')
const out = process.env.IDENTITY_BROWSER_CHECK_OUT ?? mkdtempSync(join(tmpdir(), 'synapse-identity-browser-'))
mkdirSync(out, { recursive: true })
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' }
const now = '2026-10-02T12:00:00Z'
const calls = []
const json = (res, value, status = 200) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(value)) }
const fixture = (method, path, body) => {
  calls.push(`${method} ${path}`)
  if (path === '/api/auth/session') return [404, { error: 'token-only fixture' }]
  if (path === '/api/auth/enterprise/context') return [200, { enabled: true, tenant_id: 'org-a', requirement: 'required', connections: [{ id: 'provider-a', name: 'Example SSO' }, { id: 'provider-b', name: 'Partner SSO' }], bootstrap_eligible: false }]
  if (path === '/api/v1/aup') return [200, { version: 'fixture', accepted: true }]
  if (path === '/api/v1/me') return [200, { id: 'admin', name: 'Fixture Admin', role: 'admin', tenant_id: 'org-a', person_id: 'person-a', membership_id: 'member-a', credential_kind: 'browser_session', recent_auth: true, features: { enterprise_identity: true } }]
  if (path === '/api/v1/identity/connections') return [200, { connections: [{ id: 'provider-a', display_name: 'Example SSO', issuer: 'https://issuer.example.test', enabled: true, revision: 1, draft_revision: 1, version: 2, test_passed: true }] }]
  if (path === '/api/v1/identity/policy') return [200, { requirement: 'required', version: 2, rehearsed_at: now, alert_configured: true, grace_cutoff: '2026-10-03T12:00:00Z' }]
  if (path === '/api/v1/identity/recovery/alerts') return [200, { alerts: [{ id: 'alert-a', membership_id: 'member-a', session_id: 'session-a', state: 'pending', attempts: 1, max_attempts: 3, next_attempt_at: now, created_at: now }] }]
  if (path === '/api/v1/identity/roster') return [200, { members: [{ id: 'member-a', person_id: 'person-a', name: 'Fixture Admin', role: 'admin', state: 'active', version: 2 }, { id: 'member-b', person_id: 'person-b', name: 'Taylor Member', role: 'member', state: 'active', version: 1 }] }]
  if (path === '/api/v1/identity/invitations' && method === 'GET') return [200, { invitations: [{ id: 'invite-a', recipient: 'invitee@example.test', role: 'member', state: 'pending', version: 1, expires_at: '2026-10-03T12:00:00Z' }] }]
  if (path === '/api/v1/identity/invitations' && method === 'POST') return [201, { invitation: { id: 'invite-new', recipient: 'new@example.test', role: 'member', state: 'pending', version: 1 }, code: 'fixture-invitation-code' }]
  if (path === '/api/v1/identity/bootstrap') return [200, { bootstrap_eligibility: 'fixture-proof' }]
  if (path === '/api/v1/identity/memberships') return [200, { memberships: [{ tenant_id: 'org-a', membership_id: 'member-a', name: 'Alpha', role: 'admin', active: true }, { tenant_id: 'org-b', membership_id: 'member-b', name: 'Beta', role: 'reviewer', active: true }] }]
  if (path === '/api/auth/enterprise/switch') return body?.connection_id ? [200, { authorization_url: '/fixture-provider' }] : [200, { reauthentication_required: true, connections: [{ id: 'provider-b', name: 'Partner SSO' }] }]
  if (path === '/api/v1/me/contacts') return [200, [{ id: 'contact-a', value: 'admin@example.test', source: 'manual', verified_at: now }]]
  if (path === '/api/v1/identity/authenticators') return [200, { identities: [{ connection_id: 'provider-a', name: 'Example SSO', state: 'approved' }] }]
  if (path === '/api/v1/identity/link-connections') return [200, { connections: [{ id: 'provider-b', name: 'Partner SSO' }] }]
  if (path === '/api/auth/enterprise/begin') return [200, { authorization_url: '/fixture-provider' }]
  if (path === '/api/auth/enterprise/invitation') return [200, { connections: [{ id: 'provider-a', name: 'Example SSO' }, { id: 'provider-b', name: 'Partner SSO' }] }]
  if (path === '/api/auth/enterprise/invitation/pending') return [200, { challenge_required: false }]
  if (path.startsWith('/api/v1/identity/') && method !== 'GET') return [200, {}]
  return [200, []]
}
const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://fixture')
  if (url.pathname.startsWith('/api/')) {
    let raw = ''
    req.on('data', chunk => { raw += chunk })
    req.on('end', () => { let body; try { body = raw ? JSON.parse(raw) : undefined } catch {} const [status, value] = fixture(req.method ?? 'GET', url.pathname, body); json(res, value, status) })
    return
  }
  const requested = url.pathname === '/' || url.pathname === '/fixture-provider' ? 'index.html' : normalize(url.pathname).replace(/^([.][.][/\\])+/, '')
  const file = join(dist, requested)
  const safe = file.startsWith(dist) && existsSync(file) ? file : join(dist, 'index.html')
  res.writeHead(200, { 'content-type': mime[extname(safe)] ?? 'application/octet-stream' })
  res.end(readFileSync(safe))
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const base = `http://127.0.0.1:${server.address().port}`
const evidence = { label: 'deterministic HTTP fixture; not real PostgreSQL or hosted provider', base, checks: [], failures: [], calls }
// Keep driving independent screens after one regression so the evidence reports the full browser
// surface. A non-empty failures array still makes the process fail at the end.
const check = (condition, name) => { (condition ? evidence.checks : evidence.failures).push(name) }
const waitForSettledPaint = async page => {
  await page.waitForFunction(() => {
    const main = document.querySelector('main') ?? document.body
    const opacity = Number.parseFloat(getComputedStyle(main).opacity)
    return Number.isFinite(opacity) && opacity >= 0.99 && !main.querySelector('[aria-busy="true"]')
  })
}
const snap = async (page, name) => { await waitForSettledPaint(page); await page.screenshot({ path: join(out, `${name}.png`), fullPage: true }) }
const noOverflow = async (page, name) => check(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 2), `${name}: no horizontal overflow`)
// Prefer Playwright's pinned Chromium. Local developer machines may instead have Chrome, which
// uses the same Chromium engine and keeps this diagnostic runnable without downloading a browser.
const localChromium = process.env.IDENTITY_BROWSER_CHECK_CHROMIUM ?? (process.platform === 'win32' ? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' : '')
const browser = await chromium.launch(existsSync(localChromium) ? { executablePath: localChromium } : {})
try {
  const themedContext = async (width, height, colorScheme, signedIn = false) => {
    const context = await browser.newContext({ viewport: { width, height }, colorScheme })
    await context.addInitScript(({ theme, hasToken }) => {
      localStorage.setItem('synapse-theme', theme)
      if (hasToken) sessionStorage.setItem('synapse.token', 'fixture-token')
    }, { theme: colorScheme, hasToken: signedIn })
    return context
  }
  const assertTheme = async (page, theme, name) => {
    const actual = await page.evaluate(() => document.documentElement.classList.contains('dark-mode') ? 'dark' : 'light')
    check(actual === theme, `${name}: ${theme} theme applied to html`)
  }
  const authenticated = async (width = 1440, height = 900, colorScheme = width < 1000 ? 'dark' : 'light') => {
    const context = await themedContext(width, height, colorScheme, true)
    return [context, await context.newPage()]
  }
  // Connect renders server-approved providers, recovery controls, and an unavailable-state contract.
  {
    const context = await themedContext(1440, 900, 'light'); const page = await context.newPage()
    await page.goto(`${base}/connect`); await page.getByText('Approved sign-in connection').waitFor()
    check(await page.locator('#enterprise-connection option').count() === 3, 'Connect: server provider choices rendered')
    await page.getByText('Emergency activation').click(); await page.getByLabel('Recovery code').fill('fixture-recovery'); check(await page.getByRole('button', { name: 'Activate emergency session' }).isEnabled(), 'Connect: recovery activation enabled only with code')
    await snap(page, 'connect-desktop'); await context.close()
  }
  {
    const context = await themedContext(390, 844, 'dark'); const page = await context.newPage()
    await page.goto(`${base}/connect`); await page.getByText('Approved sign-in connection').waitFor(); await assertTheme(page, 'dark', 'Connect mobile'); await noOverflow(page, 'Connect mobile dark'); await snap(page, 'connect-dark-mobile'); await context.close()
  }
  // Authentication exposes current policy, durable alert state, and one-time recovery controls.
  {
    const [context, page] = await authenticated(); await page.goto(`${base}/settings/authentication`)
    await page.getByRole('heading', { name: 'Authentication' }).waitFor(); await page.getByRole('heading', { name: 'Emergency recovery' }).waitFor()
    check(await page.getByText('pending').count() > 0, 'Authentication: retained alert state rendered')
    await page.getByLabel('Membership ID').fill('member-a'); await page.getByLabel('Person ID').fill('person-a'); check(await page.getByRole('button', { name: 'Generate recovery code' }).isEnabled(), 'Authentication: recovery code form accepts bounded identifiers')
    await snap(page, 'authentication-light-desktop'); await noOverflow(page, 'authentication desktop'); await context.close()
  }
  // Team confirmation must trap then restore focus on Escape, and invitation remains masked until reveal.
  {
    const [context, page] = await authenticated(); await page.goto(`${base}/settings/team`); await page.getByRole('heading', { name: 'Enterprise members' }).waitFor()
    const suspend = page.getByRole('button', { name: 'Suspend' }).first(); await suspend.focus(); await suspend.click(); const dialog = page.getByRole('dialog', { name: 'Confirm enterprise access change' }); await dialog.waitFor(); await page.keyboard.press('Escape')
    await expect(dialog).toBeHidden(); await expect(suspend).toBeFocused(); check(true, 'Team: Escape closes dialog and returns focus')
    await page.getByLabel('Invitation email').fill('new@example.test'); await page.getByRole('button', { name: 'Create invitation' }).click(); await page.getByRole('button', { name: 'Reveal' }).click(); await page.getByText('fixture-invitation-code').waitFor()
    check(await page.getByText('fixture-invitation-code').count() === 1, 'Team: invitation code is explicit reveal-only control')
    await snap(page, 'team-light-desktop'); await context.close()
  }
  // Profile shows own identity links and the invitation provider branch.
  {
    const [context, page] = await authenticated(); await page.goto(`${base}/profile`); await page.getByRole('heading', { name: 'Enterprise identities' }).waitFor(); await page.getByRole('button', { name: 'Link identity' }).waitFor()
    await page.getByLabel('Invitation code').fill('fixture-invite'); await page.getByRole('button', { name: 'Continue with invitation' }).click(); await page.getByRole('button', { name: 'Continue to provider' }).waitFor()
    check(await page.getByRole('button', { name: 'Continue to provider' }).isDisabled(), 'Profile: invitation requires explicit provider choice')
    await snap(page, 'profile-light-desktop'); await context.close()
  }
  // Organization picker reaches required-provider reauthentication and the compact dark layout.
  {
    const [context, page] = await authenticated(900); await page.goto(`${base}/dashboard`); const organization = page.getByLabel('Organization', { exact: true }); await organization.waitFor(); await organization.selectOption('member-b'); await page.getByRole('button', { name: 'Switch organization' }).click(); await page.getByLabel('Verify with an identity provider').waitFor()
    const continueButton = page.getByRole('button', { name: 'Continue to provider' }); check(await continueButton.isDisabled(), 'Organization picker: required provider is initially unselected')
    await page.getByLabel('Verify with an identity provider').selectOption('provider-b'); check(await continueButton.isEnabled(), 'Organization picker: required provider enables after explicit choice')
    await noOverflow(page, 'organization picker compact dark'); await snap(page, 'organization-picker-dark-compact'); await context.close()
  }
  // The interaction checks above deliberately use one stable viewport. This sweep catches layout
  // regressions in every enterprise surface at the actual desktop and mobile breakpoints in both
  // themes, including the invitation component that is rendered inside Profile.
  for (const viewport of [
    { name: 'light-desktop', width: 1440, height: 900, colorScheme: 'light' },
    { name: 'dark-desktop', width: 1440, height: 900, colorScheme: 'dark' },
    { name: 'light-mobile', width: 390, height: 844, colorScheme: 'light' },
    { name: 'dark-mobile', width: 390, height: 844, colorScheme: 'dark' },
  ]) {
    for (const screen of [
      { name: 'connect', route: '/connect', heading: 'Approved sign-in connection', authenticated: false, headingRole: false },
      { name: 'authentication', route: '/settings/authentication', heading: 'Authentication', authenticated: true, headingRole: true },
      { name: 'team', route: '/settings/team', heading: 'Enterprise members', authenticated: true, headingRole: true },
      { name: 'profile-invitation', route: '/profile', heading: 'Accept an invitation', authenticated: true, headingRole: true },
    ]) {
      const context = screen.authenticated
        ? (await authenticated(viewport.width, viewport.height, viewport.colorScheme))[0]
        : await themedContext(viewport.width, viewport.height, viewport.colorScheme)
      const page = await context.newPage()
      await page.goto(`${base}${screen.route}`)
      await (screen.headingRole ? page.getByRole('heading', { name: screen.heading }) : page.getByText(screen.heading, { exact: true })).waitFor()
      await assertTheme(page, viewport.colorScheme, `${screen.name} ${viewport.name}`)
      await noOverflow(page, `${screen.name} ${viewport.name}`)
      await snap(page, `${screen.name}-${viewport.name}`)
      await context.close()
    }
  }
} finally {
  await browser.close(); await new Promise(resolve => server.close(resolve))
  writeFileSync(join(out, 'identity-browser-evidence.json'), JSON.stringify(evidence, null, 2))
}
console.log(`identity browser evidence: ${out}`)
if (evidence.failures.length) {
  console.error(`identity browser checks failed: ${evidence.failures.join('; ')}`)
  process.exitCode = 1
}
