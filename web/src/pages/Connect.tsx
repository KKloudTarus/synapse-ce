import { ChevronDown, Eye, EyeOff, Key01, Loading01, LogIn04, RefreshCw01, ShieldTick } from '@untitledui/icons'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useAuth } from '../auth/AuthContext'
import { InvitationAcceptance } from '../auth/InvitationAcceptance'
import { useEnterpriseContext } from '../auth/useEnterpriseContext'
import { Button, ErrorState, Field, Input } from '../components/ui'
import logo from '../assets/logo.png'

export function Connect() {
  const { phase, aup, error, errorRequestId, canRetry, retrying, retry, connecting, connect, acceptAup, logout, oidcAvailable } = useAuth()
  const enterprise = useEnterpriseContext()
  const [token, setToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [accepting, setAccepting] = useState(false)
  const [signingOut, setSigningOut] = useState(false)

  if (phase === 'connecting') {
    return (
      <AuthShell>
        <div className="flex flex-col items-center gap-3 py-10 text-center">
          <Loading01 className="size-6 animate-spin motion-reduce:animate-none text-brand" />
          <p className="text-sm text-tertiary">Checking your sign-in session…</p>
        </div>
      </AuthShell>
    )
  }

  return (
    <AuthShell>
      <Brand />

      {phase === 'need-aup' && aup ? (
        <Panel>
          <div className="mb-4 text-center">
            <h2 className="text-lg font-bold tracking-tight text-primary">Acceptable Use Policy</h2>
            <p className="mt-1 text-sm text-tertiary">Review and accept to continue.</p>
          </div>
          <div className="max-h-[46vh] overflow-y-auto rounded-xl border border-secondary bg-secondary/30 p-4">
            <p className="whitespace-pre-line text-sm leading-relaxed text-secondary">{aup.text}</p>
          </div>
          {error && <AuthError className="mt-4" message={error} requestId={errorRequestId} canRetry={canRetry} retrying={retrying} onRetry={retry} />}
          <div className="mt-5 flex items-center justify-between gap-3">
            <button
              type="button"
              disabled={signingOut}
              onClick={async () => { setSigningOut(true); try { await logout() } finally { setSigningOut(false) } }}
              className="rounded text-xs text-tertiary underline-offset-2 hover:text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg disabled:cursor-not-allowed disabled:opacity-60"
            >
              {signingOut ? 'Signing out…' : 'Sign out'}
            </button>
            <Button loading={accepting} onClick={async () => { setAccepting(true); try { await acceptAup() } finally { setAccepting(false) } }}>
              <ShieldTick className="size-4" /> Accept &amp; continue
            </Button>
          </div>
          <p className="mt-3 text-center text-[11px] text-quaternary">Policy version {aup.version}</p>
        </Panel>
      ) : enterprise.status === 'loading' ? <EnterpriseLoading /> : enterprise.status === 'legacy' ? (
        <LegacySignIn {...{ error, errorRequestId, canRetry, retrying, retry, connecting, connect, oidcAvailable, token, setToken, showToken, setShowToken }} />
      ) : enterprise.status === 'error' ? (
        <EnterpriseUnavailable message={enterprise.message} onRetry={enterprise.reload} />
      ) : (
        <>
          {error && <AuthError className="mb-4" message={error} requestId={errorRequestId} canRetry={canRetry} retrying={retrying} onRetry={retry} />}
          <EnterpriseSignIn context={enterprise.context} beginning={enterprise.beginning} recovering={enterprise.recovering} begin={enterprise.begin} recover={enterprise.recover} refresh={retry} />
        </>
      )}
    </AuthShell>
  )
}

function EnterpriseLoading() {
  return <Panel><div role="status" className="flex flex-col items-center gap-3 py-10 text-center"><Loading01 className="size-6 animate-spin motion-reduce:animate-none text-brand" /><p className="text-sm text-tertiary">Loading approved sign-in methods…</p></div></Panel>
}

function EnterpriseUnavailable({ message, onRetry }: { message: string; onRetry: () => Promise<void> }) {
  return <Panel><div className="mb-5 text-center"><h2 className="text-xl font-bold tracking-tight text-primary">Sign-in unavailable</h2><p className="mt-1 text-sm text-tertiary">Your organization’s approved sign-in methods could not be loaded.</p></div><AuthError message={message} requestId={null} canRetry={false} retrying={false} onRetry={onRetry} /><Button className="mt-4 w-full" variant="secondary" onClick={() => { void onRetry() }}><RefreshCw01 className="size-4" /> Retry approved sign-in</Button></Panel>
}

function EnterpriseSignIn({ context, beginning, recovering, begin, recover, refresh }: {
  context: NonNullable<ReturnType<typeof useEnterpriseContext>['context']>
  beginning: boolean
  recovering: boolean
  begin: (connectionID: string) => Promise<string>
  recover: (secret: string) => Promise<void>
  refresh: () => Promise<void>
}) {
  const [connectionID, setConnectionID] = useState(context.connections.length === 1 ? context.connections[0].id : '')
  const [error, setError] = useState<string | null>(null)
  const [secret, setSecret] = useState('')

  const start = async () => {
    if (!connectionID) return
    setError(null)
    try {
      const authorizationURL = await begin(connectionID)
      window.location.assign(authorizationURL)
    } catch (cause) {
      if (cause instanceof DOMException && cause.name === 'AbortError') return
      setError(cause instanceof Error ? cause.message : 'Could not start enterprise sign-in. Try again.')
    }
  }
  const activateRecovery = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!secret) return
    setError(null)
    try {
      await recover(secret)
      setSecret('')
      await refresh()
    } catch (cause) {
      if (cause instanceof DOMException && cause.name === 'AbortError') return
      setError(cause instanceof Error ? cause.message : 'Emergency activation could not be completed.')
    }
  }

  return <Panel>
    <div className="mb-5 text-center"><h2 className="text-xl font-bold tracking-tight text-primary">Welcome back</h2><p className="mt-1 text-sm text-tertiary">Use an approved organization connection to continue.</p><p className="mt-2 text-xs font-medium text-secondary">Organization sign-in is {context.requirement === 'required' ? 'required' : 'optional'}.</p></div>
    {error && <AuthError className="mb-4" message={error} requestId={null} canRetry={false} retrying={false} onRetry={async () => {}} />}
    {context.connections.length === 0 ? <p role="status" className="rounded-lg border border-secondary bg-secondary/30 px-4 py-3 text-sm text-tertiary">No approved sign-in connections are available. Contact your administrator or use emergency activation.</p> : context.connections.length === 1 ? <Button className="w-full" loading={beginning} disabled={recovering} onClick={() => { void start() }}><LogIn04 className="size-5" /> Continue with {context.connections[0].name}</Button> : <div className="space-y-4"><Field label="Approved sign-in connection" htmlFor="enterprise-connection"><select id="enterprise-connection" value={connectionID} onChange={(event) => setConnectionID(event.target.value)} disabled={beginning || recovering} className="input-inset w-full rounded-lg border border-secondary bg-secondary px-3.5 py-2.5 text-sm text-primary outline-none transition-colors focus:border-brand focus:ring-2 focus:ring-brand/40"><option value="">Select a connection</option>{context.connections.map((connection) => <option key={connection.id} value={connection.id}>{connection.name}</option>)}</select></Field><Button className="w-full" loading={beginning} disabled={!connectionID || recovering} onClick={() => { void start() }}><LogIn04 className="size-5" /> Continue with selected connection</Button></div>}
    <details className="group mt-5 rounded-xl border border-secondary bg-secondary/30 transition-colors open:bg-secondary/50 hover:border-borderstrong"><summary className="flex cursor-pointer list-none items-center gap-3 p-3.5 [&::-webkit-details-marker]:hidden"><span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-brand-primary text-brand-secondary ring-1 ring-inset ring-brand/20"><Key01 className="size-4" /></span><span className="min-w-0 flex-1"><span className="block text-sm font-semibold text-primary">Emergency activation</span><span className="block text-xs text-tertiary">Use an administrator-provided recovery code</span></span><ChevronDown className="size-4 shrink-0 text-tertiary transition-transform duration-200 group-open:rotate-180" /></summary><form onSubmit={(event) => { void activateRecovery(event) }} className="space-y-4 border-t border-secondary p-3.5"><Field label="Recovery code"><Input type="password" autoComplete="one-time-code" required value={secret} onChange={(event) => setSecret(event.target.value)} placeholder="enter recovery code" className="font-mono" /></Field><Button type="submit" variant="secondary" loading={recovering} disabled={!secret || beginning} className="w-full"><Key01 className="size-4" /> Activate emergency session</Button></form></details>
    <InvitationAcceptance />
  </Panel>
}

function LegacySignIn({ error, errorRequestId, canRetry, retrying, retry, connecting, connect, oidcAvailable, token, setToken, showToken, setShowToken }: {
  error: string | null; errorRequestId: string | null; canRetry: boolean; retrying: boolean; retry: () => Promise<void>; connecting: boolean; connect: (token: string) => Promise<void>; oidcAvailable: boolean; token: string; setToken: (token: string) => void; showToken: boolean; setShowToken: (show: boolean | ((current: boolean) => boolean)) => void
}) {
  return <Panel>
    <div className="mb-5 text-center"><h2 className="text-xl font-bold tracking-tight text-primary">Welcome back</h2><p className="mt-1 text-sm text-tertiary">{oidcAvailable ? 'Sign in with your organization to continue.' : 'Sign in with your API token to continue.'}</p></div>
    {error && <AuthError className="mb-4" message={error} requestId={errorRequestId} canRetry={canRetry} retrying={retrying} onRetry={retry} />}
    {oidcAvailable && <><a href="/api/auth/oidc/login" className="btn-primary group flex w-full select-none items-center justify-center gap-2.5 rounded-xl px-4 py-3 text-sm font-semibold text-primary_on-brand transition-transform duration-150 hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg"><LogIn04 className="size-5" /> Sign in with your organization</a><div className="my-5 flex items-center gap-3 text-[11px] font-medium uppercase tracking-wider text-quaternary before:h-px before:flex-1 before:bg-secondary after:h-px after:flex-1 after:bg-secondary">or</div></>}
    <details open={!oidcAvailable} className="group rounded-xl border border-secondary bg-secondary/30 transition-colors open:bg-secondary/50 hover:border-borderstrong"><summary className="flex cursor-pointer list-none items-center gap-3 p-3.5 [&::-webkit-details-marker]:hidden"><span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-brand-primary text-brand-secondary ring-1 ring-inset ring-brand/20"><Key01 className="size-4" /></span><span className="min-w-0 flex-1"><span className="block text-sm font-semibold text-primary">Development or automation API token</span><span className="block text-xs text-tertiary">For CLI, CI/CD and service integrations</span></span><ChevronDown className="size-4 shrink-0 text-tertiary transition-transform duration-200 group-open:rotate-180" /></summary><form onSubmit={(event) => { event.preventDefault(); void connect(token) }} className="space-y-4 border-t border-secondary p-3.5"><Field label="API token"><div className="relative"><Input type={showToken ? 'text' : 'password'} required value={token} onChange={(event) => setToken(event.target.value)} placeholder="paste token…" className="pr-10 font-mono" aria-label="API token" aria-describedby="api-token-hint" /><button type="button" onClick={() => setShowToken((value) => !value)} aria-label={showToken ? 'Hide token' : 'Show token'} className="absolute inset-y-0 right-0 flex items-center rounded-r-lg px-3 text-tertiary transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60">{showToken ? <EyeOff className="size-4" /> : <Eye className="size-4" />}</button></div></Field><p id="api-token-hint" className="text-[11px] text-tertiary">{token.trim() ? 'The token is sent only to this server.' : 'Paste a token to enable this development sign-in.'}</p><Button type="submit" loading={connecting} disabled={!token.trim()} className="w-full"><Key01 className="size-4" /> Connect with API token</Button></form></details>
    <div className="mt-6 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t border-secondary pt-4 text-xs text-quaternary"><span className="inline-flex items-center gap-1.5"><ShieldTick className="size-3.5" /> Encrypted, audited access</span><span className="inline-flex items-center gap-1.5"><span className="size-1.5 rounded-full bg-accent" /> All systems operational</span></div>
  </Panel>
}

// The failure region for the sign-in gate. It takes focus when a new error appears so keyboard and
// screen-reader users land on it, and it offers Retry only when the credential was kept and repeating
// restoration may succeed. Retry is disabled while an attempt is running, so a double activation
// sends one request.
function AuthError({ message, requestId, canRetry, retrying, onRetry, className }: {
  message: string
  requestId: string | null
  canRetry: boolean
  retrying: boolean
  onRetry: () => Promise<void>
  className?: string
}) {
  const regionRef = useRef<HTMLDivElement>(null)
  const retryRef = useRef<HTMLDivElement>(null)
  // Refocus after each finished attempt too: the disabled button drops focus while a retry runs.
  useEffect(() => {
    if (retrying) return
    if (canRetry) retryRef.current?.querySelector('button')?.focus()
    else regionRef.current?.focus()
  }, [message, canRetry, retrying])
  return (
    <div className={className}>
      <div ref={regionRef} tabIndex={-1} className="rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-brand/60">
        <ErrorState message={message} />
      </div>
      {requestId && (
        <p className="mt-2 break-all text-[11px] text-tertiary">
          Request ID <span className="font-mono text-secondary">{requestId}</span>
        </p>
      )}
      {canRetry && (
        <div ref={retryRef} className="mt-3">
          <Button
            type="button"
            variant="secondary"
            loading={retrying}
            onClick={() => { void onRetry() }}
            className="w-full"
          >
            {!retrying && <RefreshCw01 className="size-4" />}
            {retrying ? 'Retrying…' : 'Retry'}
          </Button>
        </div>
      )}
    </div>
  )
}

// Branded lockup: the hexagon mark on an elevated tile + wordmark + eyebrow. Uses the crisp mark
// (logo.png), which reads in both themes — the full embossed logo washed out on the pale background.
function Brand() {
  return (
    <div className="mb-7 flex flex-col items-center text-center">
      <div className="card-sheen elev mb-4 flex size-16 items-center justify-center rounded-2xl bg-card ring-1 ring-inset ring-black/5 dark:ring-white/10">
        <img src={logo} alt="Synapse" className="size-10" />
      </div>
      <h1 className="text-2xl font-bold tracking-tight text-primary">Synapse</h1>
      <p className="mt-1.5 text-[11px] font-semibold uppercase tracking-[0.2em] text-brand dark:text-branddim">Security operations platform</p>
    </div>
  )
}

function Panel({ children }: { children: ReactNode }) {
  return (
    <div className="card-sheen elev animate-fade-in rounded-2xl border border-secondary bg-card p-6 motion-reduce:animate-none sm:p-7">
      {children}
    </div>
  )
}

// The auth background is the designed indigo-glow surface (.bg-auth) plus two soft brand blooms, so the
// floating card is anchored in brand light instead of a flat, pale white field.
function AuthShell({ children }: { children: ReactNode }) {
  return (
    <div className="bg-auth relative flex min-h-screen flex-col items-center justify-center overflow-hidden px-4 py-12">
      <div aria-hidden className="pointer-events-none absolute -top-32 left-1/2 size-[560px] -translate-x-1/2 rounded-full bg-brand-solid/10 blur-[130px]" />
      <div aria-hidden className="pointer-events-none absolute -bottom-40 -right-20 size-[420px] rounded-full bg-brand-solid/[0.08] blur-[130px]" />
      <div className="relative w-full max-w-[440px]">{children}</div>
    </div>
  )
}
