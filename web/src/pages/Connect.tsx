import { ChevronDown, Eye, EyeOff, Key01, Loading01, LogIn04, ShieldTick } from '@untitledui/icons'
import { useState, type ReactNode } from 'react'
import { useAuth } from '../auth/AuthContext'
import { Button, ErrorState, Field, Input } from '../components/ui'
import logo from '../assets/logo.png'

export function Connect() {
  const { phase, aup, error, connecting, connect, acceptAup, logout } = useAuth()
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
          {error && <div className="mt-4"><ErrorState message={error} /></div>}
          <div className="mt-5 flex items-center justify-between gap-3">
            <button
              type="button"
              disabled={signingOut}
              onClick={async () => { setSigningOut(true); try { await logout() } finally { setSigningOut(false) } }}
              className="rounded text-xs text-tertiary underline-offset-2 hover:text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {signingOut ? 'Signing out…' : 'Sign out'}
            </button>
            <Button loading={accepting} onClick={async () => { setAccepting(true); try { await acceptAup() } finally { setAccepting(false) } }}>
              <ShieldTick className="size-4" /> Accept &amp; continue
            </Button>
          </div>
          <p className="mt-3 text-center text-[11px] text-quaternary">Policy version {aup.version}</p>
        </Panel>
      ) : (
        <Panel>
          <div className="mb-5 text-center">
            <h2 className="text-xl font-bold tracking-tight text-primary">Welcome back</h2>
            <p className="mt-1 text-sm text-tertiary">Sign in with your organization to continue.</p>
          </div>

          {error && <div className="mb-4"><ErrorState message={error} /></div>}

          <a
            href="/api/auth/oidc/login"
            className="btn-primary group flex w-full select-none items-center justify-center gap-2.5 rounded-xl px-4 py-3 text-sm font-semibold text-primary_on-brand transition-transform duration-150 hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg"
          >
            <LogIn04 className="size-5" /> Sign in with your organization
          </a>

          <div className="my-5 flex items-center gap-3 text-[11px] font-medium uppercase tracking-wider text-quaternary before:h-px before:flex-1 before:bg-secondary after:h-px after:flex-1 after:bg-secondary">
            or
          </div>

          <details className="group rounded-xl border border-secondary bg-secondary/30 transition-colors open:bg-secondary/50 hover:border-secondarystrong">
            <summary className="flex cursor-pointer list-none items-center gap-3 p-3.5 [&::-webkit-details-marker]:hidden">
              <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-brand-primary text-brand-secondary ring-1 ring-inset ring-brand/20">
                <Key01 className="size-4" />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-semibold text-primary">Development or automation API token</span>
                <span className="block text-xs text-tertiary">For CLI, CI/CD and service integrations</span>
              </span>
              <ChevronDown className="size-4 shrink-0 text-tertiary transition-transform duration-200 group-open:rotate-180" />
            </summary>
            <form
              onSubmit={(e) => { e.preventDefault(); void connect(token) }}
              className="space-y-4 border-t border-secondary p-3.5"
            >
              <Field label="API token">
                <div className="relative">
                  <Input
                    type={showToken ? 'text' : 'password'}
                    required
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder="paste token…"
                    className="pr-10 font-mono"
                    aria-label="API token"
                    aria-describedby="api-token-hint"
                  />
                  <button
                    type="button"
                    onClick={() => setShowToken((v) => !v)}
                    aria-label={showToken ? 'Hide token' : 'Show token'}
                    className="absolute inset-y-0 right-0 flex items-center rounded-r-lg px-3 text-tertiary transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                  >
                    {showToken ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                  </button>
                </div>
              </Field>
              <p id="api-token-hint" className="text-[11px] text-tertiary">
                {token.trim() ? 'The token is sent only to this server.' : 'Paste a token to enable this development sign-in.'}
              </p>
              <Button type="submit" loading={connecting} disabled={!token.trim()} className="w-full">
                <Key01 className="size-4" /> Connect with API token
              </Button>
            </form>
          </details>

          <div className="mt-6 flex items-center justify-between border-t border-secondary pt-4 text-xs text-quaternary">
            <span className="inline-flex items-center gap-1.5">
              <ShieldTick className="size-3.5" /> Encrypted, audited access
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-accent" /> All systems operational
            </span>
          </div>
        </Panel>
      )}
    </AuthShell>
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
      <p className="mt-1.5 text-[11px] font-semibold uppercase tracking-[0.2em] text-brand">Security operations platform</p>
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
