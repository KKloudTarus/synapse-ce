import { Key01, Loading01, LogIn04, ShieldTick } from '@untitledui/icons'
import { useState, type ReactNode } from 'react'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, ErrorState, Field, Input } from '../components/ui'
import logoFull from '../assets/logo-full-dark.png'

export function Connect() {
  const { phase, aup, error, connecting, connect, acceptAup, logout } = useAuth()
  const [token, setToken] = useState('')
  const [accepting, setAccepting] = useState(false)
  const [signingOut, setSigningOut] = useState(false)

  if (phase === 'connecting') {
    return (
      <Center>
        <Loading01 className="size-6 animate-spin motion-reduce:animate-none text-brand" />
        <p className="mt-3 text-sm text-tertiary">Checking your sign-in session…</p>
      </Center>
    )
  }

  return (
    <Center>
      <div className="mb-7 flex flex-col items-center gap-3 text-center">
        <img src={logoFull} alt="Synapse" className="h-20 w-auto" />
        <p className="text-xs text-tertiary">Security &amp; pentest operations</p>
      </div>

      {phase === 'need-aup' && aup ? (
        <Card title="Acceptable Use Policy" className="w-full max-w-lg animate-fade-in">
          <p className="whitespace-pre-line text-sm leading-relaxed text-secondary">{aup.text}</p>
          {error && <div className="mt-4"><ErrorState message={error} /></div>}
          <div className="mt-5 flex items-center justify-between gap-3">
            <button
              type="button"
              disabled={signingOut}
              onClick={async () => {
                setSigningOut(true)
                try { await logout() } finally { setSigningOut(false) }
              }}
              className="text-xs text-tertiary underline-offset-2 hover:text-primary hover:underline"
            >
              {signingOut ? 'Signing out…' : 'Sign out'}
            </button>
            <Button variant="brand" loading={accepting} onClick={async () => {
              setAccepting(true)
              try { await acceptAup() } finally { setAccepting(false) }
            }}>
              <ShieldTick className="size-4" /> Accept &amp; continue
            </Button>
          </div>
          <p className="mt-3 text-center text-[11px] text-quaternary">Policy version {aup.version}</p>
        </Card>
      ) : (
        <Card className="w-full max-w-[420px] animate-fade-in">
          <div className="space-y-5">
            <div className="space-y-1 text-center">
              <h1 className="text-base font-semibold text-primary">Sign in to Synapse</h1>
              <p className="text-sm text-tertiary">Use your organization sign-in to continue.</p>
            </div>
            {error && <ErrorState message={error} />}
            <a
              href="/api/auth/oidc/login"
              className="inline-flex w-full select-none items-center justify-center gap-2 rounded-lg bg-brand-solid px-3.5 py-2 text-sm font-semibold text-white transition-opacity duration-150 hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2"
            >
              <LogIn04 className="size-4" /> Sign in with your organization
            </a>
            <div className="flex items-center gap-3 text-xs text-quaternary before:h-px before:flex-1 before:bg-secondary after:h-px after:flex-1 after:bg-secondary">or</div>
            <details className="rounded-lg border border-secondary bg-secondary/30 p-3">
              <summary className="cursor-pointer text-sm font-medium text-primary">Development or automation API token</summary>
              <form onSubmit={(e) => { e.preventDefault(); void connect(token) }} className="mt-4 space-y-4">
                <Field label="API token">
                  <Input
                    type="password"
                    required
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder="paste token…"
                    className="font-mono"
                    aria-label="API token"
                    aria-describedby="api-token-hint"
                  />
                </Field>
                <p id="api-token-hint" className="text-[11px] text-tertiary">
                  {token.trim() ? 'The token is sent only to this server.' : 'Paste a token to enable this development sign-in.'}
                </p>
                <Button variant="brand" type="submit" loading={connecting} disabled={!token.trim()} className="w-full">
                  <Key01 className="size-4" /> Connect with API token
                </Button>
              </form>
            </details>
          </div>
        </Card>
      )}
    </Center>
  )
}

function Center({ children }: { children: ReactNode }) {
  return <div className="flex min-h-screen flex-col items-center justify-center bg-primary px-4 py-12">{children}</div>
}
