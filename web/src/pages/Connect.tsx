import { Eye, EyeOff, Key01, Loading01, LogIn04, ShieldTick } from '@untitledui/icons'
import { useEffect, useState, type ReactNode } from 'react'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, ErrorState, Field, Input, cn } from '../components/ui'
import logoFull from '../assets/logo-full.png'

type AuthTab = 'sso' | 'token'

export function Connect() {
  const { phase, aup, error, connecting, oidcAvailable, connect, acceptAup, logout } = useAuth()
  const [token, setToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [userSelectedTab, setUserSelectedTab] = useState<AuthTab | null>(null)
  const [accepting, setAccepting] = useState(false)
  const [signingOut, setSigningOut] = useState(false)

  const currentTab = userSelectedTab ?? (oidcAvailable ? 'sso' : 'token')

  useEffect(() => {
    if (error) {
      document.getElementById('connect-error')?.focus()
    }
  }, [error])

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
      <div className="mb-8 flex flex-col items-center text-center">
        <img src={logoFull} alt="Synapse" className="h-36 w-auto select-none" />
      </div>

      {phase === 'need-aup' && aup ? (
        <Card
          title={
            <div className="flex items-center gap-2">
              <ShieldTick className="size-4.5 text-brand" />
              <span>Acceptable Use Policy</span>
            </div>
          }
          actions={
            <span className="inline-flex items-center rounded-md bg-brand-primary px-2.5 py-0.5 text-xs font-semibold text-brand-secondary ring-1 ring-inset ring-brand/25">
              v{aup.version}
            </span>
          }
          className="w-full max-w-lg animate-fade-in shadow-xs"
        >
          <div className="space-y-4">
            <div className="max-h-64 overflow-y-auto rounded-lg border border-secondary bg-secondary/40 p-4">
              <p className="whitespace-pre-line text-sm leading-relaxed text-secondary">{aup.text}</p>
            </div>
            {error && <ErrorState message={error} id="connect-error" tabIndex={-1} />}
            <div className="flex items-center justify-between gap-3 pt-2">
              <Button
                variant="secondary"
                type="button"
                disabled={signingOut}
                onClick={async () => {
                  setSigningOut(true)
                  try { await logout() } finally { setSigningOut(false) }
                }}
              >
                {signingOut ? 'Signing out…' : 'Sign out'}
              </Button>
              <Button
                variant="brand"
                loading={accepting}
                onClick={async () => {
                  setAccepting(true)
                  try { await acceptAup() } finally { setAccepting(false) }
                }}
              >
                Accept &amp; Continue
              </Button>
            </div>
          </div>
        </Card>
      ) : (
        <Card className="w-full max-w-[420px] animate-fade-in">
          <div className="space-y-5">
            <div className="space-y-1 text-center">
              <h1 className="text-base font-semibold text-primary">Welcome to Synapse</h1>
              <p className="text-sm text-tertiary">Choose your authentication method to continue.</p>
            </div>

            {error && <ErrorState message={error} id="connect-error" tabIndex={-1} />}

            <div role="tablist" aria-label="Sign in methods" className="flex rounded-lg border border-secondary bg-secondary/50 p-1">
              <button
                type="button"
                role="tab"
                aria-selected={currentTab === 'sso'}
                onClick={() => setUserSelectedTab('sso')}
                className={cn(
                  'flex flex-1 items-center justify-center gap-2 rounded-md py-2 text-xs transition duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
                  currentTab === 'sso'
                    ? 'bg-primary font-semibold text-primary shadow-xs'
                    : 'font-medium text-tertiary hover:text-primary',
                )}
              >
                <LogIn04 className="size-3.5" /> Organization
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={currentTab === 'token'}
                onClick={() => setUserSelectedTab('token')}
                className={cn(
                  'flex flex-1 items-center justify-center gap-2 rounded-md py-2 text-xs transition duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
                  currentTab === 'token'
                    ? 'bg-primary font-semibold text-primary shadow-xs'
                    : 'font-medium text-tertiary hover:text-primary',
                )}
              >
                <Key01 className="size-3.5" /> API Token
              </button>
            </div>

            {currentTab === 'sso' ? (
              <div role="tabpanel" aria-label="Organization" className="space-y-4 pt-1 animate-fade-in">
                <p className="text-center text-xs text-tertiary">
                  Sign in through your enterprise identity provider via OIDC.
                </p>
                <a
                  href="/api/auth/oidc/login"
                  className="inline-flex w-full select-none items-center justify-center gap-2 rounded-lg bg-brand-solid px-3.5 py-2.5 text-sm font-semibold text-white shadow-xs transition duration-150 hover:bg-brand-solid_hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2"
                >
                  <LogIn04 className="size-4" /> Sign in with your organization
                </a>
              </div>
            ) : (
              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  void connect(token)
                }}
                className="space-y-4 pt-1 animate-fade-in"
                role="tabpanel"
                aria-label="API Token"
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
                      autoFocus
                    />
                    <button
                      type="button"
                      onClick={() => setShowToken((prev) => !prev)}
                      aria-label={showToken ? 'Hide token' : 'Show token'}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-1 text-tertiary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                    >
                      {showToken ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                    </button>
                  </div>
                </Field>
                <p id="api-token-hint" className="text-[11px] text-tertiary">
                  {token.trim() ? 'The token is sent only to this server.' : 'Paste a token to enable this development sign-in.'}
                </p>
                <Button
                  variant="brand"
                  type="submit"
                  loading={connecting}
                  disabled={!token.trim()}
                  className="w-full disabled:cursor-not-allowed"
                >
                  <Key01 className="size-4" /> Connect with API Token
                </Button>
              </form>
            )}
          </div>
        </Card>
      )}
    </Center>
  )
}

function Center({ children }: { children: ReactNode }) {
  return <div className="flex min-h-screen flex-col items-center justify-center bg-primary px-4 py-12">{children}</div>
}
