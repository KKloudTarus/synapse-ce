import { useState, type ReactNode } from 'react'
import { Key01, Loading01, ShieldTick } from '@untitledui/icons'
import { useAuth } from '../auth/AuthContext'
import { Button } from '@/components/base/buttons/button'
import { Input } from '@/components/base/input/input'
import { ErrorState } from '../components/ui'
import logoFull from '../assets/logo-full-dark.png'

export function Connect() {
  const { phase, aup, error, connecting, connect, acceptAup, logout } = useAuth()
  const [token, setToken] = useState('')
  const [accepting, setAccepting] = useState(false)

  if (phase === 'connecting') {
    return (
      <Center>
        <Loading01 className="size-6 animate-spin text-brand" />
        <p className="mt-3 text-sm text-tertiary">Restoring session…</p>
      </Center>
    )
  }

  return (
    <Center>
      {phase === 'need-aup' && aup ? (
        <div className="w-full max-w-lg rounded-xl border border-secondary bg-primary p-6 shadow-md animate-fade-in">
          <div className="mb-6 flex flex-col items-center gap-2 text-center">
            <img src={logoFull} alt="Synapse" className="h-14 w-auto object-contain" />
            <p className="text-xs text-secondary">Security &amp; Pentest Operations</p>
          </div>
          <h2 className="text-base font-semibold text-primary">Acceptable Use Policy</h2>
          <p className="mt-3 whitespace-pre-line text-sm leading-relaxed text-secondary">{aup.text}</p>
          <div className="mt-6 flex items-center justify-between gap-3">
            <button
              type="button"
              onClick={logout}
              className="text-xs text-tertiary underline-offset-2 hover:text-primary hover:underline"
            >
              Use a different token
            </button>
            <Button
              size="md"
              color="primary"
              isLoading={accepting}
              iconLeading={ShieldTick}
              onClick={async () => {
                setAccepting(true)
                try {
                  await acceptAup()
                } finally {
                  setAccepting(false)
                }
              }}
            >
              Accept &amp; continue
            </Button>
          </div>
          <p className="mt-4 text-center text-[11px] text-quaternary">Policy version {aup.version}</p>
        </div>
      ) : (
        <div className="w-full max-w-sm rounded-xl border border-secondary bg-primary p-6 shadow-md animate-fade-in">
          <div className="mb-6 flex flex-col items-center gap-2 text-center">
            <img src={logoFull} alt="Synapse" className="h-14 w-auto object-contain" />
            <p className="text-xs text-secondary">Security &amp; Pentest Operations</p>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault()
              connect(token)
            }}
            className="space-y-4"
          >
            <Input
              label="API token"
              type="password"
              autoFocus
              value={token}
              onChange={setToken}
              placeholder="API Token"
              icon={Key01}
              size="md"
              aria-label="API token"
              className="w-full"
            />

            {error && <ErrorState message={error} />}

            <Button
              size="md"
              color="primary"
              type="submit"
              isLoading={connecting}
              className="w-full mt-3"
            >
              Connect
            </Button>

            <p className="text-center text-xs text-quaternary">
              Enter your team or personal API token to authenticate
            </p>
          </form>
        </div>
      )}
    </Center>
  )
}

function Center({ children }: { children: ReactNode }) {
  return <div className="flex min-h-screen flex-col items-center justify-center bg-primary px-4 py-12">{children}</div>
}
