import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider, useAuth } from './AuthContext'
import { Connect } from '../pages/Connect'
import { setCSRFToken, setToken, setUnauthorizedHandler } from '../lib/api'

const PENDING_AUP = { accepted: false, version: 'v1', text: 'Use responsibly.' }

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((res) => { resolve = res })
  return { promise, resolve }
}

function PhaseProbe() {
  const { phase } = useAuth()
  return <output data-testid="phase">{phase}</output>
}

const phase = () => screen.getByTestId('phase').textContent

beforeEach(() => {
  sessionStorage.clear()
  setToken('')
  setCSRFToken('')
  setUnauthorizedHandler(() => {})
})

afterEach(() => {
  vi.unstubAllGlobals()
  setToken('')
  setCSRFToken('')
  setUnauthorizedHandler(() => {})
})

describe('AuthProvider with the real API client', () => {
  it('keeps a newly connected token when a late old-token request is rejected, then clears a current rejected token', async () => {
    sessionStorage.setItem('synapse.token', 'old-token')
    const lateOldResponse = deferred<Response>()
    let oldAupRequests = 0

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input)
      const headers = init?.headers as Record<string, string> | undefined
      const authorization = headers?.authorization

      if (url === '/api/auth/session') return respond(200, { authenticated: false })
      if (url === '/api/v1/aup' && authorization === 'Bearer old-token') {
        oldAupRequests++
        if (oldAupRequests === 1) {
          return respond(503, {
            error: 'authentication temporarily unavailable',
            code: 'authentication_unavailable',
            request_id: 'old-503',
            retryable: true,
          })
        }
        return lateOldResponse.promise
      }
      if (url === '/api/v1/aup' && authorization === 'Bearer new-token') {
        return respond(200, PENDING_AUP)
      }
      if (url === '/api/v1/aup/accept' && authorization === 'Bearer new-token') {
        return respond(401, { error: 'revoked', code: 'authentication_invalid' })
      }
      throw new Error(`unexpected request: ${url} ${authorization ?? 'without authorization'}`)
    })
    vi.stubGlobal('fetch', fetchMock)

    render(<AuthProvider><PhaseProbe /><Connect /></AuthProvider>)

    fireEvent.click(await screen.findByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(oldAupRequests).toBe(2))

    fireEvent.change(screen.getByLabelText('API token'), { target: { value: 'new-token' } })
    fireEvent.submit(screen.getByLabelText('API token').closest('form')!)
    await waitFor(() => expect(phase()).toBe('need-aup'))
    expect(sessionStorage.getItem('synapse.token')).toBe('new-token')

    await act(async () => {
      lateOldResponse.resolve(respond(401, { error: 'old token revoked', code: 'authentication_invalid' }))
      await lateOldResponse.promise
    })
    expect(phase()).toBe('need-aup')
    expect(sessionStorage.getItem('synapse.token')).toBe('new-token')
    expect(screen.queryByText('Invalid API token.')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Accept & continue/i }))
    await waitFor(() => expect(phase()).toBe('unauthenticated'))
    expect(sessionStorage.getItem('synapse.token')).toBeNull()
    expect(await screen.findByText('Invalid API token.')).toBeInTheDocument()
  })
})
