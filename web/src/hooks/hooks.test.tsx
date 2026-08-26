import { act, render, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useFetch } from './useFetch'
import { usePolling } from './usePolling'

describe('usePolling', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  // Regression: `fetcher` used to be in the callback deps. Callers pass an inline
  // arrow, so every completed poll produced a new identity, re-ran the subscribe
  // effect, and refetched immediately — a request storm that ignored `interval`.
  it('respects the interval when the fetcher identity changes every render', async () => {
    const calls = { count: 0 }

    function Probe() {
      const { data } = usePolling(
        () => {
          calls.count += 1
          return Promise.resolve(calls.count)
        },
        { interval: 1000 },
      )
      return <span>{data ?? 'none'}</span>
    }

    render(<Probe />)

    await waitFor(() => expect(calls.count).toBe(1))

    // Let several renders settle without advancing the clock past the interval.
    await act(async () => {
      await Promise.resolve()
    })
    expect(calls.count).toBe(1)

    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    await waitFor(() => expect(calls.count).toBe(2))
    expect(calls.count).toBeLessThan(4)
  })

  it('calls the latest fetcher without resubscribing', async () => {
    const seen: string[] = []
    let rerender: (v: string) => void = () => {}

    function Probe() {
      const [token, setToken] = useState('a')
      rerender = setToken
      usePolling(
        () => {
          seen.push(token)
          return Promise.resolve(token)
        },
        { interval: 1000 },
      )
      return null
    }

    render(<Probe />)
    await waitFor(() => expect(seen).toEqual(['a']))

    await act(async () => {
      rerender('b')
    })
    // Changing the fetcher must not trigger an immediate extra fetch.
    expect(seen).toEqual(['a'])

    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    await waitFor(() => expect(seen).toEqual(['a', 'b']))
  })
})

describe('useFetch', () => {
  // Regression: refetch() discarded the cleanup returned by execute(), so a
  // manual refetch in flight at unmount was never aborted.
  it('aborts an in-flight manual refetch on unmount', async () => {
    const signals: AbortSignal[] = []

    function Probe() {
      const { refetch } = useFetch(
        (signal) => {
          signals.push(signal)
          return new Promise<string>(() => {})
        },
        { deps: [] },
      )
      return (
        <button type="button" onClick={refetch}>
          refetch
        </button>
      )
    }

    const { getByRole, unmount } = render(<Probe />)
    await waitFor(() => expect(signals.length).toBe(1))

    await act(async () => {
      getByRole('button').click()
    })
    await waitFor(() => expect(signals.length).toBe(2))
    expect(signals[1].aborted).toBe(false)

    unmount()
    expect(signals[1].aborted).toBe(true)
  })
})
