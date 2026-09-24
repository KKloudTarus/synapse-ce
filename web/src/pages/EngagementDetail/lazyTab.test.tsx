import { render, screen, waitFor } from '@testing-library/react'
import { Suspense } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { lazyTab } from './lazyTab'

const FLAG = 'synapse.engagement-chunk-reloaded'

function Panel() {
  return <div>tab content</div>
}

function renderTab(load: () => Promise<{ default: typeof Panel }>) {
  const Tab = lazyTab(load)
  return render(
    <Suspense fallback={<div>loading</div>}>
      <Tab />
    </Suspense>,
  )
}

describe('lazyTab', () => {
  let reload: ReturnType<typeof vi.fn>

  beforeEach(() => {
    sessionStorage.clear()
    reload = vi.fn()
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...window.location, reload },
    })
  })
  afterEach(() => {
    sessionStorage.clear()
    vi.restoreAllMocks()
  })

  it('renders the chunk and reloads nothing when the import succeeds', async () => {
    renderTab(async () => ({ default: Panel }))

    expect(await screen.findByText('tab content')).toBeInTheDocument()
    expect(reload).not.toHaveBeenCalled()
  })

  // A transient network failure should not cost the operator the tab.
  it('retries the import once before giving up', async () => {
    const load = vi.fn()
      .mockRejectedValueOnce(new Error('chunk fetch failed'))
      .mockResolvedValue({ default: Panel })
    renderTab(load)

    expect(await screen.findByText('tab content')).toBeInTheDocument()
    expect(load).toHaveBeenCalledTimes(2)
    expect(reload).not.toHaveBeenCalled()
  })

  // After a deploy rotates the hashed chunk names, React.lazy caches the rejection permanently, so
  // remounting never recovers. Reloading fetches the current index and its chunk names.
  it('reloads the page once when both attempts fail', async () => {
    const load = vi.fn().mockRejectedValue(new Error('chunk 404'))
    renderTab(load)

    await waitFor(() => expect(reload).toHaveBeenCalledTimes(1))
    expect(load).toHaveBeenCalledTimes(2)
    expect(sessionStorage.getItem(FLAG)).toBe('1')
  })

  // A chunk that is genuinely gone must not turn into a reload loop.
  it('does not reload again if a reload already happened', async () => {
    sessionStorage.setItem(FLAG, '1')
    renderTab(vi.fn().mockRejectedValue(new Error('chunk 404')))

    await waitFor(() => expect(sessionStorage.getItem(FLAG)).toBe('1'))
    expect(reload).not.toHaveBeenCalled()
  })

  it('clears the flag after a successful load so a later deploy can recover again', async () => {
    sessionStorage.setItem(FLAG, '1')
    renderTab(async () => ({ default: Panel }))

    expect(await screen.findByText('tab content')).toBeInTheDocument()
    expect(sessionStorage.getItem(FLAG)).toBeNull()
  })

  it('survives storage being unavailable', async () => {
    const getItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('storage blocked')
    })
    const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('storage blocked')
    })
    renderTab(vi.fn().mockRejectedValue(new Error('chunk 404')))

    // Storage throwing must not stop the recovery path, and must not throw out of the loader.
    await waitFor(() => expect(reload).toHaveBeenCalledTimes(1))
    getItem.mockRestore()
    setItem.mockRestore()
  })
})
