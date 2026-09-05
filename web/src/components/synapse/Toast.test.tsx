import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider, useToast } from './Toast'

function Harness() {
  const { notify } = useToast()
  return (
    <div>
      <button type="button" onClick={() => notify('Engagement is now archived.', 'success')}>
        succeed
      </button>
      <button type="button" onClick={() => notify('Transition failed', 'error')}>
        fail
      </button>
      <button type="button" onClick={() => notify('   ')}>
        blank
      </button>
    </div>
  )
}

const click = (name: string) => fireEvent.click(screen.getByRole('button', { name }))

describe('ToastProvider', () => {
  afterEach(() => vi.useRealTimers())

  it('announces an outcome in a polite live region', () => {
    render(
      <ToastProvider>
        <Harness />
      </ToastProvider>,
    )
    click('succeed')

    const region = screen.getByLabelText('Notifications')
    expect(region).toHaveAttribute('aria-live', 'polite')
    expect(screen.getByRole('status')).toHaveTextContent('Engagement is now archived.')
  })

  it('auto-expires a success toast but keeps an error until dismissed', () => {
    vi.useFakeTimers()
    render(
      <ToastProvider ttlMs={1000}>
        <Harness />
      </ToastProvider>,
    )
    click('succeed')
    click('fail')

    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('Transition failed')

    act(() => {
      vi.advanceTimersByTime(1200)
    })
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(screen.getByRole('alert')).toBeInTheDocument()

    click('Dismiss notification: Transition failed')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('ignores a blank message', () => {
    render(
      <ToastProvider>
        <Harness />
      </ToastProvider>,
    )
    click('blank')
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('degrades to a no-op outside a provider', () => {
    render(<Harness />)
    click('succeed')
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })
})
