import { act, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ScanDebugEvent } from '../../../lib/types'
import { ScanDebugTimeline, TRACK_OPEN_KEY } from './ScanDebugTimeline'

function event(step: string, status: ScanDebugEvent['status'] = 'succeeded'): ScanDebugEvent {
  return {
    stage: 'scanning',
    step,
    status,
    message: '',
    tool: 'syft',
    counts: { processed: 3 },
    startedAt: '2026-09-01T00:00:00Z',
    finishedAt: '2026-09-01T00:00:02Z',
    durationMs: 1800,
    error: '',
  }
}

const track = () => screen.getByText('Pipeline Journey Track').closest('details') as HTMLDetailsElement

describe('ScanDebugTimeline', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('renders nothing before a scan has produced steps', () => {
    const { container } = render(<ScanDebugTimeline events={[]} running={false} />)
    expect(container).toBeEmptyDOMElement()
  })

  // Regression: the empty-state early return sat above useState/useEffect, which
  // React reports as "Internal React error: Expected static flag was missing".
  it('keeps the hook order stable when it goes from empty to populated', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { rerender } = render(<ScanDebugTimeline events={[]} running={false} />)
    rerender(<ScanDebugTimeline events={[event('acquire')]} running={true} scanStatus="running" />)
    rerender(<ScanDebugTimeline events={[]} running={false} />)

    const flagError = errorSpy.mock.calls.find((call) =>
      call.some((arg) => typeof arg === 'string' && arg.includes('Expected static flag')),
    )
    expect(flagError).toBeUndefined()
    errorSpy.mockRestore()
  })

  it('stays expanded while a scan is running', () => {
    render(<ScanDebugTimeline events={[event('acquire', 'running')]} running={true} scanStatus="running" />)
    expect(track().open).toBe(true)
  })

  it('collapses once the scan has succeeded', () => {
    render(<ScanDebugTimeline events={[event('acquire')]} running={false} scanStatus="succeeded" />)
    expect(track().open).toBe(false)
  })

  it('stays expanded on a failed scan, where the steps are the answer', () => {
    render(<ScanDebugTimeline events={[event('acquire', 'failed')]} running={false} scanStatus="failed" />)
    expect(track().open).toBe(true)
  })

  it('remembers the operator toggle across mounts', () => {
    const { unmount } = render(
      <ScanDebugTimeline events={[event('acquire')]} running={false} scanStatus="succeeded" />,
    )
    // jsdom flips `open` on a summary click but does not dispatch `toggle`,
    // which is the event the browser uses to report the new state.
    const details = track()
    details.open = true
    act(() => {
      details.dispatchEvent(new Event('toggle', { bubbles: false }))
    })
    expect(localStorage.getItem(TRACK_OPEN_KEY)).toBe('true')
    unmount()

    render(<ScanDebugTimeline events={[event('acquire')]} running={false} scanStatus="succeeded" />)
    expect(track().open).toBe(true)
  })
})
