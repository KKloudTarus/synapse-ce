import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { RuleTargetPicker, type RuleTargetPage } from './RuleTargetPicker'

afterEach(() => {
  vi.useRealTimers()
})

function deferred() {
  let resolve: (page: RuleTargetPage) => void = () => {}
  const promise = new Promise<RuleTargetPage>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

describe('RuleTargetPicker', () => {
  it('keeps the latest search and discards the slower earlier one', async () => {
    vi.useFakeTimers()
    const first = deferred()
    const search = vi.fn((query: string) => {
      if (query === 'a') return first.promise
      return Promise.resolve({ items: [{ id: 'ops', label: 'Ops' }] })
    })
    render(<RuleTargetPicker label="Teams" selected={[]} onChange={vi.fn()} search={search} />)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(200)
    })
    fireEvent.change(screen.getByRole('searchbox', { name: 'Teams' }), { target: { value: 'a' } })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(200)
    })
    fireEvent.change(screen.getByRole('searchbox', { name: 'Teams' }), { target: { value: 'ab' } })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(200)
    })
    await act(async () => {
      first.resolve({ items: [{ id: 'pay', label: 'Payments' }] })
    })
    expect(screen.queryByRole('option', { name: /Payments/ })).not.toBeInTheDocument()
    expect(screen.getByRole('option', { name: /Ops \(ops\)/ })).toBeInTheDocument()
  })

  it('appends the next page and distinguishes duplicate names by id', async () => {
    vi.useFakeTimers()
    const search = vi
      .fn()
      .mockResolvedValueOnce({
        items: [{ id: 'alex-1', label: 'Alex' }],
        next: 'page-2',
      })
      .mockResolvedValueOnce({
        items: [{ id: 'alex-2', label: 'Alex' }],
      })
    const onChange = vi.fn()
    render(<RuleTargetPicker label="Engagements" selected={[]} onChange={onChange} search={search} />)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(200)
    })
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(screen.getByRole('option', { name: 'Alex (alex-2)' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Alex (alex-1)' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Alex (alex-2)' }))
    expect(onChange).toHaveBeenCalledWith(['alex-2'])
  })

  it('moves through results with the arrow keys', async () => {
    vi.useFakeTimers()
    const search = vi.fn().mockResolvedValue({
      items: [
        { id: 'a', label: 'Alpha' },
        { id: 'b', label: 'Beta' },
      ],
    })
    render(<RuleTargetPicker label="Engagements" selected={[]} onChange={vi.fn()} search={search} />)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(200)
    })
    const list = screen.getByRole('listbox', { name: 'Engagements results' })
    list.focus()
    fireEvent.keyDown(list, { key: 'ArrowDown' })
    expect(screen.getByRole('option', { name: 'Alpha (a)' }).querySelector('button')).toHaveFocus()
    fireEvent.keyDown(list, { key: 'ArrowDown' })
    expect(screen.getByRole('option', { name: 'Beta (b)' }).querySelector('button')).toHaveFocus()
  })

  it('keeps a saved id that the directory no longer returns and warns when it is archived', async () => {
    vi.useFakeTimers()
    const search = vi.fn().mockResolvedValue({
      items: [{ id: 'old', label: 'Old team', archived: true }],
    })
    const onChange = vi.fn()
    render(<RuleTargetPicker label="Teams" selected={['old', 'ghost']} onChange={onChange} search={search} />)
    expect(screen.getAllByText('Not in the current directory')).toHaveLength(2)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(200)
    })
    expect(screen.getByText('Archived')).toBeInTheDocument()
    expect(screen.getAllByText('Not in the current directory')).toHaveLength(1)
    fireEvent.click(screen.getByRole('button', { name: 'Remove ghost' }))
    expect(onChange).toHaveBeenCalledWith(['old'])
  })

  it('reports a denied search without clearing the current selection', async () => {
    vi.useFakeTimers()
    const search = vi.fn().mockRejectedValue(Object.assign(new Error('forbidden'), { status: 403 }))
    render(<RuleTargetPicker label="Teams" selected={['kept']} onChange={vi.fn()} search={search} />)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(200)
    })
    expect(screen.getByRole('alert')).toHaveTextContent('You do not have permission to search these records')
    expect(screen.getByText('kept')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove kept' })).toBeInTheDocument()
  })
})
