import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { UserPicker } from './UserPicker'

vi.mock('../../lib/api', () => ({ api: { userChoices: vi.fn() } }))

describe('UserPicker', () => {
  beforeEach(() => { vi.resetAllMocks() })

  it('searches the selected team server-side and keeps the chosen identity visible', async () => {
    vi.mocked(api.userChoices).mockResolvedValueOnce({ items: [{ id: 'user-1', name: 'Alex', role: 'consultant' }], next: 'user-1' })
      .mockResolvedValueOnce({ items: [{ id: 'user-2', name: 'Alex', role: 'reviewer' }], next: '' })
      .mockResolvedValueOnce({ items: [], next: '' })
    const onChange=vi.fn()
    const {rerender}=render(<UserPicker team="team-1" value="" onChange={onChange} />)
    fireEvent.click(await screen.findByRole('button',{name:'Alex (user-1)'}))
    expect(onChange).toHaveBeenCalledWith('user-1')
    rerender(<UserPicker team="team-1" value="user-1" onChange={onChange} />)
    expect(screen.getByText('Selected: Alex (user-1)')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('searchbox',{name:'Assignee'}),{target:{value:'Alex'}})
    await waitFor(()=>expect(api.userChoices).toHaveBeenLastCalledWith('team-1','Alex',undefined,expect.any(AbortSignal)))
  })

  it('requires a destination team before exposing a user search', () => {
    render(<UserPicker team="" value="" onChange={vi.fn()} />)
    expect(screen.getByRole('searchbox',{name:'Assignee'})).toBeDisabled()
  })
})
