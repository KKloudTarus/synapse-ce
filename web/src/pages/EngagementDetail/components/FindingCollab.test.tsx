import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { CommentsPanel } from './FindingCollab'

const api = vi.hoisted(() => ({
  findingComments: vi.fn(),
  addFindingComment: vi.fn(),
  userChoices: vi.fn(),
}))

vi.mock('../../../lib/api', () => ({ ApiError: class ApiError extends Error {}, api }))

const users = Array.from({ length: 11 }, (_, index) => ({ id: `user-${index + 1}`, name: `User ${index + 1}` }))

function renderComments() {
  api.findingComments.mockResolvedValue([])
  api.userChoices.mockResolvedValue({ items: users, next: undefined })
  return render(<CommentsPanel engagementId="engagement" findingId="finding" />)
}

afterEach(() => vi.resetAllMocks())

describe('CommentsPanel mentions', () => {
  it('selects canonical IDs, caps at ten, removes one, and clears after a successful post', async () => {
    api.addFindingComment.mockResolvedValue({})
    const user = userEvent.setup()
    renderComments()
    await screen.findByText('User 1')
    expect(api.userChoices).toHaveBeenCalledWith('', '', undefined, expect.any(AbortSignal), 'mention')
    for (const candidate of users.slice(0, 10)) {
      await user.click(screen.getByRole('button', { name: new RegExp(`${candidate.name} \\(${candidate.id}\\)`) }))
    }
    const search = screen.getByLabelText('Search eligible users to mention')
    expect(search).toBeDisabled()
    expect(screen.getAllByRole('button', { name: /^Remove User/ })).toHaveLength(10)
    await user.click(screen.getByRole('button', { name: 'Remove User 1' }))
    expect(search).not.toBeDisabled()
    await user.type(screen.getByLabelText('New comment'), 'draft')
    await user.click(screen.getByRole('button', { name: 'Post' }))
    await waitFor(() => expect(api.addFindingComment).toHaveBeenCalledWith('engagement', 'finding', 'draft', users.slice(1, 10).map((candidate) => candidate.id)))
    expect(screen.getByLabelText('New comment')).toHaveValue('')
    expect(screen.queryByRole('button', { name: /^Remove User/ })).not.toBeInTheDocument()
  })

  it('preserves the body and selected IDs after a failed post', async () => {
    api.addFindingComment.mockRejectedValue(new Error('offline'))
    const user = userEvent.setup()
    renderComments()
    await screen.findByText('User 1')
    await user.click(screen.getByRole('button', { name: /User 1 \(user-1\)/ }))
    await user.type(screen.getByLabelText('New comment'), 'retry me')
    await user.click(screen.getByRole('button', { name: 'Post' }))
    expect(await screen.findByText('offline')).toBeInTheDocument()
    expect(screen.getByLabelText('New comment')).toHaveValue('retry me')
    expect(screen.getByRole('button', { name: 'Remove User 1' })).toBeInTheDocument()
  })

  it('shows an empty mention search and gives concurrent panels distinct input labels', async () => {
    api.findingComments.mockResolvedValue([])
    api.userChoices.mockResolvedValue({ items: [], next: undefined })
    render(<><CommentsPanel engagementId="engagement" findingId="first" /><CommentsPanel engagementId="engagement" findingId="second" /></>)
    await waitFor(() => expect(api.userChoices).toHaveBeenCalledTimes(2))
    expect(screen.getAllByText('No eligible users found.')).toHaveLength(2)
    const searches = screen.getAllByLabelText('Search eligible users to mention')
    expect(searches[0].id).not.toBe(searches[1].id)
    expect(document.querySelectorAll(`label[for="${searches[0].id}"]`)).toHaveLength(1)
  })

  it('does not let a late post clear the draft and mentions for a different finding', async () => {
    let finishPost!: (value: object) => void
    api.addFindingComment.mockImplementation(() => new Promise((resolve) => { finishPost = resolve }))
    const user = userEvent.setup()
    const view = renderComments()
    await screen.findByText('User 1')
    await user.click(screen.getByRole('button', { name: /User 1 \(user-1\)/ }))
    await user.type(screen.getByLabelText('New comment'), 'first finding')
    await user.click(screen.getByRole('button', { name: 'Post' }))
    expect(screen.getByLabelText('New comment')).toBeDisabled()
    view.rerender(<CommentsPanel engagementId="engagement" findingId="second" />)
    expect(screen.getByLabelText('New comment')).toHaveValue('')
    expect(screen.queryByRole('button', { name: 'Remove User 1' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /User 2 \(user-2\)/ }))
    await user.type(screen.getByLabelText('New comment'), 'second finding draft')
    await act(async () => { finishPost({}) })
    expect(screen.getByLabelText('New comment')).toHaveValue('second finding draft')
    expect(screen.getByRole('button', { name: 'Remove User 2' })).toBeInTheDocument()
    expect(api.addFindingComment).toHaveBeenCalledWith('engagement', 'finding', 'first finding', ['user-1'])
  })

  it('keeps a saved comment when an older GET resolves after the refreshed thread', async () => {
    let finishInitial!: (value: object[]) => void
    const saved = { id: 'saved', author: 'Alice', body: 'new comment', createdAt: null }
    api.findingComments.mockImplementationOnce(() => new Promise((resolve) => { finishInitial = resolve })).mockResolvedValue([saved])
    api.userChoices.mockResolvedValue({ items: [], next: undefined })
    api.addFindingComment.mockResolvedValue(saved)
    const user = userEvent.setup()
    render(<CommentsPanel engagementId="engagement" findingId="finding" />)
    await user.type(screen.getByLabelText('New comment'), 'new comment')
    await user.click(screen.getByRole('button', { name: 'Post' }))
    expect(await screen.findByText('new comment')).toBeInTheDocument()
    await act(async () => { finishInitial([]) })
    expect(screen.getByText('new comment')).toBeInTheDocument()
  })

  it('shows a load error and retry while preserving a successfully saved comment', async () => {
    const saved = { id: 'saved', author: 'Alice', body: 'saved despite refresh failure', createdAt: null }
    api.findingComments.mockResolvedValueOnce([]).mockRejectedValueOnce(new Error('refresh unavailable')).mockResolvedValue([saved])
    api.userChoices.mockResolvedValue({ items: [], next: undefined })
    api.addFindingComment.mockResolvedValue(saved)
    const user = userEvent.setup()
    render(<CommentsPanel engagementId="engagement" findingId="finding" />)
    await screen.findByText('No comments yet.')
    await user.type(screen.getByLabelText('New comment'), saved.body)
    await user.click(screen.getByRole('button', { name: 'Post' }))
    expect(await screen.findByText('Could not load comments: refresh unavailable')).toBeInTheDocument()
    expect(screen.getByText(saved.body)).toBeInTheDocument()
    expect(screen.queryByText('No comments yet.')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry loading comments' }))
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
    expect(screen.getAllByText(saved.body)).toHaveLength(1)
  })

  it('renders legacy comment bodies as plain text', async () => {
    api.findingComments.mockResolvedValue([{ id: 'legacy', author: 'Alice', body: '<img src=x onerror=alert(1)>', createdAt: null }])
    api.userChoices.mockResolvedValue({ items: [], next: undefined })
    render(<CommentsPanel engagementId="engagement" findingId="finding" />)
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
  })
})
