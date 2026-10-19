import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { Integration } from '../../lib/types'
import { JiraInboundSettings } from './JiraInboundSettings'

vi.mock('../../lib/api', () => ({ api: { configureJiraInboundWebhook: vi.fn() } }))
const integration = { id: 'jira', name: 'Personal lab', enabled: true, connectionRevision: 1, credentialRevision: 1 } as Integration
beforeEach(() => vi.resetAllMocks())

it('keeps credentials unavailable without administrator authority', () => {
  render(<JiraInboundSettings integrations={[integration]} canAdmin={false} />)
  expect(screen.getByText(/Only a tenant administrator/)).toBeInTheDocument()
  expect(screen.queryByLabelText('Webhook secret')).not.toBeInTheDocument()
  expect(api.configureJiraInboundWebhook).not.toHaveBeenCalled()
})

it('has an empty state before a connection exists', () => {
  render(<JiraInboundSettings integrations={[]} canAdmin />)
  expect(screen.getByText(/Connect and enable Jira/)).toBeInTheDocument()
})

it('clears the submitted secret and hides the returned path', async () => {
  let complete!: (value: { path: string; version: number; rotated: boolean }) => void
  vi.mocked(api.configureJiraInboundWebhook).mockImplementation(() => new Promise((resolve) => { complete = resolve }))
  render(<JiraInboundSettings integrations={[integration]} canAdmin />)
  fireEvent.change(screen.getByLabelText('Webhook secret'), { target: { value: 'a'.repeat(32) } })
  fireEvent.click(screen.getByRole('button', { name: 'Configure or rotate webhook' }))
  expect(screen.getByRole('button', { name: 'Configuring webhook…' })).toBeDisabled()
  complete({ path: '/api/v1/hooks/opaque-private-path', version: 1, rotated: false })
  await screen.findByText(/Signed webhook configured/)
  expect(screen.getByLabelText('Webhook secret')).toHaveValue('')
  expect(screen.queryByText('/api/v1/hooks/opaque-private-path')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Show webhook path' }))
  expect(screen.getByText('/api/v1/hooks/opaque-private-path')).toBeInTheDocument()
  expect(api.configureJiraInboundWebhook).toHaveBeenCalledTimes(1)
})

it('shows a safe error and allows retry', async () => {
  vi.mocked(api.configureJiraInboundWebhook).mockRejectedValue(new Error('Signed webhooks are unavailable for this server.'))
  render(<JiraInboundSettings integrations={[integration]} canAdmin />)
  fireEvent.change(screen.getByLabelText('Webhook secret'), { target: { value: 'b'.repeat(32) } })
  fireEvent.click(screen.getByRole('button', { name: 'Configure or rotate webhook' }))
  await screen.findByText('Signed webhooks are unavailable for this server.')
  await waitFor(() => expect(screen.getByRole('button', { name: 'Configure or rotate webhook' })).toBeEnabled())
})
