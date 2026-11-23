import { render, screen } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { Authentication } from './Authentication'

const auth = vi.hoisted(() => ({ currentUser: { credentialKind: 'bootstrap' } }))
vi.mock('../auth/AuthContext', () => ({ useOptionalAuth: () => auth }))
vi.mock('../lib/api/identity', async (importOriginal) => ({
  ...await importOriginal<typeof import('../lib/api/identity')>(),
  identityApi: {
    connections: vi.fn().mockResolvedValue([]),
    policy: vi.fn().mockResolvedValue({ requirement: 'optional', version: 1 }),
    alerts: vi.fn().mockResolvedValue([]),
  },
}))

beforeEach(() => { auth.currentUser.credentialKind = 'bootstrap' })

it('gives the deployment operator a reachable initial organization setup form', async () => {
  render(<MemoryRouter><Authentication enabled /></MemoryRouter>)
  expect(await screen.findByLabelText('Target organization ID')).toBeInTheDocument()
})

it('does not offer cross-organization provisioning to a native organization administrator', async () => {
  auth.currentUser.credentialKind = 'enterprise_session'
  render(<MemoryRouter><Authentication enabled /></MemoryRouter>)
  await screen.findByRole('heading', { name: 'Administrator verification' })
  expect(screen.queryByLabelText('Target organization ID')).not.toBeInTheDocument()
})
