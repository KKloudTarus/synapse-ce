import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../../lib/api'
import { EvidenceBadge } from './ScanBadges'

vi.mock('../../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../../lib/api')>('../../../lib/api')
  return { ...actual, api: { evidence: vi.fn() } }
})

describe('EvidenceBadge', () => {
  beforeEach(() => vi.resetAllMocks())

  it('states the chain is verified when it is', async () => {
    vi.mocked(api.evidence).mockResolvedValue({ intact: true, verified: 12, head: 'abc', attestation: { key_id: 'k1', algorithm: 'ed25519' } })
    render(<EvidenceBadge engagementId="eng-1" />)

    expect(await screen.findByText('Evidence verified')).toBeInTheDocument()
  })

  it('states the chain is tampered when it is broken', async () => {
    vi.mocked(api.evidence).mockResolvedValue({ intact: false, verified: 12, head: 'abc' })
    render(<EvidenceBadge engagementId="eng-1" />)

    expect(await screen.findByText('Evidence tampered')).toBeInTheDocument()
  })

  // Rendering nothing on failure let an unreachable evidence service look exactly like an
  // engagement with a clean chain, because a reader takes the absence of a tamper badge as the
  // absence of tampering.
  it('says the chain is unchecked when the check fails, rather than rendering nothing', async () => {
    vi.mocked(api.evidence).mockRejectedValue(new Error('evidence service unavailable'))
    render(<EvidenceBadge engagementId="eng-1" />)

    const badge = await screen.findByText('Evidence unchecked')
    expect(badge).toBeInTheDocument()
    expect(screen.queryByText('Evidence verified')).not.toBeInTheDocument()
    // The label must not be mistaken for a verdict on the chain.
    expect(badge.parentElement?.getAttribute('title')).toMatch(/not a statement that the chain is intact/)
  })

  // A ledger that exists but records nothing is a real "nothing yet" answer and stays quiet.
  it('renders nothing when there is no evidence recorded yet', async () => {
    vi.mocked(api.evidence).mockResolvedValue(null)
    const { container } = render(<EvidenceBadge engagementId="eng-1" />)

    await vi.waitFor(() => expect(api.evidence).toHaveBeenCalled())
    expect(container.textContent).toBe('')
  })
})
