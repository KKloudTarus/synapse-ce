import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { Finding, SLAAssessment, SLAEvent, SLAView } from '../../lib/types'
import { SLATab } from './SLATab'

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api')
  return {
    ...actual,
    api: { slas: vi.fn(), transitionSLA: vi.fn(), slaEvents: vi.fn(), slaAssessments: vi.fn() },
  }
})

const assessment: SLAAssessment = {
  tenantId: 'tenant-1',
  id: 'sla-assessment-1',
  engagementId: 'engagement-1',
  findingId: 'finding-1',
  sourceRiskAssessmentId: 'risk-1',
  inputs: {
    severity: 'high', cvssScore: 8.1, kev: false, epss: 0.2, publicPoC: false,
    activeExploitation: false, criticality: 'high', exposure: 'external', feasibility: 'patch_available',
  },
  result: {
    tier: 'high', score: 71, mitigateBy: '2026-09-20T07:00:00Z', remediateBy: '2026-10-04T07:00:00Z',
    reason: 'External exposure with a patch available.', computedAt: '2026-09-06T07:00:00Z', configVersion: 'sla-v1',
    breakdown: { severity: 30, exploitability: 12, threatIntel: 8, exposure: 15, criticality: 6, feasibility: 0, overrides: [] },
  },
  inputHash: 'a'.repeat(64),
  configHash: 'b'.repeat(64),
  previousAssessmentId: '',
  deadlineAnchorAt: '2026-09-06T07:00:00Z',
  assessedAt: '2026-09-06T07:00:00Z',
  createdAt: '2026-09-06T07:00:00Z',
}

const view: SLAView = {
  assessment,
  lifecycle: {
    tenantId: 'tenant-1', engagementId: 'engagement-1', findingId: 'finding-1', assessmentId: 'sla-assessment-1',
    status: 'open', version: 2, reason: '', compensatingControl: '', acceptedBy: '', acceptedAt: null,
    acceptanceExpiresAt: null, updatedBy: 'operator', updatedAt: '2026-09-06T07:00:00Z',
  },
  effectiveState: 'open',
  overdue: false,
  acceptanceExpired: false,
}

const secondView: SLAView = {
  ...view,
  assessment: { ...assessment, id: 'sla-assessment-2', findingId: 'finding-2' },
  lifecycle: { ...view.lifecycle, findingId: 'finding-2', assessmentId: 'sla-assessment-2' },
}

const findings = [
  { id: 'finding-1', title: 'Unauthenticated admin route' } as Finding,
  { id: 'finding-2', title: 'Secret in build log' } as Finding,
]

const events: SLAEvent[] = [
  {
    tenantId: 'tenant-1', id: 'sla-event-1', engagementId: 'engagement-1', findingId: 'finding-1',
    assessmentId: 'sla-assessment-1', from: 'open', to: 'accepted_risk', reason: 'Accepted until the gateway ships.',
    compensatingControl: 'WAF rule 4102', acceptanceExpiresAt: '2026-12-01T07:00:00Z', actor: 'reviewer@example.test',
    beforeVersion: 1, afterVersion: 2, at: '2026-09-07T07:00:00Z',
  },
]

function openTransitionPanel() {
  render(<SLATab engagementId="engagement-1" findings={findings} />)
  return screen.findAllByRole('button', { name: 'Transition' })
}

describe('SLATab decision record', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.slas).mockResolvedValue([view])
    vi.mocked(api.slaEvents).mockResolvedValue([])
    vi.mocked(api.slaAssessments).mockResolvedValue([])
  })

  it('shows the prior transition with its actor, reason, control, and expiry', async () => {
    vi.mocked(api.slaEvents).mockResolvedValue(events)
    const buttons = await openTransitionPanel()
    fireEvent.click(buttons[0])

    expect(await screen.findByText('Accepted until the gateway ships.')).toBeInTheDocument()
    expect(screen.getByText('by reviewer@example.test')).toBeInTheDocument()
    expect(screen.getByText(/Compensating control: WAF rule 4102/)).toBeInTheDocument()
    expect(screen.getByText(/Acceptance expires/)).toBeInTheDocument()
  })

  it('shows the deadline assessment behind the current tier', async () => {
    vi.mocked(api.slaAssessments).mockResolvedValue([assessment])
    const buttons = await openTransitionPanel()
    fireEvent.click(buttons[0])

    expect(await screen.findByText('External exposure with a patch available.')).toBeInTheDocument()
    // Scoped to the history section: the table header also reads "Mitigate by".
    const section = screen.getByRole('region', { name: 'Deadline assessments' })
    expect(within(section).getByText(/Mitigate by/)).toBeInTheDocument()
  })

  it('states an empty history rather than leaving the panel silent', async () => {
    const buttons = await openTransitionPanel()
    fireEvent.click(buttons[0])

    expect(await screen.findByText('No transitions recorded yet.')).toBeInTheDocument()
    expect(screen.getByText('No deadline assessments recorded yet.')).toBeInTheDocument()
  })

  // An outage on the history services must not read as an SLA nobody has acted on.
  it('surfaces a history outage instead of rendering it as no decisions', async () => {
    vi.mocked(api.slaEvents).mockRejectedValue(new Error('sla events unavailable'))
    const buttons = await openTransitionPanel()
    fireEvent.click(buttons[0])

    expect(await screen.findByText(/sla events unavailable/)).toBeInTheDocument()
    expect(screen.queryByText('No transitions recorded yet.')).not.toBeInTheDocument()
  })
})

describe('SLATab failure and identity handling', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.slaEvents).mockResolvedValue([])
    vi.mocked(api.slaAssessments).mockResolvedValue([])
  })

  // An initial list failure left `fetchedItems` null forever, and the null check ran before the
  // error check, so a failed SLA service rendered as a spinner that never resolved.
  it('surfaces an initial list failure instead of spinning forever', async () => {
    vi.mocked(api.slas).mockRejectedValue(new Error('sla service unavailable'))
    render(<SLATab engagementId="engagement-1" findings={findings} />)

    expect(await screen.findByText('sla service unavailable')).toBeInTheDocument()
    expect(screen.queryByText('Loading remediation SLAs…')).not.toBeInTheDocument()
  })

  // Dropping the assessments error would render an outage as "no deadline assessments recorded".
  it('surfaces a deadline-assessments outage in its own column', async () => {
    vi.mocked(api.slas).mockResolvedValue([view])
    vi.mocked(api.slaAssessments).mockRejectedValue(new Error('assessments unavailable'))
    render(<SLATab engagementId="engagement-1" findings={findings} />)
    fireEvent.click((await screen.findAllByRole('button', { name: 'Transition' }))[0])

    expect(await screen.findByText('assessments unavailable')).toBeInTheDocument()
    expect(screen.queryByText('No deadline assessments recorded yet.')).not.toBeInTheDocument()
  })

  // The panel is keyed on the finding. Without that, the previous finding's audit trail stays on
  // screen under the new finding's title, and a typed rationale is written against the wrong one.
  it('never shows one finding\'s history under another finding', async () => {
    vi.mocked(api.slas).mockResolvedValue([view, secondView])
    vi.mocked(api.slaEvents).mockImplementation(async (_engagementId: string, findingId: string) =>
      findingId === 'finding-1' ? events : new Promise(() => []) as never,
    )
    render(<SLATab engagementId="engagement-1" findings={findings} />)

    const buttons = await screen.findAllByRole('button', { name: 'Transition' })
    fireEvent.click(buttons[0])
    await screen.findByText('Accepted until the gateway ships.')

    // finding-2's history never resolves, so anything from finding-1 still on screen is stale.
    fireEvent.click(buttons[1])
    await screen.findByText('Transition: Secret in build log')
    await waitFor(() => {
      expect(screen.queryByText('Accepted until the gateway ships.')).not.toBeInTheDocument()
    })
  })

  it('clears a typed rationale when the selected finding changes', async () => {
    vi.mocked(api.slas).mockResolvedValue([view, secondView])
    render(<SLATab engagementId="engagement-1" findings={findings} />)

    const buttons = await screen.findAllByRole('button', { name: 'Transition' })
    fireEvent.click(buttons[0])
    const reason = await screen.findByPlaceholderText('Required audit rationale')
    fireEvent.change(reason, { target: { value: 'typed while looking at finding-1' } })

    fireEvent.click(buttons[1])
    await screen.findByText('Transition: Secret in build log')
    expect(screen.getByPlaceholderText('Required audit rationale')).toHaveValue('')
  })
})
