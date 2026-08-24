import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Finding } from '../../lib/types'
import { FindingsTab } from './FindingsTab'

vi.mock('../../lib/api', () => ({
  ApiError: class ApiError extends Error {
    status = 500
  },
  api: {
    addFindingComment: vi.fn().mockResolvedValue(undefined),
    createFinding: vi.fn().mockResolvedValue(undefined),
    findingComments: vi.fn().mockResolvedValue([]),
    findingRetests: vi.fn().mockResolvedValue([]),
    judgments: vi.fn().mockResolvedValue([]),
    recordRetest: vi.fn().mockResolvedValue(undefined),
    setFindingAssignee: vi.fn().mockResolvedValue(undefined),
    updateFindingStatus: vi.fn().mockResolvedValue(undefined),
    verifyFinding: vi.fn().mockResolvedValue(undefined),
    writeups: vi.fn().mockResolvedValue([]),
  },
}))

function finding(id: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    engagementId: 'eng-1',
    title: `Finding ${id}`,
    description: '',
    severity: 'high',
    cvssVector: '',
    cwe: 'CWE-79',
    status: 'open',
    dedupKey: id,
    kev: false,
    riskScore: 10,
    class: 'third_party',
    scope: '',
    reachability: '',
    impact: '',
    priority: 1,
    assignee: '',
    version: 1,
    kind: 'sca',
    evidenceScore: 0,
    proposedBy: '',
    complianceControls: [],
    ...overrides,
  }
}

describe('FindingsTab', () => {
  // jsdom does not implement scrollIntoView, which the deep-link effect calls.
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn()
  })

  // Regression: the deep-link effect had the derived `rows` array in its deps and
  // unconditionally produced a new Set, so it re-rendered forever ("Maximum update
  // depth exceeded") whenever focusedFindingId was set.
  it('does not re-render forever when a finding is deep-linked', async () => {
    const findings = [finding('f-1'), finding('f-2'), finding('f-3')]
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    render(
      <MemoryRouter>
        <FindingsTab
          findings={findings}
          scan={null}
          engagementId="eng-1"
          filter="all"
          setFilter={() => {}}
          focusedFindingId="f-2"
          onUpdated={() => {}}
          onReload={() => {}}
        />
      </MemoryRouter>,
    )

    await waitFor(() => {
      expect(screen.getByText('Finding f-2')).toBeInTheDocument()
    })

    const depthError = errorSpy.mock.calls.find((call) =>
      call.some((arg) => typeof arg === 'string' && arg.includes('Maximum update depth')),
    )
    expect(depthError).toBeUndefined()
    errorSpy.mockRestore()
  })
})
