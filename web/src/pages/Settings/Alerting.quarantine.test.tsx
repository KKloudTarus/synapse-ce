import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { QuarantinedSources } from './Alerting'

vi.mock('../../lib/api', () => ({
  api: { notificationSourceFailurePage: vi.fn() },
  AlertNotEnabledError: class AlertNotEnabledError extends Error {},
  ApiError: class ApiError extends Error {},
}))

describe('quarantined notification sources', () => {
  it('shows the safe reason and source identity in delivery history', async () => {
    vi.mocked(api.notificationSourceFailurePage).mockResolvedValue({
      items: [{
        source_kind: 'scan_job', source_id: 'scan-1', event_type: 'scan.completed',
        occurred_at: '2026-09-29T07:00:00Z', processed_at: '2026-09-29T07:01:00Z',
        failed_reason: 'event_data_too_large',
      }],
    })
    render(<QuarantinedSources event="all" from="" to="" />)
    expect(await screen.findByText('scan.completed')).toBeInTheDocument()
    expect(screen.getByText('scan_job: scan-1')).toBeInTheDocument()
    expect(screen.getByText('Event data exceeds 16 KiB')).toBeInTheDocument()
    expect(api.notificationSourceFailurePage).toHaveBeenCalledWith({
      event_type: undefined, from: undefined, to: undefined, offset: 0,
    })
  })
})
