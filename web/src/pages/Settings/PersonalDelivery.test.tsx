import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { PersonalDelivery } from './PersonalDelivery'

vi.mock('../../lib/api', async (original) => ({
  ...(await original<typeof import('../../lib/api')>()),
  api: {
    listPersonalDefaults: vi.fn(),
    savePersonalDefault: vi.fn(),
    listEngagements: vi.fn(),
    getEngagementNotificationSetting: vi.fn(),
    saveEngagementNotificationSetting: vi.fn(),
    userChoices: vi.fn(),
  },
}))

const events = [{ type: 'finding.ownership_changed', label: 'Finding ownership changed' }] as never

describe('personal delivery settings (#1415, #1418)', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() })
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.userChoices).mockResolvedValue({ items: [] } as never)
  })

  it('switches a tenant default with the revision it read', async () => {
    vi.mocked(api.listPersonalDefaults).mockResolvedValue([
      { event_type: 'finding.ownership_changed', channel: 'email', enabled: false, builtin: true, revision: 0 },
      { event_type: 'finding.ownership_changed', channel: 'slack', enabled: true, builtin: false, revision: 3 },
      { event_type: 'finding.ownership_changed', channel: 'teams', enabled: false, builtin: true, revision: 0 },
    ])
    vi.mocked(api.savePersonalDefault).mockResolvedValue({ event_type: 'finding.ownership_changed', channel: 'slack', enabled: false, builtin: false, revision: 4 })
    render(<PersonalDelivery canManage eventTypes={events} />)
    const slack = await screen.findByRole('checkbox', { name: 'Finding ownership changed by Slack DM' })
    expect(slack).toBeChecked()
    fireEvent.click(slack)
    await waitFor(() => expect(api.savePersonalDefault).toHaveBeenCalledWith({ event_type: 'finding.ownership_changed', channel: 'slack', enabled: false, revision: 3 }))
    await waitFor(() => expect(screen.getByRole('checkbox', { name: 'Finding ownership changed by Slack DM' })).not.toBeChecked())
  })

  it('is read-only without manage_integrations and absent without the inbox', async () => {
    vi.mocked(api.listPersonalDefaults).mockResolvedValue([{ event_type: 'finding.ownership_changed', channel: 'email', enabled: false, builtin: true, revision: 0 }])
    const { unmount } = render(<PersonalDelivery canManage={false} eventTypes={events} />)
    expect(await screen.findByRole('checkbox', { name: 'Finding ownership changed by Email' })).toBeDisabled()
    unmount()
    const { ApiError } = await import('../../lib/api')
    vi.mocked(api.listPersonalDefaults).mockRejectedValue(new ApiError(404, 'not found'))
    render(<PersonalDelivery canManage eventTypes={events} />)
    await waitFor(() => expect(api.listPersonalDefaults).toHaveBeenCalledTimes(2))
    expect(screen.queryByText('Personal delivery defaults')).not.toBeInTheDocument()
  })

  it('clears an engagement lead keeping the external override', async () => {
    vi.mocked(api.listPersonalDefaults).mockResolvedValue([])
    vi.mocked(api.listEngagements).mockResolvedValue([{ id: 'eng-1', name: 'Payments' }] as never)
    vi.mocked(api.getEngagementNotificationSetting).mockResolvedValue({ engagement_id: 'eng-1', external_notifications: 'signal', revision: 2, lead_user_id: 'ada' })
    vi.mocked(api.saveEngagementNotificationSetting).mockResolvedValue({ engagement_id: 'eng-1', external_notifications: 'signal', revision: 3 })
    render(<PersonalDelivery canManage eventTypes={events} />)
    fireEvent.click(await screen.findByRole('combobox', { name: 'Engagement' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Payments' }))
    // The picker names what is chosen: a lead, not an assignee.
    expect(await screen.findByRole('searchbox', { name: 'Lead' })).toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: 'Clear lead' }))
    await waitFor(() => expect(api.saveEngagementNotificationSetting).toHaveBeenCalledWith('eng-1', { external_notifications: 'signal', revision: 2, lead_user_id: '' }))
    expect(await screen.findByText('Engagement lead saved.')).toBeInTheDocument()
  })
})

describe('engagement lead saves stay with their engagement (#1415)', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() })
    vi.mocked(api.listPersonalDefaults).mockResolvedValue([])
    vi.mocked(api.userChoices).mockResolvedValue({ items: [] } as never)
    vi.mocked(api.listEngagements).mockResolvedValue([{ id: 'eng-a', name: 'Alpha' }, { id: 'eng-b', name: 'Bravo' }] as never)
    vi.mocked(api.getEngagementNotificationSetting).mockImplementation(async (id: string) =>
      id === 'eng-a'
        ? { engagement_id: 'eng-a', external_notifications: 'none', revision: 4, lead_user_id: 'ada' }
        : { engagement_id: 'eng-b', external_notifications: 'inherit', revision: 1, lead_user_id: 'bob' },
    )
  })

  it('cannot switch engagement while a save is in flight, and saves against the shown one', async () => {
    let finish: (value: unknown) => void = () => {}
    vi.mocked(api.saveEngagementNotificationSetting).mockImplementation(() => new Promise((resolve) => { finish = resolve }) as never)
    render(<PersonalDelivery canManage eventTypes={events} />)
    fireEvent.click(await screen.findByRole('combobox', { name: 'Engagement' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Alpha' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Clear lead' }))
    await waitFor(() => expect(api.saveEngagementNotificationSetting).toHaveBeenCalledWith('eng-a', { external_notifications: 'none', revision: 4, lead_user_id: '' }))
    expect(screen.getByRole('combobox', { name: 'Engagement' })).toBeDisabled()
    finish({ engagement_id: 'eng-a', external_notifications: 'none', revision: 5 })
    expect(await screen.findByText('Engagement lead saved.')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Engagement' })).toBeEnabled()
    // Bravo then shows its own settings, and a save goes to Bravo with Bravo's revision and override.
    fireEvent.click(screen.getByRole('combobox', { name: 'Engagement' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Bravo' }))
    vi.mocked(api.saveEngagementNotificationSetting).mockResolvedValue({ engagement_id: 'eng-b', external_notifications: 'inherit', revision: 2 })
    fireEvent.click(await screen.findByRole('button', { name: 'Clear lead' }))
    await waitFor(() => expect(api.saveEngagementNotificationSetting).toHaveBeenLastCalledWith('eng-b', { external_notifications: 'inherit', revision: 1, lead_user_id: '' }))
  })
})
