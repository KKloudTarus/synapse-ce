import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../../lib/api'
import { RegionalSettings } from './RegionalSettings'

vi.mock('../../lib/api', async (original) => ({
  ...(await original<typeof import('../../lib/api')>()),
  api: {
    me: vi.fn(),
    getTenantSettings: vi.fn(),
    saveTenantSettings: vi.fn(),
  },
}))

const defaults = { defaultLocale: 'en' as const, timeZone: 'UTC', revision: 0, locales: ['en' as const, 'vi' as const] }

describe('language and time zone settings', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    // Radix Select scrolls the chosen option into view, which jsdom does not implement.
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() })
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.getTenantSettings).mockResolvedValue(defaults)
  })

  it('shows a saved Vietnamese locale and zone as stored', async () => {
    // Regression: the form used to start at en and copy the stored values in after mount, which
    // left the language select on its placeholder.
    vi.mocked(api.getTenantSettings).mockResolvedValue({
      ...defaults,
      defaultLocale: 'vi',
      timeZone: 'Asia/Ho_Chi_Minh',
      revision: 1,
      updatedAt: '2026-09-29T04:00:11Z',
    })
    render(<RegionalSettings />)
    expect(await screen.findByLabelText('Time zone')).toHaveValue('Asia/Ho_Chi_Minh')
    expect(screen.getByRole('combobox', { name: 'Default language' })).toHaveTextContent('Tiếng Việt (Vietnamese)')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('shows the defaults for a tenant that never saved settings', async () => {
    render(<RegionalSettings />)
    expect(await screen.findByLabelText('Time zone')).toHaveValue('UTC')
    expect(screen.getByRole('combobox', { name: 'Default language' })).toHaveTextContent('English')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('saves the language and an IANA time zone with the revision it read', async () => {
    vi.mocked(api.saveTenantSettings).mockResolvedValue({
      ...defaults,
      defaultLocale: 'vi',
      timeZone: 'Asia/Ho_Chi_Minh',
      revision: 1,
      updatedAt: '2026-09-28T08:00:00Z',
    })
    render(<RegionalSettings />)
    fireEvent.click(await screen.findByRole('combobox', { name: 'Default language' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Tiếng Việt (Vietnamese)' }))
    fireEvent.change(screen.getByLabelText('Time zone'), { target: { value: 'Asia/Ho_Chi_Minh' } })
    expect(screen.getByText(/Current time there:/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(api.saveTenantSettings).toHaveBeenCalledWith({ defaultLocale: 'vi', timeZone: 'Asia/Ho_Chi_Minh', revision: 0 }),
    )
    expect(await screen.findByText(/Last changed/)).toBeInTheDocument()
  })

  it('refuses a name that is not a time zone before calling the API', async () => {
    render(<RegionalSettings />)
    fireEvent.change(await screen.findByLabelText('Time zone'), { target: { value: '+07:00' } })
    expect(screen.getByText('Not a known time zone name.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/is not a time zone name/)).toBeInTheDocument()
    expect(api.saveTenantSettings).not.toHaveBeenCalled()
  })

  it('reloads the latest values when another administrator saved first', async () => {
    vi.mocked(api.getTenantSettings)
      .mockResolvedValueOnce(defaults)
      .mockResolvedValueOnce({ ...defaults, timeZone: 'Europe/Berlin', revision: 1 })
    vi.mocked(api.saveTenantSettings).mockRejectedValue(new ApiError(409, 'conflict'))
    render(<RegionalSettings />)
    fireEvent.change(await screen.findByLabelText('Time zone'), { target: { value: 'Asia/Tokyo' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/Another administrator changed these settings/)).toBeInTheDocument()
    await waitFor(() => expect(screen.getByLabelText('Time zone')).toHaveValue('Europe/Berlin'))
  })

  it('shows the settings read-only to a user who is not an administrator', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'member' } as never)
    render(<RegionalSettings />)
    expect(await screen.findByText('Only tenant administrators can change these settings.')).toBeInTheDocument()
    expect(screen.getByLabelText('Time zone')).toBeDisabled()
    expect(screen.getByRole('combobox', { name: 'Default language' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('shows an error when the settings cannot be loaded', async () => {
    vi.mocked(api.getTenantSettings).mockRejectedValue(new Error('Cannot reach the API.'))
    render(<RegionalSettings />)
    expect(await screen.findByText('Cannot reach the API.')).toBeInTheDocument()
  })
})
