import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { Settings } from './Settings'
import { SettingsConfig } from './SettingsConfig'

describe('Settings Layout', () => {
  it('renders Settings header and tab links', () => {
    render(
      <MemoryRouter initialEntries={['/settings']}>
        <Routes>
          <Route path="settings" element={<Settings />}>
            <Route index element={<div>Audit Log Content</div>} />
            <Route path="team" element={<div>Team Content</div>} />
            <Route path="config" element={<SettingsConfig />} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )

    expect(screen.getByRole('heading', { name: 'Settings' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Audit' })).toHaveAttribute('href', '/settings')
    expect(screen.getByRole('link', { name: 'Team' })).toHaveAttribute('href', '/settings/team')
    expect(screen.getByRole('link', { name: 'Config' })).toHaveAttribute('href', '/settings/config')
    expect(screen.getByText('Audit Log Content')).toBeInTheDocument()
  })

  it('renders team sub-tab when navigated to /settings/team', () => {
    render(
      <MemoryRouter initialEntries={['/settings/team']}>
        <Routes>
          <Route path="settings" element={<Settings />}>
            <Route index element={<div>Audit Log Content</div>} />
            <Route path="team" element={<div>Team Content</div>} />
            <Route path="config" element={<SettingsConfig />} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )

    expect(screen.getByText('Team Content')).toBeInTheDocument()
  })

  it('renders config sub-tab with environment, theme selector, and disconnect action', () => {
    render(
      <MemoryRouter initialEntries={['/settings/config']}>
        <Routes>
          <Route path="settings" element={<Settings />}>
            <Route index element={<div>Audit Log Content</div>} />
            <Route path="team" element={<div>Team Content</div>} />
            <Route path="config" element={<SettingsConfig />} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )

    expect(screen.getByText('Self-hosted · single-tenant · isolated storage')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Light theme' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Dark theme' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Disconnect' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Dark theme' }))
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(document.documentElement.classList.contains('dark-mode')).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'Light theme' }))
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(document.documentElement.classList.contains('dark-mode')).toBe(false)
  })
})
