import { fireEvent, render, screen, within } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { EntraDiscoverySettings } from './EntraDiscoverySettings'

it('associates each discovery selector with its own label and directory help', () => {
  const onChange = vi.fn()
  render(<>
    <section aria-label="Initial provisioning"><EntraDiscoverySettings issuer="https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0" mode="common" disabled onChange={vi.fn()} /></section>
    <section aria-label="Existing connection"><EntraDiscoverySettings issuer="https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0" mode="" onChange={onChange} /></section>
  </>)
  const initial = within(screen.getByRole('region', { name: 'Initial provisioning' })).getByLabelText('Entra metadata discovery')
  const existing = within(screen.getByRole('region', { name: 'Existing connection' })).getByLabelText('Entra metadata discovery')
  expect(initial).toBeDisabled()
  expect(existing).toBeEnabled()
  expect(existing.id).not.toBe(initial.id)
  expect(existing).toHaveAccessibleDescription(/22222222-2222-2222-2222-222222222222/)
  expect(initial).toHaveAccessibleDescription(/11111111-1111-1111-1111-111111111111/)
  fireEvent.change(existing, { target: { value: 'organizations' } })
  expect(onChange).toHaveBeenCalledWith('organizations')
})
