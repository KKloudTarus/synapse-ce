import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ApiError } from '../../lib/api'
import { FeatureDisabledState, isFeatureDisabled } from './FeatureDisabledState'

describe('FeatureDisabledState', () => {
  it('names the switch that turns the feature on', () => {
    render(<FeatureDisabledState feature="Fleet" envVar="SYNAPSE_FLEET_ENABLED" hint="It reports agent coverage." />)
    expect(screen.getByText('Fleet is not enabled')).toBeInTheDocument()
    expect(screen.getByText(/SYNAPSE_FLEET_ENABLED=true/)).toBeInTheDocument()
    expect(screen.getByText(/It reports agent coverage\./)).toBeInTheDocument()
  })

  it('renders no Retry action, because retrying a 404 404s again', () => {
    render(<FeatureDisabledState feature="Fleet" envVar="SYNAPSE_FLEET_ENABLED" />)
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument()
    expect(screen.queryByText(/HTTP 404/)).not.toBeInTheDocument()
  })

  it('says so plainly when the build exposes no switch', () => {
    render(<FeatureDisabledState feature="Attack paths" />)
    expect(screen.getByText(/does not expose the feature/)).toBeInTheDocument()
  })
})

describe('isFeatureDisabled', () => {
  it('is true only for a 404 ApiError', () => {
    expect(isFeatureDisabled(new ApiError(404, 'HTTP 404'))).toBe(true)
    expect(isFeatureDisabled(new ApiError(500, 'HTTP 500'))).toBe(false)
    expect(isFeatureDisabled(new Error('HTTP 404'))).toBe(false)
    expect(isFeatureDisabled(null)).toBe(false)
  })
})
