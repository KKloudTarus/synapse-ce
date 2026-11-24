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

  // This state usually replaces a whole route. A title rendered as a paragraph left those screens
  // with no heading at all, so a screen reader landed on a page it could not name and the heading
  // sweep in web/scripts/ui-audit.mjs reported /fleet/hosts and /fleet/workloads as headless.
  it('carries the page heading by default', () => {
    render(<FeatureDisabledState feature="Fleet host inventory" envVar="SYNAPSE_FLEET_HOST_INGEST_ENABLED" />)
    expect(screen.getByRole('heading', { level: 1, name: 'Fleet host inventory is not enabled' })).toBeInTheDocument()
  })

  it('steps down to the level the surrounding surface leaves free', () => {
    const { rerender } = render(<FeatureDisabledState feature="AI triage" titleAs="h2" />)
    expect(screen.getByRole('heading', { level: 2, name: 'AI triage is not enabled' })).toBeInTheDocument()
    rerender(<FeatureDisabledState feature="Legal hold" titleAs="h3" />)
    expect(screen.getByRole('heading', { level: 3, name: 'Legal hold is not enabled' })).toBeInTheDocument()
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
