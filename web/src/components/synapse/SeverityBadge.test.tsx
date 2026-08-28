import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { SeverityBadge } from './SeverityBadge'

describe('SeverityBadge', () => {
  it('renders critical severity badge with dot icon by default', () => {
    const { container } = render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
    expect(container.querySelector('svg')).toBeInTheDocument() // Dot icon SVG
  })

  it('renders all 5 severity levels with capitalized text', () => {
    const severities = ['critical', 'high', 'medium', 'low', 'info'] as const
    const labels = ['Critical', 'High', 'Medium', 'Low', 'Info']

    severities.forEach((sev, idx) => {
      const { unmount } = render(<SeverityBadge severity={sev} />)
      expect(screen.getByText(labels[idx])).toBeInTheDocument()
      unmount()
    })
  })

  it('hides dot icon when showIcon is false', () => {
    const { container } = render(<SeverityBadge severity="low" showIcon={false} />)
    expect(screen.getByText('Low')).toBeInTheDocument()
    expect(container.querySelector('svg')).not.toBeInTheDocument()
  })

  it('supports size="sm"', () => {
    render(<SeverityBadge severity="high" size="sm" />)
    expect(screen.getByText('High')).toBeInTheDocument()
  })
})
