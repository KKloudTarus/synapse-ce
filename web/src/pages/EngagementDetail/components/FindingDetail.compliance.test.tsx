import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ComplianceChips } from './FindingDetail'

describe('ComplianceChips', () => {
  it('renders the mapped controls without implying the control passed', () => {
    render(
      <ComplianceChips
        controls={[{ framework: 'PCI-DSS-4.0', id: '6.2.4', title: 'Secure coding' }]}
      />,
    )
    // The control the finding maps to is shown.
    expect(screen.getByText('6.2.4')).toBeInTheDocument()
    expect(screen.getByText('PCI DSS')).toBeInTheDocument()
    // The framing must read as controls the finding IMPACTS, never a verified/compliant state: a compliance
    // mapping on a finding means the control FAILED, so it must not be labelled "Compliance" with a verified
    // checkmark (the no-false-assurance guardrail, issue #1041).
    expect(screen.getByText('Controls impacted')).toBeInTheDocument()
    expect(screen.queryByText('Compliance')).not.toBeInTheDocument()
    // The clarifying tooltip trigger states a mapping is not a pass/certification.
    expect(screen.getByLabelText('What Controls impacted means')).toBeInTheDocument()
  })

  it('renders nothing when the finding maps to no control', () => {
    const { container } = render(<ComplianceChips controls={[]} />)
    expect(container).toBeEmptyDOMElement()
  })
})
