import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../lib/api'
import type { CodeQualityReport } from '../lib/types'
import { CodeQualityTab } from './CodeQualityTab'

vi.mock('../lib/api', () => ({ api: { codeQuality: vi.fn() } }))

const report: CodeQualityReport = {
  inventory: [],
  findings: [],
  duplication: { blocks: [], duplicatedLines: 0, totalLines: 0, files: 0 },
  rating: { security: 'A', reliability: 'B', maintainability: 'C', techDebtMinutes: 0, debtRatioPct: 0, linesOfCode: 0 },
}

describe('CodeQualityTab', () => {
  beforeEach(() => { vi.resetAllMocks() })

  it('renders loading and backend errors', async () => {
    vi.mocked(api.codeQuality).mockReturnValue(new Promise(() => {}))
    const view = render(<CodeQualityTab engagementId="e1" />)
    expect(screen.getByText('Analyzing code quality…')).toBeInTheDocument()
    view.unmount()

    vi.mocked(api.codeQuality).mockRejectedValue(new Error('Analysis failed'))
    render(<CodeQualityTab engagementId="e1" />)
    expect(await screen.findByText('Analysis failed')).toBeInTheDocument()
  })

  it('explains why Code Quality is unavailable', async () => {
    vi.mocked(api.codeQuality).mockResolvedValue({ available: false, reason: 'No local source directory.' })
    render(<CodeQualityTab engagementId="e1" />)
    expect(await screen.findByText('Code Quality unavailable')).toBeInTheDocument()
    expect(screen.getByText('No local source directory.')).toBeInTheDocument()
  })

  it('renders the shared report presentation', async () => {
    vi.mocked(api.codeQuality).mockResolvedValue({ available: true, report })
    render(<CodeQualityTab engagementId="e1" />)
    expect(await screen.findByRole('heading', { name: 'Quality ratings' })).toBeInTheDocument()
    expect(screen.getByLabelText('Security rating A')).toBeInTheDocument()
  })
})
