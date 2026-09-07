import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { QualityProfiles } from './QualityProfiles'
import type { QualityProfile, RuleSummary } from '../../lib/types'

vi.mock('../../lib/api', () => ({
  api: {
    projectBranches: vi.fn(() => Promise.resolve([])),
    listQualityProfiles: vi.fn(),
    listRules: vi.fn(),
    copyQualityProfile: vi.fn(),
    assignProjectProfile: vi.fn(),
    deleteQualityProfile: vi.fn(),
    activateProfileRule: vi.fn(),
    deactivateProfileRule: vi.fn(),
    setProfileRuleSeverity: vi.fn(),
  },
  ApiError: class ApiError extends Error {},
}))

const mockProfiles: QualityProfile[] = [
  {
    key: 'go-default',
    name: 'Go Default Baseline',
    language: 'go',
    parent: '',
    activatedRules: { 'go:S100': { severity: 'high' } },
    builtIn: true,
  },
  {
    key: 'go-custom',
    name: 'Go Custom Strict',
    language: 'go',
    parent: 'go-default',
    activatedRules: { 'go:S100': { severity: 'critical' }, 'go:S200': { severity: 'medium' } },
    builtIn: false,
  },
  {
    key: 'ts-default',
    name: 'TypeScript Default',
    language: 'typescript',
    parent: '',
    activatedRules: { 'ts:S101': { severity: 'high' } },
    builtIn: true,
  },
]

const mockGoRules: RuleSummary[] = [
  {
    key: 'go:S100',
    name: 'Avoid SQL injection concatenation',
    language: 'go',
    type: 'vulnerability',
    qualities: ['security'],
    defaultSeverity: 'high',
    tags: ['cwe-89', 'security'],
    cwe: ['CWE-89'],
    owasp: ['A03:2021'],
    description: 'Avoid concatenation in SQL',
    remediationEffort: 5,
    detection: 'ast',
  },
  {
    key: 'go:S200',
    name: 'Unchecked error return value',
    language: 'go',
    type: 'bug',
    qualities: ['reliability'],
    defaultSeverity: 'medium',
    tags: ['reliability'],
    cwe: [],
    owasp: [],
    description: 'Check error return',
    remediationEffort: 2,
    detection: 'ast',
  },
]

describe('QualityProfiles', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.listQualityProfiles).mockResolvedValue(mockProfiles)
    vi.mocked(api.listRules).mockResolvedValue(mockGoRules)
  })

  it('renders 4 KPI stat cards and master sidebar list grouped by language', async () => {
    render(<QualityProfiles />)

    // Check KPI cards
    expect(await screen.findByText('Total Profiles')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('Languages')).toBeInTheDocument()
    expect(screen.getByText('Built-in Defaults')).toBeInTheDocument()
    expect(screen.getAllByText('2').length).toBe(2) // 2 languages, 2 built-in profiles
    expect(screen.getByText('Custom Profiles')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument() // 1 custom profile

    // Master sidebar buttons
    expect(screen.getAllByText('Go Default Baseline').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Go Custom Strict').length).toBeGreaterThan(0)
    expect(screen.getAllByText('TypeScript Default').length).toBeGreaterThan(0)
  })

  it('auto-selects the first profile and displays its rules catalog', async () => {
    render(<QualityProfiles />)

    // Should auto-select 'go-default' and fetch rules
    expect(await screen.findByText('Avoid SQL injection concatenation')).toBeInTheDocument()
    expect(screen.getByText('go:S100')).toBeInTheDocument()
    expect(api.listRules).toHaveBeenCalledWith({ languages: ['go'] })
  })

  it('filters master sidebar profiles by search query and type pills', async () => {
    render(<QualityProfiles />)
    await screen.findByText('Avoid SQL injection concatenation')

    const searchInput = screen.getByPlaceholderText(/Search profile or language/i)

    // Search for TypeScript
    fireEvent.change(searchInput, { target: { value: 'type' } })
    expect(screen.queryByRole('button', { name: /Go Default Baseline/i })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /TypeScript Default/i })).toBeInTheDocument()

    // Clear search
    fireEvent.change(searchInput, { target: { value: '' } })
    expect(screen.getByRole('button', { name: /Go Default Baseline/i })).toBeInTheDocument()

    // Filter Custom only
    fireEvent.click(screen.getByRole('button', { name: /^Custom/i }))
    expect(screen.getByRole('button', { name: /Go Custom Strict/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Go Default Baseline/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /TypeScript Default/i })).not.toBeInTheDocument()
  })

  it('opens and submits Copy Profile modal', async () => {
    vi.mocked(api.copyQualityProfile).mockResolvedValue({
      key: 'go-team-copy',
      name: 'Go Team Copy',
      language: 'go',
      parent: 'go-default',
      activatedRules: {},
      builtIn: false,
    })

    render(<QualityProfiles />)
    await screen.findByText('Avoid SQL injection concatenation')

    fireEvent.click(screen.getByRole('button', { name: /Copy profile/i }))

    // Modal dialog is rendered
    expect(screen.getByRole('heading', { name: 'Copy Quality Profile' })).toBeInTheDocument()

    const keyInput = screen.getByLabelText(/New Profile Key/i)
    const nameInput = screen.getByLabelText(/Profile Display Name/i)

    fireEvent.change(keyInput, { target: { value: 'go-team-copy' } })
    fireEvent.change(nameInput, { target: { value: 'Go Team Copy' } })

    const submitBtn = within(screen.getByRole('dialog')).getByRole('button', { name: /Create copy/i })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(api.copyQualityProfile).toHaveBeenCalledWith('go-default', 'go-team-copy', 'Go Team Copy')
    })
  })

  it('opens and submits Assign Profile modal', async () => {
    vi.mocked(api.assignProjectProfile).mockResolvedValue()

    render(<QualityProfiles />)
    await screen.findByText('Avoid SQL injection concatenation')

    fireEvent.click(screen.getByRole('button', { name: /Assign to project/i }))

    expect(screen.getByRole('heading', { name: 'Assign Profile to Project' })).toBeInTheDocument()

    const projectInput = screen.getByLabelText(/Target Project Key/i)
    fireEvent.change(projectInput, { target: { value: 'synapse-backend' } })

    const assignBtn = within(screen.getByRole('dialog')).getByRole('button', { name: /Assign profile/i })
    fireEvent.click(assignBtn)

    await waitFor(() => {
      expect(api.assignProjectProfile).toHaveBeenCalledWith('synapse-backend', 'go', 'go-default')
    })
  })

  it('allows deleting custom profile with Delete modal confirmation', async () => {
    vi.mocked(api.deleteQualityProfile).mockResolvedValue()

    render(<QualityProfiles />)
    await screen.findByText('Avoid SQL injection concatenation')

    // Switch to custom profile in master sidebar
    fireEvent.click(screen.getByRole('button', { name: /Go Custom Strict/i }))

    // Delete button should now be visible for custom profile
    const deleteBtn = await screen.findByRole('button', { name: /Delete/i })
    fireEvent.click(deleteBtn)

    expect(screen.getByRole('heading', { name: 'Delete Quality Profile' })).toBeInTheDocument()

    const confirmDeleteBtn = within(screen.getByRole('dialog')).getByRole('button', { name: /Delete profile/i })
    fireEvent.click(confirmDeleteBtn)

    await waitFor(() => {
      expect(api.deleteQualityProfile).toHaveBeenCalledWith('go-custom')
    })
  })

  it('filters rules list by active/inactive status and search keyword', async () => {
    render(<QualityProfiles />)
    await screen.findByText('Avoid SQL injection concatenation')

    // Both rules initially in catalog
    expect(screen.getByText('Avoid SQL injection concatenation')).toBeInTheDocument()
    expect(screen.getByText('Unchecked error return value')).toBeInTheDocument()

    // Filter Active only (only go:S100 is active in go-default)
    fireEvent.click(screen.getByRole('button', { name: /^Active/i }))
    expect(screen.getByText('Avoid SQL injection concatenation')).toBeInTheDocument()
    expect(screen.queryByText('Unchecked error return value')).not.toBeInTheDocument()

    // Filter by rule search
    const ruleSearchInput = screen.getByPlaceholderText(/Filter rules by name or key/i)
    fireEvent.change(ruleSearchInput, { target: { value: 'injection' } })
    expect(screen.getByText('Avoid SQL injection concatenation')).toBeInTheDocument()
  })

  it('allows clicking the profile key to copy it to clipboard', async () => {
    const writeTextMock = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextMock,
      },
    })

    render(<QualityProfiles />)
    const copyBtn = await screen.findByRole('button', { name: 'Copy key go-default' })
    fireEvent.click(copyBtn)

    expect(writeTextMock).toHaveBeenCalledWith('go-default')
    expect(await screen.findByText(/Copied/i)).toBeInTheDocument()
  })
})

