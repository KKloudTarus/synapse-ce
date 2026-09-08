import { act, render, renderHook, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../lib/api'
import type { UploadedSourcePackage } from '../lib/types'
import { RetestSourceChoice } from '../components/synapse/RetestSourceChoice'
import { MAX_SOURCE_BYTES, sourceArchiveError, useRetestSource } from './useRetestSource'

vi.mock('../lib/api', async (importOriginal) => ({
  ...await importOriginal<typeof import('../lib/api')>(),
  api: { uploadedSource: vi.fn(), getEngagement: vi.fn() },
}))

const source: UploadedSourcePackage = {
  versionId: 'version-a', filename: 'source-a.zip', size: 2048, sha256: 'a'.repeat(64), target: '', uploadedBy: 'operator', uploadedAt: '2026-09-08T00:00:00Z',
}

describe('uploaded predecessor source selection', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.getEngagement).mockResolvedValue({ inScope: [{ kind: 'repo', value: 'https://example.test/repo' }] } as never)
  })

  it('clears a selected file when the predecessor changes, including switching back', async () => {
    vi.mocked(api.uploadedSource).mockImplementation(async (id) => ({ ...source, versionId: `version-${id}` }))
    const { result, rerender } = renderHook(({ id }) => useRetestSource(id), { initialProps: { id: 'a' } })
    await waitFor(() => expect(result.current.loading).toBe(false))
    const file = new File(['revision'], 'new.zip')
    act(() => result.current.chooseFile(file))
    expect(result.current.input).toMatchObject({ sourceStrategy: 'upload_new', source: file })
    rerender({ id: 'b' })
    expect(result.current.file).toBeUndefined()
    expect(result.current.input).toEqual({})
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.input).toMatchObject({ sourceStrategy: 'reuse_current', sourceVersionId: 'version-b' })
    rerender({ id: 'a' })
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.input).toMatchObject({ sourceStrategy: 'reuse_current', sourceVersionId: 'version-a', source: undefined })
  })

  it('does not reuse stale metadata when an older predecessor lookup resolves later', async () => {
    let resolveFirst!: (value: UploadedSourcePackage) => void
    vi.mocked(api.uploadedSource).mockImplementation((id) => id === 'a'
      ? new Promise((resolve) => { resolveFirst = resolve })
      : Promise.resolve({ ...source, versionId: 'version-b' }))
    const { result, rerender } = renderHook(({ id }) => useRetestSource(id), { initialProps: { id: 'a' } })
    expect(result.current.loading).toBe(true)
    expect(result.current.validationError('copy')).toMatch(/Wait/)
    rerender({ id: 'b' })
    await waitFor(() => expect(result.current.input.sourceVersionId).toBe('version-b'))
    await act(async () => { resolveFirst(source) })
    expect(result.current.input.sourceVersionId).toBe('version-b')
  })

  it.each([
    ['git', { kind: 'repo', value: 'https://example.test/repository.git' }],
    ['local', { kind: 'repo', value: '/authorized/source/repository' }],
    ['image', { kind: 'image', value: 'registry.example.test/application:v1' }],
  ])('keeps %s predecessor requests unchanged when no uploaded package exists', async (_kind, target) => {
    vi.mocked(api.uploadedSource).mockRejectedValue(new ApiError(404, 'Not found'))
    vi.mocked(api.getEngagement).mockResolvedValue({ inScope: [target] } as never)
    const { result } = renderHook(() => useRetestSource('source-less'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.input).toEqual({})
    expect(result.current.validationError('empty')).toBe('')
    render(<RetestSourceChoice selection={result.current} />)
    expect(screen.queryByRole('radio')).not.toBeInTheDocument()
  })

  it('keeps permission failures distinct from an absent source and constrains empty scope', async () => {
    vi.mocked(api.uploadedSource).mockRejectedValueOnce(new ApiError(403, 'Not authorized')).mockResolvedValueOnce(source)
    const { result } = renderHook(() => useRetestSource('a'))
    await waitFor(() => expect(result.current.error).toBe('Not authorized'))
    expect(result.current.validationError('copy')).toMatch(/Retry/)
    act(() => result.current.refetch())
    await waitFor(() => expect(result.current.source).toEqual(source))
    expect(result.current.validationError('empty')).toMatch(/must copy/)
    expect(result.current.validationError('copy')).toBe('')
  })

  it('allows a new child archive when a legacy uploaded predecessor has lost its package metadata', async () => {
    vi.mocked(api.uploadedSource).mockRejectedValue(new ApiError(404, 'No package'))
    vi.mocked(api.getEngagement).mockResolvedValue({ inScope: [{ kind: 'repo', value: `uploaded-source/sha256/${'a'.repeat(64)}` }] } as never)
    const { result } = renderHook(() => useRetestSource('legacy-upload'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.source).toBeNull()
    expect(result.current.strategy).toBe('upload_new')
    expect(result.current.validationError('copy')).toBe('Choose a source archive to upload.')
    expect(api.getEngagement).toHaveBeenCalledWith('legacy-upload')
    const file = new File(['recovered revision'], 'replacement.zip')
    act(() => result.current.chooseFile(file))
    expect(result.current.input).toEqual({ sourceStrategy: 'upload_new', sourceVersionId: undefined, source: file })
    expect(result.current.validationError('empty')).toMatch(/must copy/)
    render(<RetestSourceChoice selection={result.current} />)
    expect(screen.getByRole('radio', { name: /Use previous source/ })).toBeDisabled()
    expect(screen.getByRole('radio', { name: /Upload new source/ })).toBeChecked()
    expect(screen.getByRole('status')).toHaveTextContent('previous source archive is unavailable')
    expect(screen.queryByText('source-a.zip')).not.toBeInTheDocument()
  })

  it('does not classify a failed fallback scope lookup as a source-less predecessor', async () => {
    vi.mocked(api.uploadedSource).mockRejectedValue(new ApiError(404, 'No package'))
    vi.mocked(api.getEngagement).mockRejectedValue(new ApiError(503, 'Scope lookup unavailable'))
    const { result } = renderHook(() => useRetestSource('a'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toBe('Scope lookup unavailable')
    expect(result.current.validationError('copy')).toMatch(/Retry/)
    expect(result.current.input).toEqual({})
  })

  it('renders an untrusted archive filename as text and disables all choices during submission', async () => {
    vi.mocked(api.uploadedSource).mockResolvedValue({ ...source, filename: '<img src=x onerror=alert(1)>.zip' })
    function Choice() { return <RetestSourceChoice selection={useRetestSource('a')} disabled /> }
    const view = render(<Choice />)
    expect(await screen.findByText('<img src=x onerror=alert(1)>.zip')).toBeVisible()
    expect(view.container.querySelector('img')).toBeNull()
    expect(screen.getByRole('radio', { name: /Use previous source/ })).toBeDisabled()
    expect(screen.getByRole('radio', { name: /Upload new source/ })).toBeDisabled()
    await userEvent.click(screen.getByRole('radio', { name: /Upload new source/ }))
    expect(screen.queryByLabelText('Re-test source archive')).not.toBeInTheDocument()
  })

  it('validates archive type and non-empty size without accepting an oversized upload', () => {
    for (const name of ['source.zip', 'source.tar', 'source.tar.gz', 'source.tgz', 'SOURCE.ZIP']) {
      expect(sourceArchiveError(new File(['archive'], name))).toBe('')
    }
    expect(sourceArchiveError()).not.toBe('')
    expect(sourceArchiveError(new File([], 'empty.zip'))).not.toBe('')
    expect(sourceArchiveError(new File(['bytes'], 'source.zip.exe'))).not.toBe('')
    const oversized = new File(['small fixture'], 'large.zip')
    Object.defineProperty(oversized, 'size', { value: MAX_SOURCE_BYTES + 1 })
    expect(sourceArchiveError(oversized)).not.toBe('')
  })
})
