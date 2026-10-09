import { afterEach, describe, expect, it, vi } from 'vitest'
import { blobDownload } from './client'

afterEach(() => vi.unstubAllGlobals())
describe('File download response handling', () => {
  it('accepts 204 without creating or clicking a download', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })))
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    await expect(blobDownload('/api/v1/export', 'export.json')).resolves.toBeUndefined()
    expect(click).not.toHaveBeenCalled()
  })
  it('rejects an empty 200 without fabricating a 502 or format advice', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 200 })))
    await expect(blobDownload('/api/v1/export', 'export.json')).rejects.toMatchObject({ status: 200, code: 'empty_export', message: 'The export is empty. No file was downloaded.' })
  })
  it('downloads a populated file and releases its object URL', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('synthetic file', { headers: { 'Content-Disposition': 'attachment; filename="server.csv"' } })))
    const create = vi.fn().mockReturnValue('blob:synthetic')
    const revoke = vi.fn()
    vi.stubGlobal('URL', class extends URL { static createObjectURL = create; static revokeObjectURL = revoke })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { expect(this.download).toBe('server.csv') })
    await blobDownload('/api/v1/export', 'fallback.csv')
    expect(click).toHaveBeenCalledOnce()
    expect(create).toHaveBeenCalledOnce()
    expect(revoke).toHaveBeenCalledWith('blob:synthetic')
  })
})
