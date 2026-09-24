import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../../lib/api'
import { resolveAssetId } from './AssetDetail'

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api')
  return {
    ...actual,
    api: { getBusinessAsset: vi.fn(), listBusinessAssets: vi.fn() },
  }
})

const PAGE = 100

function asset(id: string, key: string) {
  return { id, key, name: key, type: 'application', criticality: 'low', lifecycle: 'active' } as never
}

function page(items: unknown[], total: number, offset: number) {
  return { items, total, limit: PAGE, offset } as never
}

describe('resolveAssetId', () => {
  beforeEach(() => vi.resetAllMocks())

  it('resolves an id directly without listing', async () => {
    vi.mocked(api.getBusinessAsset).mockResolvedValue(asset('a1', 'mobile'))
    await expect(resolveAssetId('a1')).resolves.toBe('a1')
    expect(api.listBusinessAssets).not.toHaveBeenCalled()
  })

  // The bug this guards: the key search used to read only the default first page, so any asset
  // past it rendered "Asset not found" even though it existed.
  it('finds a key that lives beyond the first page', async () => {
    vi.mocked(api.getBusinessAsset).mockRejectedValue(new ApiError(404, 'not found'))
    const firstPage = Array.from({ length: PAGE }, (_, i) => asset(`id-${i}`, `key-${i}`))
    vi.mocked(api.listBusinessAssets).mockImplementation(async (query = '') =>
      query.includes('offset=0')
        ? page(firstPage, 150, 0)
        : page([asset('wanted-id', 'late-key')], 150, PAGE),
    )
    await expect(resolveAssetId('late-key')).resolves.toBe('wanted-id')
    expect(api.listBusinessAssets).toHaveBeenCalledTimes(2)
  })

  it('returns null only after exhausting the pages', async () => {
    vi.mocked(api.getBusinessAsset).mockRejectedValue(new ApiError(404, 'not found'))
    vi.mocked(api.listBusinessAssets).mockResolvedValue(page([asset('a1', 'mobile')], 1, 0))
    await expect(resolveAssetId('absent')).resolves.toBeNull()
  })

  // A real outage must stay visible rather than degrade into "Asset not found".
  it('rethrows a non-404 failure from the direct lookup', async () => {
    vi.mocked(api.getBusinessAsset).mockRejectedValue(new ApiError(503, 'upstream down'))
    await expect(resolveAssetId('a1')).rejects.toThrow('upstream down')
    expect(api.listBusinessAssets).not.toHaveBeenCalled()
  })
})
