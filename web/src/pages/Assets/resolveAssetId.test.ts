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

function asset(id: string, key: string) {
  return { id, key, name: key, type: 'application', criticality: 'low', lifecycle: 'active' } as never
}

describe('resolveAssetId', () => {
  beforeEach(() => vi.resetAllMocks())

  it('resolves an id in one request', async () => {
    vi.mocked(api.getBusinessAsset).mockResolvedValue(asset('a1', 'mobile'))
    await expect(resolveAssetId('a1')).resolves.toBe('a1')
    expect(api.getBusinessAsset).toHaveBeenCalledTimes(1)
  })

  // GET /appsec/assets/{assetID} resolves a business key too: the handler calls
  // businessassetuc.Service.Get, which falls back to GetBusinessAssetByKey. Verified against a live
  // API: creating an asset with key K and requesting /appsec/assets/K answers 200 with that asset.
  it('resolves a business key through the same request', async () => {
    vi.mocked(api.getBusinessAsset).mockResolvedValue(asset('a1', 'mobile'))
    await expect(resolveAssetId('mobile')).resolves.toBe('a1')
    expect(api.getBusinessAsset).toHaveBeenCalledWith('mobile', undefined)
  })

  // Listing the inventory to resolve a key made one navigation cost a full tenant scan per page,
  // and it never found anything the detail route had not already resolved.
  it('never lists the inventory', async () => {
    vi.mocked(api.getBusinessAsset).mockRejectedValue(new ApiError(404, 'not found'))
    await expect(resolveAssetId('absent')).resolves.toBeNull()
    expect(api.listBusinessAssets).not.toHaveBeenCalled()
  })

  it('treats 404 as absent', async () => {
    vi.mocked(api.getBusinessAsset).mockRejectedValue(new ApiError(404, 'not found'))
    await expect(resolveAssetId('absent')).resolves.toBeNull()
  })

  // A real outage must stay visible rather than degrade into "Asset not found".
  it('rethrows a non-404 failure', async () => {
    vi.mocked(api.getBusinessAsset).mockRejectedValue(new ApiError(503, 'upstream down'))
    await expect(resolveAssetId('a1')).rejects.toThrow('upstream down')
  })

  it('passes the abort signal through so an abandoned navigation stops the request', async () => {
    const controller = new AbortController()
    vi.mocked(api.getBusinessAsset).mockResolvedValue(asset('a1', 'mobile'))
    await resolveAssetId('mobile', controller.signal)
    expect(api.getBusinessAsset).toHaveBeenCalledWith('mobile', controller.signal)
  })

  it('returns null for an empty route param without calling the API', async () => {
    await expect(resolveAssetId('')).resolves.toBeNull()
    expect(api.getBusinessAsset).not.toHaveBeenCalled()
  })
})
