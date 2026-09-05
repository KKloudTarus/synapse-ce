import type { Capability } from '../types'
import { req } from './client'

/**
 * Optional-subsystem catalog. Wire shape: `capabilityView` in
 * internal/adapter/httpapi/capability_handler.go, resolved from
 * internal/usecase/capabilities/service.go.
 *
 * A disabled subsystem and a crashed one both answer 404 on their routes, so the dashboard cannot
 * tell them apart without this. The route itself is optional: a server built before it answers 404
 * here too. That is not an error to surface — it means "this deployment does not report
 * capabilities", and every caller falls back to showing everything.
 */
function mapCapability(raw: any): Capability {
  return {
    key: raw?.key ?? '',
    name: raw?.name ?? '',
    enabled: raw?.enabled === true,
    switch: raw?.switch ?? '',
    requires: Array.isArray(raw?.requires) ? raw.requires : [],
  }
}

export const capabilitiesApi = {
  /** Returns null when the deployment does not report capabilities; callers then assume all on. */
  listCapabilities: async (): Promise<Capability[] | null> => {
    try {
      const res = await req('/capabilities')
      const list = res?.capabilities
      if (!Array.isArray(list)) return null
      return list.map(mapCapability).filter((c: Capability) => c.key !== '')
    } catch {
      return null
    }
  },
}
