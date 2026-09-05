import { useEffect, useState } from 'react'
import { api } from './api'
import type { Capability } from './types'

/**
 * Deployment capability catalog, read once per page load.
 *
 * `GET /api/v1/capabilities` (internal/adapter/httpapi/capability_handler.go) reports which
 * optional subsystems this server switched on. A subsystem that is off answers 404 on its routes,
 * which is indistinguishable from a crash, so navigation to it should say "off, set this switch"
 * rather than offer a link that 404s.
 *
 * `null` means the deployment does not report capabilities: an older server, or a build with the
 * catalog unwired. Every caller treats that as "assume everything is on" and keeps today's
 * behaviour, so a dashboard never hides a working subsystem because a probe failed.
 */
export type CapabilityIndex = Map<string, Capability> | null

let pending: Promise<CapabilityIndex> | null = null

export function loadCapabilities(): Promise<CapabilityIndex> {
  // Navigation must render whatever this probe does, so nothing it can throw escapes: a build
  // without the client, a rejected promise, a malformed body all mean "assume everything is on".
  pending ??= (async (): Promise<CapabilityIndex> => {
    try {
      const list = await api.listCapabilities()
      return list === null ? null : new Map(list.map((c) => [c.key, c]))
    } catch {
      return null
    }
  })()
  return pending
}

/** Test seam: drops the per-page cache so a suite can serve a different catalog. */
export function resetCapabilityCache(): void {
  pending = null
}

/**
 * The capability that gates a nav target, or null when the deployment reports it enabled, does not
 * report capabilities at all, or does not know the key. All three mean "render the live link".
 */
export function disabledCapability(index: CapabilityIndex, key: string | undefined): Capability | null {
  if (!index || !key) return null
  const capability = index.get(key)
  if (!capability || capability.enabled) return null
  return capability
}

/** One sentence naming the switch an operator sets, for a tooltip on a disabled nav item. */
export function capabilityHint(capability: Capability): string {
  const unmet = capability.requires.length > 0 ? ` It also needs: ${capability.requires.join(', ')}.` : ''
  return `${capability.name} is disabled. Set ${capability.switch}=true on the API and restart it.${unmet}`
}

export function useCapabilities(): CapabilityIndex {
  const [index, setIndex] = useState<CapabilityIndex>(null)
  useEffect(() => {
    let live = true
    loadCapabilities().then((next) => {
      if (live) setIndex(next)
    })
    return () => {
      live = false
    }
  }, [])
  return index
}
