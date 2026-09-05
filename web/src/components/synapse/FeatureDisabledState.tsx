import type { ComponentType, ReactNode } from 'react'
import { Power01 } from '@untitledui/icons'
import { EmptyState } from '../ui'
import { ApiError } from '../../lib/api'

/**
 * A feature switched off server-side answers 404 on its routes. That is a
 * configuration state, not a failure: show the switch instead of an HTTP code
 * and a Retry button that would 404 again.
 */
export function isFeatureDisabled(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404
}

/** Same test for a `useFetch` error string, which has already lost the status. */
export function isFeatureDisabledMessage(message: string | null | undefined): boolean {
  return Boolean(message && /(^|\D)404(\D|$)/.test(message))
}

export function FeatureDisabledState({
  feature,
  envVar,
  hint,
  icon = Power01,
}: {
  /** Human name of the feature, e.g. "Fleet". */
  feature: string
  /** The `SYNAPSE_*` switch that turns it on. Omit when the build has none. */
  envVar?: string
  /** One sentence on what the feature gives you once enabled. */
  hint?: ReactNode
  icon?: ComponentType<{ className?: string }>
}) {
  const instruction = envVar
    ? `Set ${envVar}=true on the API and restart it.`
    : 'This deployment does not expose the feature.'
  return (
    <EmptyState
      icon={icon}
      title={`${feature} is not enabled`}
      hint={hint ? `${instruction} ${hint}` : instruction}
    />
  )
}
