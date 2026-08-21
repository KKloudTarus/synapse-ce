import { api } from '../../lib/api'
import type { ScanJob } from '../../lib/types'
import { usePolling, type UsePollingResult } from '../usePolling'

/**
 * Polls the scan status for an engagement at a fixed interval.
 * Useful during active scans to show real-time progress.
 *
 * @example
 * ```tsx
 * const { data: job, loading } = useScanStatus(engagementId, {
 *   interval: 3000,
 *   enabled: isRunning,
 * })
 * ```
 */
export function useScanStatus(
  engagementId: string,
  options: { interval?: number; enabled?: boolean } = {},
): UsePollingResult<ScanJob | null> {
  const { interval = 3000, enabled = true } = options
  return usePolling(
    () => api.scanStatus(engagementId),
    { interval, enabled: enabled && !!engagementId, deps: [engagementId] },
  )
}
