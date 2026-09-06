import { ApiError, req } from './client'

/**
 * Operator alerting self-test. POST /alerts/test delivers one synthetic alert to every configured sink so
 * an operator can prove the alert path works before relying on it. 200 with an Outcome when at least one
 * sink acknowledged; 502 with the same Outcome plus an error when none did. `audit_failed` counts sinks
 * that delivered but whose audit write failed. Route registers only when alerting is wired (a 404 means
 * "not enabled"); the POST also requires the administer permission.
 *
 * SOURCE OF TRUTH: `internal/usecase/alerting/service.go` (`Outcome`), handler `alert_handler.go`.
 */

export interface AlertTestOutcome {
  matched: boolean
  delivered: number
  failed: number
  auditFailed: number
}

export interface AlertTestResult {
  acknowledged: boolean
  outcome: AlertTestOutcome
  error?: string
}

function mapOutcome(o: any): AlertTestOutcome {
  return {
    matched: o?.matched === true,
    delivered: o?.delivered ?? 0,
    failed: o?.failed ?? 0,
    auditFailed: o?.audit_failed ?? 0,
  }
}

export class AlertNotEnabledError extends Error {
  constructor() {
    super('Alerting is not enabled in this deployment.')
    this.name = 'AlertNotEnabledError'
  }
}

export const alertingApi = {
  /**
   * Sends the synthetic test alert. Resolves with acknowledged=false and the outcome when the server
   * answers 502 (no sink acknowledged), so the caller can render the per-sink counts either way. Throws
   * AlertNotEnabledError on 404.
   */
  testAlert: async (): Promise<AlertTestResult> => {
    try {
      const r = await req('/alerts/test', { method: 'POST' })
      return { acknowledged: true, outcome: mapOutcome(r?.outcome) }
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) throw new AlertNotEnabledError()
      if (e instanceof ApiError && e.status === 502 && (e.body as { outcome?: unknown })?.outcome) {
        return { acknowledged: false, outcome: mapOutcome((e.body as { outcome?: unknown }).outcome), error: e.message }
      }
      throw e
    }
  },
}
