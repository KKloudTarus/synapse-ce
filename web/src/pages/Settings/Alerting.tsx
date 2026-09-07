import { useState } from 'react'
import { AlertTriangle, BellRinging01, CheckCircle, Send01 } from '@untitledui/icons'
import { Button, Card, EmptyState, InfoNote, cn } from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { useFetch } from '../../hooks'
import { api, AlertNotEnabledError } from '../../lib/api'
import type { AlertTestResult } from '../../lib/api'

function OutcomeStat({ value, label, tone, hint }: { value: number; label: string; tone: string; hint: string }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-secondary bg-primary px-3 py-2">
      <span className={cn('text-xl font-bold tabular-nums', tone)}>{value}</span>
      <span className="inline-flex items-center gap-1 text-sm font-medium text-primary">
        {label}
        <InfoNote label={label}>{hint}</InfoNote>
      </span>
    </div>
  )
}

export function Alerting() {
  const { notify } = useToast()
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  const canAdmin = me?.role === 'admin' || me?.role === 'owner'
  const [result, setResult] = useState<AlertTestResult | null>(null)
  const [ranAt, setRanAt] = useState('')
  const [notEnabled, setNotEnabled] = useState(false)
  const [sending, setSending] = useState(false)

  async function send() {
    if (!canAdmin) return
    setSending(true)
    try {
      const res = await api.testAlert()
      setResult(res)
      setRanAt(new Date().toLocaleString())
      if (res.acknowledged) notify(`Test alert delivered to ${res.outcome.delivered} sink${res.outcome.delivered === 1 ? '' : 's'}.`, 'success')
      else notify(res.error || 'No sink acknowledged the test alert.', 'error')
    } catch (e) {
      if (e instanceof AlertNotEnabledError) {
        setNotEnabled(true)
        return
      }
      notify(e instanceof Error ? e.message : 'Failed to send test alert.', 'error')
    } finally {
      setSending(false)
    }
  }

  if (notEnabled)
    return (
      <EmptyState
        icon={BellRinging01}
        title="Alerting is not enabled"
        hint="This deployment has no alert delivery configured. Configure at least one alert sink to use the self-test."
      />
    )

  return (
    <div className="space-y-6">
      <Card title="Alert delivery self-test" titleClassName="flex items-center gap-2">
        <p className="text-sm text-secondary">
          Send one synthetic alert to every configured sink to prove the path works before you rely on it. The
          test alert is clearly marked and carries no real finding. It succeeds when at least one sink
          acknowledges delivery.
        </p>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <Button variant="primary" loading={sending} disabled={!canAdmin} onClick={send}>
            <Send01 className="size-4" aria-hidden />
            Send test alert
          </Button>
          {!canAdmin && <span className="text-sm text-tertiary">Sending a test alert needs the administer permission.</span>}
        </div>
      </Card>

      {result && (
        <Card
          title="Last test result"
          titleClassName="flex items-center gap-2"
          actions={
            result.acknowledged ? (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-success-primary/25 bg-success-primary/10 px-2.5 py-1 text-xs font-semibold text-success-primary">
                <CheckCircle className="size-3.5" aria-hidden />
                Acknowledged
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-error-primary/25 bg-error-primary/10 px-2.5 py-1 text-xs font-semibold text-error-primary">
                <AlertTriangle className="size-3.5" aria-hidden />
                No acknowledgement
              </span>
            )
          }
        >
          {ranAt && (
            <p className="mb-3 inline-flex items-center gap-1 text-xs text-tertiary">
              Tested at {ranAt}
              <InfoNote label="About these counts">The API reports per-sink counts, not individual sink identities.</InfoNote>
            </p>
          )}
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <OutcomeStat value={result.outcome.delivered} label="Delivered" hint="sinks that acknowledged" tone="text-success-primary" />
            <OutcomeStat value={result.outcome.failed} label="Failed" hint="sinks that refused" tone={result.outcome.failed > 0 ? 'text-error-primary' : 'text-tertiary'} />
            <OutcomeStat value={result.outcome.auditFailed} label="Audit failed" hint="delivered, audit write failed" tone={result.outcome.auditFailed > 0 ? 'text-warning-primary' : 'text-tertiary'} />
            <OutcomeStat value={result.outcome.matched ? 1 : 0} label="Rule matched" hint="test alert matched a routing rule" tone="text-brand-secondary" />
          </div>
          {!result.acknowledged && (
            <p className="mt-3 text-sm text-error-primary">
              {result.error || 'Every configured sink refused the test alert.'} Check sink credentials and connectivity.
            </p>
          )}
        </Card>
      )}
    </div>
  )
}

export default Alerting
