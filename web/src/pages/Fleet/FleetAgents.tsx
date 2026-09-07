import { useState } from 'react'
import { Copy01, Key01, RefreshCcw01, Rocket02, Server01 } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { AgentKey, RolloutStatus } from '../../lib/api'
import type { FleetAgentRow } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, InfoNote, Input, Pill, Spinner, cn } from '../../components/ui'
import { FeatureDisabledState, isFeatureDisabled } from '../../components/synapse/FeatureDisabledState'
import { useFetch } from '../../hooks'
import { FleetStateBadge, formatFleetTime } from './fleetShared'

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      className="inline-flex items-center gap-1 rounded-md border border-secondary px-2 py-1 text-xs text-tertiary hover:text-primary"
      onClick={() => {
        navigator.clipboard?.writeText(value).then(() => {
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        })
      }}
    >
      <Copy01 className="size-3.5" /> {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

/** Mint a single-use agent enrolment token. The token is returned once and never re-fetchable. */
function EnrolmentCard({ canAdmin }: { canAdmin: boolean }) {
  const [ttlMinutes, setTtlMinutes] = useState(15)
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function mint() {
    setBusy(true)
    setErr('')
    setToken('')
    try {
      setToken(await api.mintEnrolToken(Math.max(1, ttlMinutes) * 60))
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not mint an enrolment token')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Agent enrolment"
      titleClassName="flex items-center gap-2"
      actions={
        <InfoNote label="How enrolment works">
          A new agent joins the fleet by presenting a single-use enrolment token, then receives a signed
          certificate. Mint a token, hand it to the host's installer within its lifetime, and it is spent on
          first use. The token is shown once and cannot be retrieved again.
        </InfoNote>
      }
    >
      {!canAdmin ? (
        <p className="text-sm text-tertiary">Minting an enrolment token needs the administrator role.</p>
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Lifetime (minutes)</span>
              <Input type="number" min={1} value={ttlMinutes} onChange={(e) => setTtlMinutes(Number(e.target.value) || 1)} className="w-32" aria-label="Enrolment token lifetime minutes" />
            </label>
            <Button variant="primary" loading={busy} disabled={busy} onClick={mint}>
              <Key01 className="size-4" /> Mint token
            </Button>
          </div>
          {err && <ErrorState message={err} />}
          {token && (
            <div className="space-y-2 rounded-lg border border-warning-primary/30 bg-warning-primary/5 p-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-warning-primary">Copy this token now. It is shown only once.</span>
              </div>
              <div className="flex items-center gap-2">
                <code className="min-w-0 flex-1 truncate rounded bg-primary px-2 py-1 font-mono text-xs text-primary" title={token}>{token}</code>
                <CopyButton value={token} />
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

/** Staged agent binary rollout for one release channel. */
function RolloutCard({ canAdmin }: { canAdmin: boolean }) {
  const [channel, setChannel] = useState('stable')
  const { data, loading, error, refetch } = useFetch<RolloutStatus>(() => api.getFleetRollout(channel), { deps: [channel] })
  const [target, setTarget] = useState('')
  const [canary, setCanary] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [pauseReason, setPauseReason] = useState('')

  async function act(run: () => Promise<RolloutStatus>) {
    setBusy(true)
    setErr('')
    try {
      await run()
      await refetch()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Rollout action failed')
    } finally {
      setBusy(false)
    }
  }

  const rollout = data?.rollout ?? null

  return (
    <Card
      title="Agent rollout"
      actions={
        <div className="flex items-center gap-2">
          <InfoNote label="Staged rollout">
            The target agent version for a channel rolls out to the canary groups first, then to every host on
            promote. Pause holds the rollout; resume continues it. Hosts on this channel converge to the target.
          </InfoNote>
          <label className="flex items-center gap-1 text-xs text-tertiary">
            channel
            <Input value={channel} onChange={(e) => setChannel(e.target.value)} className="w-28" aria-label="Rollout channel" />
          </label>
        </div>
      }
    >
      {loading && !data ? (
        <div className="flex justify-center py-6"><Spinner /></div>
      ) : error ? (
        <ErrorState message={error} />
      ) : (
        <div className="space-y-4">
          {rollout ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Target version" value={rollout.targetVersion || '—'} mono />
              <Field label="State" value={rollout.paused ? `paused${rollout.pauseReason ? ` — ${rollout.pauseReason}` : ''}` : rollout.promotedToAll ? 'promoted to all' : 'canary'} />
              <Field label="Canary groups" value={rollout.canaryGroups.length ? rollout.canaryGroups.join(', ') : '—'} />
              <Field label="Updated" value={`${formatFleetTime(rollout.updatedAt)}${rollout.updatedBy ? ` by ${rollout.updatedBy}` : ''}`} />
            </div>
          ) : (
            <p className="text-sm text-tertiary">{data?.reason || `No rollout plan is configured for the ${data?.channel ?? channel} channel.`}</p>
          )}

          {canAdmin && (
            <div className="space-y-3 border-t border-secondary pt-3">
              <div className="flex flex-wrap items-end gap-3">
                <label className="flex flex-col gap-1">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Set target version</span>
                  <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={rollout?.targetVersion || 'e.g. 1.4.2'} className="w-44 font-mono" aria-label="Set target version" />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Canary groups (comma-sep)</span>
                  <Input value={canary} onChange={(e) => setCanary(e.target.value)} placeholder="canary-a, canary-b" className="w-56" aria-label="Canary groups" />
                </label>
                <Button
                  variant="secondary"
                  loading={busy}
                  disabled={busy || !target.trim()}
                  onClick={() => act(() => api.setFleetRolloutTarget(target.trim(), canary.split(',').map((c) => c.trim()).filter(Boolean), channel)).then(() => { setTarget(''); setCanary('') })}
                >
                  Set target
                </Button>
              </div>
              {rollout && (
                <div className="flex flex-wrap items-end gap-2">
                  <Button variant="secondary" loading={busy} disabled={busy || rollout.promotedToAll} onClick={() => act(() => api.promoteFleetRollout(channel))}>
                    <Rocket02 className="size-4" /> Promote to all
                  </Button>
                  {rollout.paused ? (
                    <Button variant="secondary" loading={busy} disabled={busy} onClick={() => act(() => api.resumeFleetRollout(channel))}>Resume</Button>
                  ) : (
                    <>
                      <Input value={pauseReason} onChange={(e) => setPauseReason(e.target.value)} placeholder="pause reason" className="w-48" aria-label="Pause reason" />
                      <Button variant="secondary" loading={busy} disabled={busy || !pauseReason.trim()} onClick={() => act(() => api.pauseFleetRollout(pauseReason.trim(), channel)).then(() => setPauseReason(''))}>Pause</Button>
                    </>
                  )}
                </div>
              )}
              {err && <ErrorState message={err} />}
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-quaternary">{label}</span>
      <span className={cn('text-sm text-secondary', mono && 'font-mono')}>{value}</span>
    </div>
  )
}

function AgentKeysPanel({ agentId, canAdmin }: { agentId: string; canAdmin: boolean }) {
  const { data, loading, error, refetch } = useFetch<AgentKey[]>(() => api.listAgentKeys(agentId), { deps: [agentId] })
  const [busyKey, setBusyKey] = useState('')

  async function revoke(keyId: string) {
    if (!window.confirm(`Revoke signing key ${keyId}? The agent must rotate to a new key.`)) return
    setBusyKey(keyId)
    try {
      await api.revokeAgentKey(agentId, keyId)
      await refetch()
    } finally {
      setBusyKey('')
    }
  }

  if (loading && !data) return <div className="px-4 py-3 text-xs text-tertiary">Loading keys…</div>
  if (error) return <div className="px-4 py-3"><ErrorState message={error} /></div>
  if (!data || data.length === 0) return <div className="px-4 py-3 text-xs text-tertiary">No signing keys recorded for this agent.</div>

  return (
    <div className="overflow-x-auto px-4 py-3">
      <table className="w-full text-xs">
        <thead className="text-left uppercase tracking-wide text-quaternary">
          <tr><th className="py-1 pr-4 font-medium">Key</th><th className="py-1 pr-4 font-medium">Purpose</th><th className="py-1 pr-4 font-medium">Algorithm</th><th className="py-1 pr-4 font-medium">Not after</th><th className="py-1 pr-4 font-medium">State</th><th /></tr>
        </thead>
        <tbody className="divide-y divide-secondary">
          {data.map((k) => (
            <tr key={k.keyId}>
              <td className="py-1.5 pr-4 font-mono text-secondary" title={k.keyId}>{k.keyId}</td>
              <td className="py-1.5 pr-4 text-tertiary">{k.purpose || '—'}</td>
              <td className="py-1.5 pr-4 font-mono text-tertiary">{k.algorithm || '—'}</td>
              <td className="py-1.5 pr-4 tabular-nums text-tertiary">{formatFleetTime(k.notAfter)}</td>
              <td className="py-1.5 pr-4">
                {k.revoked ? <Pill className="bg-error-primary/10 text-error-primary ring-1 ring-inset ring-error-primary/25">revoked</Pill> : <Pill className="bg-success-primary/10 text-success-primary ring-1 ring-inset ring-success-primary/25">active</Pill>}
              </td>
              <td className="py-1.5 text-right">
                {canAdmin && !k.revoked && (
                  <button type="button" className="text-xs text-error-primary hover:underline disabled:opacity-50" disabled={busyKey === k.keyId} onClick={() => revoke(k.keyId)}>
                    {busyKey === k.keyId ? 'Revoking…' : 'Revoke'}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AgentRow({ agent, canAdmin, onChange }: { agent: FleetAgentRow; canAdmin: boolean; onChange: () => void }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  async function revokeAgent() {
    const reason = window.prompt(`Revoke agent ${agent.name || agent.id}? Enter a reason:`, 'decommissioned')
    if (reason === null) return
    setBusy(true)
    try {
      await api.revokeFleetAgent(agent.id, reason || 'revoked')
      onChange()
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className="rounded-lg border border-secondary bg-primary">
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 px-4 py-3">
        <div className="flex min-w-0 items-center gap-2">
          <Server01 className="size-4 shrink-0 text-tertiary" aria-hidden />
          <span className="truncate text-sm font-semibold text-primary" title={agent.id}>{agent.name || agent.id}</span>
          <FleetStateBadge state={agent.state} />
          {agent.platform && <span className="text-xs text-quaternary">{agent.platform}</span>}
          {agent.agentVersion && <span className="font-mono text-xs text-quaternary">v{agent.agentVersion}</span>}
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-tertiary">seen {formatFleetTime(agent.lastSeen)}</span>
          <button type="button" className="text-xs text-tertiary hover:text-primary" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
            <Key01 className="mr-1 inline size-3.5" />{open ? 'Hide keys' : 'Keys'}
          </button>
          {canAdmin && agent.state !== 'revoked' && (
            <button type="button" className="text-xs text-error-primary hover:underline disabled:opacity-50" disabled={busy} onClick={revokeAgent}>
              {busy ? 'Revoking…' : 'Revoke agent'}
            </button>
          )}
        </div>
      </div>
      {open && <div className="border-t border-secondary"><AgentKeysPanel agentId={agent.id} canAdmin={canAdmin} /></div>}
    </li>
  )
}

function AgentsCard({ canAdmin }: { canAdmin: boolean }) {
  const { data, loading, error, refetch } = useFetch<FleetAgentRow[]>(() => api.listFleetAgents(), { deps: [] })
  return (
    <Card
      title="Agents"
      actions={
        <InfoNote label="Agent lifecycle">
          Every enrolled agent, its health, and its signing keys. Revoking an agent bars it from the fleet;
          revoking a single key forces that agent to rotate. Both are recorded in the audit log.
        </InfoNote>
      }
    >
      {loading && !data ? (
        <div className="flex justify-center py-6"><Spinner /></div>
      ) : error ? (
        <ErrorState message={error} />
      ) : !data || data.length === 0 ? (
        <EmptyState icon={Server01} title="No agents enrolled" hint="Mint an enrolment token above and run it on a host to enrol the first agent." />
      ) : (
        <ul className="space-y-2" role="list">
          {data.map((a) => <AgentRow key={a.id} agent={a} canAdmin={canAdmin} onChange={refetch} />)}
        </ul>
      )}
    </Card>
  )
}

export function FleetAgents() {
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  const { error } = useFetch<FleetAgentRow[]>(() => api.listFleetAgents(), { deps: [] })
  const canAdmin = me?.role === 'admin'

  if (error && isFeatureDisabled(error)) {
    return (
      <div className="mx-auto max-w-[1200px] p-4">
        <FeatureDisabledState feature="Fleet agent management" envVar="SYNAPSE_FLEET_ENABLED" hint="Agent enrolment, revocation, signing keys, and rollout need the fleet subsystem." />
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-[1200px] animate-fade-in space-y-6 p-4 pb-12">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight text-primary">
          <RefreshCcw01 className="size-6 text-tertiary" aria-hidden /> Agent administration
        </h1>
        <p className="text-sm text-tertiary">Enrol and revoke fleet agents, rotate their signing keys, and stage agent binary rollouts.</p>
      </header>
      <EnrolmentCard canAdmin={canAdmin} />
      <RolloutCard canAdmin={canAdmin} />
      <AgentsCard canAdmin={canAdmin} />
    </div>
  )
}

export default FleetAgents
