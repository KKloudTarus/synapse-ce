import { useState, useEffect, useRef } from 'react'
import { AlertTriangle, Play, Target04, ShieldZap, ShieldTick, XClose } from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Field, Input, Select, Spinner, cn } from '../../components/ui'
import { useParallelFetch, usePolling } from '../../hooks'
import { api, streamReconLogs } from '../../lib/api'
import type { Engagement, ReconRun, ReconTool } from '../../lib/types'
import type { Tab } from './index'

export function ReconTab({ eng, onGoTab }: { eng: Engagement; onGoTab: (t: Tab) => void }) {
  const [active, setActive] = useState<string | null>(null)

  const { data, loading, error: err } = useParallelFetch<[ReconTool[], ReconRun[]]>(
    () => Promise.all([api.reconTools(), api.reconRuns(eng.id)]),
    { deps: [eng.id] },
  )

  const tools: ReconTool[] = data?.[0] ?? []
  const [runs, setRuns] = useState<ReconRun[]>([])

  // Sync fetched runs into local state for mutation
  useEffect(() => {
    if (data) setRuns(data[1])
  }, [data])

  // Poll while any run is queued/running so the list reflects progress.
  const hasRunning = runs.some((r) => r.status === 'running' || r.status === 'queued')
  const { data: polledRuns } = usePolling(
    () => api.reconRuns(eng.id),
    { interval: 2500, enabled: hasRunning, deps: [eng.id] },
  )

  useEffect(() => {
    if (polledRuns) setRuns(polledRuns)
  }, [polledRuns])

  if (loading) return <Spinner label="Loading recon…" />
  if (err) return <ErrorState message={err} />

  return (
    <div className="space-y-6">
      {eng.liveReconEnabled ? (
        <ReconLauncher
          eng={eng}
          tools={tools}
          onLaunched={(run) => {
            setRuns((prev) => [run, ...prev.filter((x) => x.id !== run.id)])
            setActive(run.id)
          }}
        />
      ) : (
        <Card title="Live reconnaissance disabled">
          <div className="flex flex-wrap items-center gap-3 text-sm text-tertiary">
            <AlertTriangle className="size-4 shrink-0 text-info" />
            <span>Live recon is lab-only and turned off for this engagement.</span>
            <Button variant="secondary" onClick={() => onGoTab('settings')} className="px-3 py-1.5">
              Enable in Settings
            </Button>
          </div>
        </Card>
      )}
      <ReconRunsList runs={runs} activeId={active} onSelect={setActive} />
      {active && (
        <ReconConsole
          engagementId={eng.id}
          runId={active}
          onClose={() => setActive(null)}
          onDone={() => api.reconRuns(eng.id).then(setRuns).catch(() => {})}
        />
      )}
    </div>
  )
}

export function ReconLauncher({ eng, tools, onLaunched }: { eng: Engagement; tools: ReconTool[]; onLaunched: (r: ReconRun) => void }) {
  const [toolName, setToolName] = useState(tools[0]?.name ?? '')
  const [target, setTarget] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const tool = tools.find((t) => t.name === toolName)
  const targets = tool ? eng.inScope.filter((t) => tool.acceptedKinds.includes(t.kind)) : []

  // Keep the selected target valid as the tool (and thus accepted kinds) changes.
  useEffect(() => {
    setTarget((cur) => (targets.some((t) => t.value === cur) ? cur : targets[0]?.value ?? ''))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toolName, eng.id])

  async function launch() {
    if (!toolName || !target) {
      setErr('Pick a tool and an in-scope target.')
      return
    }
    setBusy(true)
    setErr(null)
    try {
      onLaunched(await api.startReconRun(eng.id, toolName, target))
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Launch failed')
    } finally {
      setBusy(false)
    }
  }

  if (tools.length === 0) {
    return (
      <Card title="Recon">
        <p className="text-sm text-tertiary">No recon tools are registered.</p>
      </Card>
    )
  }

  return (
    <Card title="Launch recon">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Tool">
          <Select
            value={toolName}
            onValueChange={setToolName}
            ariaLabel="Recon tool"
            options={tools.map((t) => ({
              value: t.name,
              label: (
                <span className="flex items-center gap-2">
                  {t.name}
                  {t.capabilitySensitive && (
                    <span className="rounded bg-medium/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-medium">lab-only</span>
                  )}
                </span>
              ),
            }))}
          />
        </Field>
        <Field label="In-scope target" hint={targets.length ? undefined : 'No in-scope target matches this tool – add one in Settings'}>
          {targets.length > 0 ? (
            <Select
              value={target}
              onValueChange={setTarget}
              ariaLabel="In-scope target"
              options={targets.map((t) => ({ value: t.value, label: <span className="font-mono">{t.value}</span> }))}
            />
          ) : (
            <Input value="" disabled placeholder="no matching in-scope target" />
          )}
        </Field>
      </div>
      {tool?.capabilitySensitive && (
        <p className="mt-3 flex items-center gap-1.5 text-xs text-medium">
          <AlertTriangle className="size-3.5" /> {tool.name} uses raw sockets – authorized lab environments only.
        </p>
      )}
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
      <div className="mt-4 flex justify-end">
        <Button loading={busy} disabled={!target} onClick={launch} color="secondary" className="px-3 py-1.5">
          <Play className="size-4" /> Launch
        </Button>
      </div>
    </Card>
  )
}

export function ReconStatusPill({ status }: { status: ReconRun['status'] }) {
  const cls: Record<ReconRun['status'], string> = {
    queued: 'bg-secondary text-tertiary ring-secondary',
    running: 'bg-info/10 text-info ring-info/25',
    succeeded: 'bg-accent/10 text-accent ring-accent/25',
    failed: 'bg-critical/10 text-critical ring-critical/25',
  }
  return (
    <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ring-inset', cls[status])}>
      {status}
    </span>
  )
}

export function ReconContainmentBadge({ posture }: { posture: string }) {
  const unsandboxed = posture.startsWith('unsandboxed')
  const Icon = unsandboxed ? ShieldZap : ShieldTick
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 font-mono text-xs tabular-nums ring-1',
        unsandboxed ? 'bg-high/10 text-high ring-high/25' : 'bg-accent/10 text-accent ring-accent/25',
      )}
      title="Containment posture this run executed under (sealed into evidence)"
    >
      <Icon className="size-3 shrink-0" aria-hidden />
      {/* Announce the safe/unsafe state to screen readers – the icon is decorative and the
          posture string alone (e.g. "unsandboxed-dev") carries no semantic severity. */}
      <span className="sr-only">{unsandboxed ? 'Warning, unsandboxed: ' : 'Sandboxed: '}</span>
      <span className="truncate">{posture}</span>
    </span>
  )
}

export function ReconRunsList({ runs, activeId, onSelect }: { runs: ReconRun[]; activeId: string | null; onSelect: (id: string) => void }) {
  if (runs.length === 0) {
    return <EmptyState icon={Target04} title="No recon runs yet" hint="Launch a tool above to start reconnaissance." />
  }
  return (
    <Card title="Runs" bodyClass="p-0">
      <div className="divide-y divide-secondary">
        {runs.map((r) => (
          <button
            key={r.id}
            onClick={() => onSelect(r.id)}
            aria-pressed={activeId === r.id}
            className={cn(
              'flex w-full flex-col gap-1 px-4 py-3 text-left text-sm transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40',
              activeId === r.id && 'bg-secondary',
            )}
          >
            <div className="flex w-full items-center gap-3">
              <ReconStatusPill status={r.status} />
              <span className="font-mono font-medium text-primary">{r.tool}</span>
              <span className="truncate font-mono text-tertiary">{r.target}</span>
              <span className="ml-auto shrink-0 tabular-nums text-xs text-quaternary">
                {r.status === 'succeeded' ? `${r.resultCount} in-scope` : r.status === 'failed' ? 'failed' : r.stage}
              </span>
            </div>
            {r.containment && <ReconContainmentBadge posture={r.containment} />}
          </button>
        ))}
      </div>
    </Card>
  )
}

export function ReconConsole({ engagementId, runId, onClose, onDone }: { engagementId: string; runId: string; onClose: () => void; onDone: () => void }) {
  const [lines, setLines] = useState<string[]>([])
  const [done, setDone] = useState(false)
  const [reconnecting, setReconnecting] = useState(false)
  const boxRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setLines([])
    setDone(false)
    setReconnecting(false)
    const ctrl = new AbortController()
    let lastId = 0
    let stopped = false

    async function pump() {
      while (!stopped) {
        try {
          await streamReconLogs(engagementId, runId, {
            lastEventId: lastId,
            signal: ctrl.signal,
            onEvent: (e) => {
              setReconnecting(false)
              if (e.done) {
                stopped = true
                setDone(true)
                onDone()
                return
              }
              if (e.id) lastId = e.id
              if (e.line !== undefined) setLines((prev) => [...prev, e.line as string])
            },
          })
        } catch {
          if (ctrl.signal.aborted) return
        }
        if (stopped || ctrl.signal.aborted) return
        setReconnecting(true)
        await new Promise((r) => setTimeout(r, 1000)) // brief pause, then reconnect-replay
      }
    }
    pump()
    return () => {
      stopped = true
      ctrl.abort()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [engagementId, runId])

  useEffect(() => {
    boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight })
  }, [lines])

  return (
    <Card
      title="Live log"
      actions={
        <div className="flex items-center gap-3">
          <span className={cn('flex items-center gap-1.5 text-xs', done ? 'text-tertiary' : reconnecting ? 'text-medium' : 'text-info')}>
            <span className={cn('size-1.5 rounded-full', done ? 'bg-tertiary' : reconnecting ? 'bg-medium' : 'bg-info')} />
            {done ? 'ended' : reconnecting ? 'reconnecting…' : 'streaming'}
          </span>
          <button type="button" aria-label="Close log" onClick={onClose} className="rounded-md p-1 text-tertiary hover:bg-secondary hover:text-primary">
            <XClose className="size-4" />
          </button>
        </div>
      }
    >
      <div
        ref={boxRef}
        role="log"
        aria-live="polite"
        aria-relevant="additions"
        className="max-h-96 overflow-auto rounded-lg border border-secondary bg-primary p-3 font-mono text-xs leading-relaxed"
      >
        {lines.length === 0 ? (
          <span className="text-quaternary">Waiting for output…</span>
        ) : (
          lines.map((l, i) => (
            <div
              key={i}
              className={cn(
                'whitespace-pre-wrap break-all',
                l.startsWith('ERROR') ? 'text-critical' : l.startsWith('WARN') ? 'text-medium' : l.includes('[dropped') ? 'text-tertiary' : 'text-primary',
              )}
            >
              {l}
            </div>
          ))
        )}
      </div>
    </Card>
  )
}

export const TARGET_KINDS = ['domain', 'ip', 'cidr', 'url', 'repo', 'image']
