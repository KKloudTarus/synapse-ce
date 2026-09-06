import { useMemo } from 'react'
import { Cube01, GitBranch01, ShieldZap, Target04, Activity } from '@untitledui/icons'
import { Card, EmptyState, ErrorState, Pill, Spinner, cn } from '../../components/ui'
import { useParallelFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { RiskFinding, RiskStory } from '../../lib/api'

function severityTone(sev: string): string {
  const s = sev.toLowerCase()
  if (s === 'critical' || s === 'high') return 'bg-error-solid'
  if (s === 'medium') return 'bg-warning-solid'
  if (s === 'low') return 'bg-utility-blue-500'
  return 'bg-quaternary'
}

function priorityLabel(p: number): string {
  return p >= 1 && p <= 5 ? `P${p}` : '—'
}

// story.score is the best (most urgent) finding priority: 1 = act now, 5 = low, 0 = no findings.
function urgencyRank(score: number): number {
  return score >= 1 && score <= 5 ? score : 99 // 0 / no findings sorts last
}

function scoreTone(score: number): string {
  if (score === 1) return 'text-error-primary bg-error-primary/10 border-error-primary/25'
  if (score === 2 || score === 3) return 'text-warning-primary bg-warning-primary/10 border-warning-primary/25'
  if (score >= 4) return 'text-utility-blue-600 dark:text-utility-blue-400 bg-utility-blue-500/10 border-utility-blue-500/25'
  return 'text-tertiary bg-secondary border-secondary'
}

function scoreLabel(score: number): string {
  if (score === 0) return 'no findings'
  if (score === 1) return 'P1 · act now'
  return `P${score}`
}

function SignalBadges({ f }: { f: RiskFinding }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {f.kev && <Pill className="text-error-primary">KEV</Pill>}
      {f.reachable && (
        <Pill className="text-error-primary">
          <Target04 className="size-3" aria-hidden />
          reachable
        </Pill>
      )}
      {f.onAttackPath && (
        <Pill className="text-warning-primary">
          <GitBranch01 className="size-3" aria-hidden />
          on attack path
        </Pill>
      )}
      {f.seenUnderAttack && (
        <Pill className="text-error-primary">
          <Activity className="size-3" aria-hidden />
          seen under attack
        </Pill>
      )}
    </span>
  )
}

function FindingRow({ f }: { f: RiskFinding }) {
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-secondary/60 py-2 first:border-t-0">
      <span className={cn('size-2 shrink-0 rounded-full', severityTone(f.severity))} aria-hidden title={f.severity} />
      {f.severity && <span className="sr-only">{f.severity} severity: </span>}
      <span className="min-w-0 flex-1 truncate text-sm text-primary" title={f.title}>
        {f.title || f.findingId}
      </span>
      <span className="font-mono text-xs font-semibold text-tertiary">{priorityLabel(f.priority)}</span>
      <SignalBadges f={f} />
    </li>
  )
}

function StoryCard({ story }: { story: RiskStory }) {
  const name = story.identity.name || story.identity.key || story.assetId
  const topFindings = story.findings.slice(0, 6)
  const moreFindings = story.findings.length - topFindings.length
  return (
    <Card
      title={
        <span className="inline-flex items-center gap-2">
          <Cube01 className="size-4 text-quaternary" aria-hidden />
          <span className="truncate">{name}</span>
          {story.identity.kind && <Pill className="font-mono">{story.identity.kind}</Pill>}
        </span>
      }
      actions={
        <span className={cn('inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-bold', scoreTone(story.score))}>
          <ShieldZap className="size-3.5" aria-hidden />
          {scoreLabel(story.score)}
        </span>
      }
    >
      {story.qualifiers.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1.5">
          {story.qualifiers.map((q) => (
            <Pill key={q}>{q}</Pill>
          ))}
        </div>
      )}
      {story.findings.length > 0 ? (
        <ul>
          {topFindings.map((f) => (
            <FindingRow key={f.findingId} f={f} />
          ))}
          {moreFindings > 0 && <li className="pt-2 text-xs text-tertiary">and {moreFindings} more finding{moreFindings === 1 ? '' : 's'}</li>}
        </ul>
      ) : (
        <p className="text-sm text-tertiary">No findings correlated to this asset.</p>
      )}
      <div className="mt-4 flex flex-wrap gap-x-6 gap-y-1 border-t border-secondary/60 pt-3 text-xs text-tertiary">
        <span>{story.exposure.length} exposure element{story.exposure.length === 1 ? '' : 's'}</span>
        <span>{story.paths.length} attack path{story.paths.length === 1 ? '' : 's'}</span>
        <span>{story.detections.length} detection{story.detections.length === 1 ? '' : 's'}</span>
      </div>
    </Card>
  )
}

export function RiskStoriesTab({ engagementId }: { engagementId: string }) {
  const { data, loading, error } = useParallelFetch<[RiskStory[]]>(
    () => Promise.all([api.riskStories(engagementId)]),
    { deps: [engagementId] },
  )

  const stories = useMemo(() => {
    const list = data?.[0] ?? []
    // Most urgent first: priority 1 (act now) leads; assets with no findings (score 0) sort last.
    return [...list].sort((a, b) => urgencyRank(a.score) - urgencyRank(b.score))
  }, [data])

  if (loading) return <Spinner label="Loading risk stories…" />
  if (error) return <ErrorState message={error} />
  if (stories.length === 0)
    return (
      <EmptyState
        icon={Cube01}
        title="No correlated risk stories yet"
        hint="A risk story is assembled per asset once findings, exposure, attack paths, or detections correlate to it. Run scans and enroll assets to populate this view."
      />
    )

  return (
    <div className="space-y-6">
      <p className="text-sm text-tertiary">
        One story per asset, ranked by correlated risk. A finding is raised when it is reachable, on an
        attack path, or seen under attack; those signals order it above an equal-priority finding without
        them.
      </p>
      {stories.map((s) => (
        <StoryCard key={s.assetId} story={s} />
      ))}
    </div>
  )
}
