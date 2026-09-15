import { Activity, AlertCircle, GitBranch01 } from '@untitledui/icons'
import { useFetch } from '../../../hooks'
import { api } from '../../../lib/api'
import { EmptyState, ErrorState, Pill, cn } from '../../../components/ui'

function readableReason(reason: string | null): string {
  if (!reason) return 'The analysis did not retain complete complexity and Git history evidence.'
  return reason.replaceAll('_', ' ')
}

export function BehavioralHotspotsPanel({
  projectKey,
  analysisID,
  path,
}: {
  projectKey: string
  analysisID: string
  path: string
}) {
  const { data, loading, error } = useFetch(
    (signal) => api.projectBehavioralHotspots(projectKey, analysisID, { path, limit: 50 }, signal),
    { enabled: Boolean(projectKey && analysisID), deps: [projectKey, analysisID, path] },
  )

  if (loading && !data) return <div className="h-24" aria-label="Loading behavioral hotspots" />
  if (error && !data) return <ErrorState message={error} />
  if (!data) return null

  const source = data.analysis.sourceRef || 'detached HEAD'
  const commit = data.analysis.sourceCommit ? data.analysis.sourceCommit.slice(0, 12) : 'unknown commit'
  const complete = data.availability === 'complete'
  const unavailable = data.availability === 'unavailable'

  return (
    <section className="space-y-3" aria-labelledby="behavioral-hotspots-heading">
      <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 id="behavioral-hotspots-heading" className="flex items-center gap-2 text-sm font-bold text-primary">
              <Activity className="size-4 text-brand-secondary" aria-hidden="true" />
              Behavioral hotspots
            </h3>
            <p className="mt-1 text-xs text-tertiary">
              Ranked by cyclomatic complexity × commits that changed the file in bounded first-parent history.
            </p>
          </div>
          <span
            className={cn(
              'rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide',
              complete
                ? 'border-success-primary/30 bg-success-primary/10 text-success-primary'
                : unavailable
                  ? 'border-error-primary/30 bg-error-primary/10 text-error-primary'
                  : 'border-warning-primary/30 bg-warning-primary/10 text-warning-primary',
            )}
          >
            {data.availability}
          </span>
        </div>
        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-2 text-xs text-tertiary">
          <span className="inline-flex items-center gap-1.5">
            <GitBranch01 className="size-3.5" aria-hidden="true" />
            <span className="font-medium text-primary">{source}</span>
            <span className="font-mono">@ {commit}</span>
          </span>
          <span>{data.evaluatedCommits} of {data.requestedCommits} commits evaluated{data.reachedRoot ? ' · repository root reached' : ''}</span>
          <span>{data.totalMeasured} measured · {data.totalExcluded} excluded</span>
        </div>
        {!complete && data.reason && (
          <p className="mt-3 flex items-center gap-1.5 text-xs text-warning-primary">
            <AlertCircle className="size-3.5 shrink-0" aria-hidden="true" />
            {readableReason(data.reason)}
          </p>
        )}
      </div>

      {unavailable ? (
        <EmptyState
          icon={Activity}
          title="Behavioral hotspots unavailable"
          hint={`${readableReason(data.reason)} Run a Git-backed analysis with bounded history and the confined AST metrics sidecar enabled.`}
        />
      ) : data.items.length === 0 ? (
        <EmptyState icon={Activity} title="No measured files in this path" hint="Choose a parent directory or run an analysis with supported source files." />
      ) : (
        <div className="overflow-hidden rounded-xl border border-secondary bg-primary shadow-xs">
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-xs">
              <thead className="border-b border-secondary bg-secondary/40 text-[10px] font-bold uppercase tracking-wider text-tertiary">
                <tr>
                  <th scope="col" className="w-12 px-4 py-2.5 text-right">Rank</th>
                  <th scope="col" className="min-w-[280px] px-4 py-2.5">File</th>
                  <th scope="col" className="px-4 py-2.5">Language</th>
                  <th scope="col" className="px-4 py-2.5 text-right">Cyclomatic</th>
                  <th scope="col" className="px-4 py-2.5 text-right">Changes</th>
                  <th scope="col" className="px-4 py-2.5 text-right">Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-secondary/50">
                {data.items.map((item, index) => (
                  <tr key={item.path} className="hover:bg-secondary/30">
                    <td className="px-4 py-3 text-right font-mono text-tertiary">{index + 1}</td>
                    <td className="max-w-[560px] truncate px-4 py-3 font-mono font-semibold text-primary" title={item.path}>{item.path}</td>
                    <td className="px-4 py-3">{item.language ? <Pill className="text-[10px]">{item.language}</Pill> : '—'}</td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums">{item.cyclomatic.toLocaleString()}</td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums">{item.changeCount.toLocaleString()}</td>
                    <td className="px-4 py-3 text-right font-mono font-black tabular-nums text-brand-secondary">{item.score.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data.omitted > 0 && (
            <p className="border-t border-secondary px-4 py-2.5 text-xs text-tertiary">
              Showing {data.shown} of {data.totalMeasured} measured files; {data.omitted} lower-ranked files omitted.
            </p>
          )}
        </div>
      )}
    </section>
  )
}
