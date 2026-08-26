import { AlertTriangle, BarChart01, CheckCircle, Circle, GitBranch01, XCircle } from '@untitledui/icons'
import { Link } from 'react-router-dom'
import { Pill, cn } from '../../../components/ui'
import type { Project } from '../../../lib/types'
import { formatDate, formatLang, gradeStyle, projectHealth } from './projectCardHelpers'

export function ProjectCard({ project }: { project: Project }) {
  const analysis = project.latestAnalysis
  const health = projectHealth(project)
  const healthMeta = {
    failing: { label: 'Gate failed', icon: XCircle, tone: 'border-error/40 bg-error-primary/10 text-error-primary ring-error/20' },
    passing: { label: 'Gate passed', icon: CheckCircle, tone: 'border-success-primary/40 bg-success-primary/10 text-success-primary ring-success-primary/20' },
    analyzing: { label: 'Analyzing', icon: BarChart01, tone: 'border-brand/40 bg-brand-primary/15 text-brand-secondary ring-brand/20' },
    failed: { label: 'Run failed', icon: AlertTriangle, tone: 'border-error/40 bg-error-primary/10 text-error-primary ring-error/20' },
    unanalyzed: { label: 'No analysis', icon: Circle, tone: 'border-secondary bg-secondary/50 text-tertiary ring-secondary' },
  }[health]
  const HealthIcon = healthMeta.icon
  const languages = Object.keys(project.defaultProfileByLang || {})

  return (
    <Link
      to={`/code-quality/projects/${encodeURIComponent(project.key)}`}
      className={cn(
        'group flex flex-col justify-between rounded-xl border bg-primary p-4 shadow-xs transition-all hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50',
        health === 'failing' || health === 'failed'
          ? 'border-error/25 hover:border-error/60'
          : health === 'passing'
          ? 'border-secondary hover:border-success-primary/50'
          : 'border-secondary hover:border-brand/50',
      )}
    >
      <div>
        {/* Card Top: Title, Subtitle, Languages, and Health Pill */}
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <h2 className="truncate text-base font-bold text-primary group-hover:text-brand-secondary transition-colors">
              {project.name}
            </h2>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="truncate font-mono text-xs text-utility-blue-700 dark:text-utility-blue-300 italic">
                {project.key}
              </span>
              {languages.length > 0 && (
                <div className="flex items-center gap-1">
                  {languages.map((lang) => (
                    <span
                      key={lang}
                      className="inline-flex items-center rounded-md bg-secondary/70 px-1.5 py-0.2 font-mono text-[10px] font-semibold text-secondary border border-secondary"
                    >
                      {formatLang(lang)}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
          <Pill className={cn('shrink-0 ring-1 ring-inset font-semibold', healthMeta.tone)}>
            <HealthIcon className="size-3" aria-hidden="true" /> {healthMeta.label}
          </Pill>
        </div>

        {/* Middle: SonarQube-style 3 Pillars (Grade + Issue Count) */}
        {analysis ? (
          <div className="mt-3.5 flex flex-wrap gap-2" aria-label="Quality ratings">
            {(['security', 'reliability', 'maintainability'] as const).map((dim) => {
              const count =
                dim === 'security'
                  ? (analysis.issues.byKind?.vulnerability ??
                    (analysis.issues.bySeverity.critical ?? 0) + (analysis.issues.bySeverity.high ?? 0))
                  : dim === 'reliability'
                  ? (analysis.issues.byKind?.bug ?? (analysis.issues.bySeverity.medium ?? 0))
                  : (analysis.issues.byKind?.code_smell ?? (analysis.issues.bySeverity.low ?? 0))

              return (
                <span
                  key={dim}
                  aria-label={`${dim.charAt(0).toUpperCase() + dim.slice(1)} rating ${analysis.rating[dim]}`}
                  className={cn(
                    'inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-bold ring-1 ring-inset shadow-2xs',
                    gradeStyle(analysis.rating[dim]),
                  )}
                >
                  <span className="font-extrabold text-sm">{analysis.rating[dim]}</span>
                  <span className="font-mono font-semibold tabular-nums">{count}</span>
                  <span className="font-normal text-[11px] capitalize opacity-80">{dim.slice(0, 3)}</span>
                </span>
              )
            })}
          </div>
        ) : project.latestJob?.status === 'running' ? (
          <div className="mt-3 rounded-lg border border-brand/30 bg-brand-primary/10 p-2.5 text-xs text-brand-secondary space-y-1.5">
            <div className="flex items-center justify-between font-semibold">
              <span className="capitalize">{project.latestJob.stage || 'Analyzing'}...</span>
              <span>{project.latestJob.progress ?? 0}%</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-brand-primary/20">
              <div
                className="h-full bg-brand-solid transition-all duration-300 rounded-full"
                style={{ width: `${Math.max(5, project.latestJob.progress ?? 0)}%` }}
              />
            </div>
          </div>
        ) : (
          <div className="mt-3 rounded-lg border border-dashed border-secondary bg-secondary/30 px-3 py-2 text-xs text-tertiary">
            Run the first analysis to establish a baseline and evaluate the quality gate.
          </div>
        )}
      </div>

      {/* Footer: Detailed metrics, Branch, Commit & Date */}
      <div className="mt-3.5 flex flex-wrap items-center justify-between gap-2 border-t border-secondary pt-3 text-xs">
        {analysis ? (
          <>
            <span className="flex items-center gap-1 text-xs">
              <span className="font-mono font-bold text-error-primary tabular-nums">
                {analysis.issues.bySeverity.critical ?? 0}
              </span>
              <span className="text-quaternary">/</span>
              <span className="font-mono font-bold text-utility-orange-600 dark:text-utility-orange-400 tabular-nums">
                {analysis.issues.bySeverity.high ?? 0}
              </span>
              <span className="text-tertiary text-[11px]">crit+high</span>
              <span className="text-quaternary mx-0.5">·</span>
              <span className="font-mono font-bold text-brand-secondary tabular-nums">
                {analysis.newCode.counts.total}
              </span>
              <span className="text-tertiary text-[11px]">new</span>
            </span>
            <span className="flex items-center gap-1.5 text-xs text-tertiary truncate">
              {project.sourceBinding.ref && (
                <span className="inline-flex items-center gap-1 font-mono text-[11px] text-quaternary bg-secondary/40 px-1 rounded">
                  <GitBranch01 className="size-3" aria-hidden="true" />
                  {project.sourceBinding.ref}
                </span>
              )}
              <span className="font-semibold text-secondary truncate">
                {analysis.gateInfo.name || project.gateId || 'Synapse way'}
              </span>
              <span className="text-quaternary">·</span>
              <span className="shrink-0">{formatDate(analysis.createdAt)}</span>
            </span>
          </>
        ) : (
          <>
            <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-mono capitalize bg-secondary text-secondary">
              <GitBranch01 className="size-3" aria-hidden="true" />
              {project.sourceBinding.kind} · {project.sourceBinding.ref || 'default'}
            </span>
            <span className="font-semibold text-secondary">{project.gateId || 'Default gate'}</span>
          </>
        )}
        <span className="sr-only">Open decision details</span>
      </div>
    </Link>
  )
}
