import { ArrowRight, LinkExternal02 } from '@untitledui/icons'
import { Link } from 'react-router-dom'
import { cn } from '../../../components/ui'
import { issueStatusLabel, type ProjectIssue } from '../../../lib/types'
import { cleanIssueTitle, extractLine, statusBadge, typeMeta } from './projectIssueHelpers'

export function IssueItemRow({
  issue,
  isSelected,
  showFilePath,
  onClick,
}: {
  issue: ProjectIssue
  isSelected: boolean
  showFilePath?: boolean
  onClick: () => void
}) {
  const meta = typeMeta(issue.type)
  const TypeIcon = meta.icon
  const line = extractLine(issue.location)

  return (
    <div
      onClick={onClick}
      className={cn(
        'group flex items-start justify-between gap-3 p-3.5 text-left transition-all cursor-pointer',
        isSelected
          ? 'bg-brand-primary/10 border-l-3 border-l-brand-solid shadow-2xs'
          : 'border-l-3 border-l-transparent hover:bg-secondary/40',
      )}
    >
      <div className="min-w-0 flex-1 space-y-1.5">
        {/* Title */}
        <div className="font-semibold text-xs text-primary leading-snug break-words group-hover:text-brand-secondary transition-colors">
          {cleanIssueTitle(issue.title || issue.ruleKey)}
        </div>

        {/* Badges & Meta Row */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          {/* Domain & Severity pill */}
          <span className={cn('inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold border', meta.badge)}>
            <TypeIcon className="size-3 shrink-0" aria-hidden="true" />
            <span>{meta.label}</span>
            <span>·</span>
            <span className="font-mono font-bold uppercase">{issue.severity}</span>
          </span>

          {/* Status Badge */}
          <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-semibold border capitalize', statusBadge(issue.status))}>
            {issueStatusLabel(issue.status)}
          </span>

          {/* File path if in flat mode */}
          {showFilePath && issue.file && (
            <span className="font-mono rounded border border-secondary bg-secondary/50 px-1.5 py-0.5 text-[11px] text-tertiary truncate max-w-[200px]">
              {issue.file}
            </span>
          )}

          {/* Line number */}
          {line && (
            <span className="font-mono rounded border border-secondary bg-secondary/50 px-1.5 py-0.5 text-[11px] text-secondary">
              L{line}
            </span>
          )}

          {/* Rule Key link */}
          <Link
            to={`/rules/${encodeURIComponent(issue.ruleKey)}`}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="inline-flex items-center gap-1 font-mono text-[11px] text-tertiary hover:text-brand-secondary hover:underline"
            title="View Rule Definition"
          >
            <span>{issue.ruleKey}</span>
            <LinkExternal02 className="size-2.5" aria-hidden="true" />
          </Link>

          {/* New Indicator */}
          {issue.isNew && (
            <span className="rounded bg-brand-primary/15 px-1 py-0.2 font-mono text-[10px] font-extrabold uppercase text-brand-secondary border border-brand/20">
              New
            </span>
          )}
        </div>
      </div>

      {/* Inspect action pill */}
      <div className="shrink-0 pt-0.5">
        <span className="inline-flex items-center gap-1 rounded-lg border border-secondary bg-primary px-2 py-1 text-[11px] font-semibold text-tertiary group-hover:border-brand/40 group-hover:text-primary shadow-2xs transition-all">
          <span>Inspect</span>
          <ArrowRight className="size-3" aria-hidden="true" />
        </span>
      </div>
    </div>
  )
}

export function FacetItem({
  label,
  icon: Icon,
  active,
  count,
  tone,
  pillStyle,
  onClick,
}: {
  label: string
  icon?: any
  active: boolean
  count?: number
  tone?: string
  pillStyle?: string
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex w-full items-center justify-between rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all',
        active
          ? 'bg-brand-primary/10 text-brand-secondary border border-brand/30 shadow-2xs'
          : 'text-secondary hover:bg-secondary/60 hover:text-primary border border-transparent',
      )}
    >
      <span className="flex items-center gap-1.5 truncate">
        {Icon && <Icon className={cn('size-3.5 shrink-0', tone)} aria-hidden="true" />}
        <span className="truncate capitalize">{label}</span>
      </span>
      {typeof count === 'number' && (
        <span
          className={cn(
            'font-mono text-[11px] px-1.5 py-0.2 rounded-md font-bold',
            pillStyle || (active ? 'bg-brand/20 text-brand-secondary' : 'bg-secondary text-tertiary'),
          )}
        >
          {count}
        </span>
      )}
    </button>
  )
}
