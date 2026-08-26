import { useEffect, useMemo, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import {
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Copy01,
  FileCode01 as FileCode2,
  File02,
  File06 as Files,
  FolderClosed,
  SwitchHorizontal01 as GitCompareArrows,
  ShieldTick,
  Tool01,
  Virus,
  Zap,
  XClose,
} from '@untitledui/icons'
import { Button, EmptyState, Pill, Skeleton, cn } from '../../ui'
import { PROJECT_CODE_SOURCE_WINDOW } from '../../../lib/projectCodeNavigation'
import type {
  ProjectCodeDiffHunk,
  ProjectCodeDiffResponse,
  ProjectCodeDiffRow,
  ProjectCodeFile,
  ProjectCodeFileIndex,
  ProjectCodeFileView,
  ProjectCodeFinding,
  ProjectCodeView,
} from '../../../lib/types'
import { useCodeNavigation } from './useCodeNavigation'
import { FileNavigator, StatusDot, statusLabel } from './FileNavigator'
import { HighlightedCodeLine } from './syntaxHighlighter'

const rowHeight = 26

export { FileNavigator } from './FileNavigator'
export { useCodeNavigation } from './useCodeNavigation'

export function ProjectCodeWorkspace({
  index,
  source,
  diff,
  selectedPath,
  selectedFindingId,
  view,
  onSelectFile,
  onSelectFinding,
  onView,
  onNavigateLine,
  onRetrySource,
  sourceError,
  diffError,
}: {
  index: ProjectCodeFileIndex
  source: ProjectCodeFileView | null
  diff: ProjectCodeDiffResponse | null
  selectedPath: string | null
  selectedFindingId: string | null
  view: ProjectCodeView
  onSelectFile: (path: string) => void
  onSelectFinding: (finding: ProjectCodeFinding | null) => void
  onView: (view: ProjectCodeView) => void
  onNavigateLine?: (line: number) => void
  onRetrySource: () => void
  sourceError: string | null
  diffError: string | null
}) {
  const [search, setSearch] = useState('')
  const [changedOnly, setChangedOnly] = useState(false)
  const [findingsOnly, setFindingsOnly] = useState(false)
  const [status, setStatus] = useState('all')

  const files = useMemo(() => {
    const query = search.trim().toLowerCase()
    return index.files.filter((file) =>
      (!query || file.path.toLowerCase().includes(query)) &&
      (!changedOnly || file.status !== 'unchanged') &&
      (!findingsOnly || file.findingCount > 0) &&
      (status === 'all' || file.status === status),
    )
  }, [changedOnly, findingsOnly, index.files, search, status])

  const findings = useMemo(
    () => [...(source?.findings ?? [])].sort((a, b) => a.location.startLine - b.location.startLine || a.id.localeCompare(b.id)),
    [source],
  )
  const selectedFinding = findings.find((finding) => finding.id === selectedFindingId) ?? null
  const selectedFile = index.files.find((file) => file.path === selectedPath) ?? null
  const contentError = view === 'source' ? sourceError : diffError

  const workspaceStatus = !selectedFile
    ? 'No source file selected'
    : contentError
      ? `${selectedFile.path}: ${contentError}`
      : view === 'source' && !source || view !== 'source' && !diff
        ? `Loading ${view} view for ${selectedFile.path}`
        : `${selectedFile.path}, ${view} view${selectedFinding ? `, finding ${findings.indexOf(selectedFinding) + 1} of ${findings.length}` : ''}`

  const { filesOpen, setFilesOpen, filesButton, filesPanel } = useCodeNavigation({
    findings,
    selectedFinding,
    onSelectFinding,
  })

  const navigator = (
    <FileNavigator
      index={index}
      files={files}
      selectedPath={selectedPath}
      search={search}
      changedOnly={changedOnly}
      findingsOnly={findingsOnly}
      status={status}
      onSearch={setSearch}
      onChangedOnly={setChangedOnly}
      onFindingsOnly={setFindingsOnly}
      onStatus={setStatus}
      onSelect={(path) => {
        onSelectFile(path)
        setFilesOpen(false)
      }}
    />
  )

  return (
    <div className="space-y-3">
      <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">
        {workspaceStatus}
      </div>

      {/* Mobile Drawer Trigger */}
      <div className="flex items-center justify-between gap-3 lg:hidden">
        <Button
          variant="secondary"
          onClick={(event) => {
            filesButton.current = event.currentTarget
            setFilesOpen(true)
          }}
          aria-haspopup="dialog"
        >
          <Files className="size-4" /> Browse files
        </Button>
        <span className="min-w-0 truncate font-mono text-xs text-tertiary">
          {selectedFile?.path ?? 'Select a file'}
        </span>
      </div>

      {filesOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <button
            type="button"
            aria-label="Close files"
            onClick={() => setFilesOpen(false)}
            className="absolute inset-0 bg-black/60"
          />
          <aside
            ref={filesPanel}
            tabIndex={-1}
            role="dialog"
            aria-modal="true"
            aria-label="Captured files"
            className="absolute inset-y-0 left-0 flex w-[min(90vw,22rem)] flex-col border-r border-secondary bg-primary shadow-2xl outline-none"
          >
            <div className="flex h-14 items-center justify-between border-b border-secondary px-4">
              <h2 className="text-sm font-semibold text-primary">Captured files</h2>
              <Button
                variant="ghost"
                className="min-h-11 min-w-11 px-0"
                onClick={() => setFilesOpen(false)}
                aria-label="Close files"
              >
                <XClose className="size-5" />
              </Button>
            </div>
            {navigator}
          </aside>
        </div>
      )}

      {/* IDE Code Workspace Layout */}
      <div className="flex min-h-[36rem] overflow-hidden rounded-xl border border-secondary bg-primary shadow-xs lg:h-[max(40rem,calc(100dvh-18rem))]">
        {/* Left File Navigator (Sidebar) */}
        <aside className="hidden w-72 shrink-0 flex-col border-r border-secondary bg-secondary/20 lg:flex">
          {navigator}
        </aside>

        {/* Right Code Viewer & Inspector */}
        <section className="flex min-w-0 flex-1 flex-col bg-primary">
          <WorkspaceHeader
            file={selectedFile}
            source={source}
            index={index}
            view={view}
            diff={diff}
            findings={findings}
            onView={onView}
          />
          {!selectedFile ? (
            <EmptyState
              icon={FileCode2}
              title="Select a source file"
              hint="Choose a captured file to inspect the immutable analysis snapshot."
            />
          ) : view === 'source' ? (
            !selectedFile.sourceAvailable ? (
              <Unavailable file={selectedFile} />
            ) : sourceError ? (
              <PaneError message={sourceError} onRetry={onRetrySource} />
            ) : !source ? (
              <CodeSkeleton />
            ) : (
              <SourcePane
                source={source}
                findings={findings}
                selectedFinding={selectedFinding}
                onSelectFinding={onSelectFinding}
                onNavigateLine={onNavigateLine}
              />
            )
          ) : diffError ? (
            <PaneError message={diffError} onRetry={onRetrySource} />
          ) : diff ? (
            <DiffPane diff={diff} split={view === 'split'} filename={selectedFile.path} />
          ) : (
            <CodeSkeleton />
          )}
        </section>
      </div>
    </div>
  )
}

function WorkspaceHeader({
  file,
  source,
  index,
  view,
  diff,
  findings,
  onView,
}: {
  file: ProjectCodeFile | null
  source: ProjectCodeFileView | null
  index: ProjectCodeFileIndex
  view: ProjectCodeView
  diff: ProjectCodeDiffResponse | null
  findings: ProjectCodeFinding[]
  onView: (view: ProjectCodeView) => void
}) {
  const [copied, setCopied] = useState(false)
  const enabled = (candidate: ProjectCodeView) =>
    candidate === 'source' ||
    (!!file &&
      file.status !== 'unchanged' &&
      (candidate === 'unified' ? index.capabilities.unifiedDiff : index.capabilities.splitDiff))

  const unavailableReason =
    view === 'unified'
      ? diff?.capabilities.unifiedDiff.reason
      : view === 'split'
        ? diff?.capabilities.splitDiff.reason
        : null

  function copyPath() {
    if (!file?.path) return
    navigator.clipboard.writeText(file.path).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }).catch(() => {})
  }

  // Count findings by domain
  const secCount = findings.filter((f) => f.type === 'vulnerability').length
  const bugCount = findings.filter((f) => f.type === 'bug').length
  const smellCount = findings.filter((f) => f.type === 'code_smell').length
  const hotspotCount = findings.filter((f) => f.kind === 'hotspot' || f.type === 'security_hotspot').length

  // Breadcrumbs tokens
  const pathParts = file?.path ? file.path.split('/') : []
  const fileName = pathParts.length > 0 ? pathParts[pathParts.length - 1] : 'Code workspace'
  const folderParts = pathParts.slice(0, -1)

  return (
    <header className="shrink-0 border-b border-secondary bg-primary">
      {/* Row 1: Interactive Breadcrumbs & View Modes */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 border-b border-secondary/60 bg-secondary/15">
        {/* Breadcrumbs */}
        <div className="flex flex-wrap items-center gap-1.5 min-w-0 text-xs">
          <FolderClosed className="size-3.5 text-tertiary shrink-0" aria-hidden="true" />
          {folderParts.map((folder, idx) => (
            <span key={idx} className="flex items-center gap-1.5 text-tertiary font-mono">
              <span>{folder}</span>
              <span className="text-quaternary font-sans">/</span>
            </span>
          ))}
          <div className="flex items-center gap-1.5 font-mono font-bold text-primary">
            <File02 className="size-3.5 text-brand-secondary shrink-0" aria-hidden="true" />
            <span className="truncate">{fileName}</span>
          </div>

          {/* Copy Button */}
          {file?.path && (
            <button
              type="button"
              onClick={copyPath}
              className="ml-1 inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-sans font-medium text-tertiary hover:bg-secondary hover:text-primary transition-colors border border-transparent hover:border-secondary shadow-2xs"
              title={copied ? 'Copied path!' : `Copy: ${file.path}`}
              aria-label="Copy file path"
            >
              {copied ? (
                <Check className="size-3 text-success-primary" aria-hidden="true" />
              ) : (
                <Copy01 className="size-3" aria-hidden="true" />
              )}
              <span className="hidden sm:inline">{copied ? 'Copied' : 'Copy'}</span>
            </button>
          )}

          {file && (
            <Pill className="ml-1 capitalize text-[10px] py-0.2">
              <StatusDot status={file.status} />
              {statusLabel(file.status)}
            </Pill>
          )}
        </div>

        {/* View Mode Switcher */}
        <div className="flex items-center rounded-lg border border-secondary bg-secondary p-0.5" aria-label="Code view">
          {(['source', 'unified', 'split'] as const).map((candidate) => (
            <button
              key={candidate}
              type="button"
              disabled={!enabled(candidate)}
              aria-pressed={view === candidate}
              onClick={() => onView(candidate)}
              className={cn(
                'rounded-md px-2.5 py-1 text-[11px] font-semibold capitalize transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 disabled:cursor-not-allowed disabled:opacity-40',
                view === candidate
                  ? 'bg-primary text-brand-secondary shadow-2xs border border-secondary/60'
                  : 'text-tertiary hover:text-primary',
              )}
            >
              {candidate}
            </button>
          ))}
        </div>
      </div>

      {/* Row 2: SonarQube-style File Quality Metrics Bar */}
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1.5 px-4 py-2 text-xs bg-primary">
        <div className="flex flex-wrap items-center gap-4 text-[11px]">
          <div className="flex items-center gap-1.5 text-secondary font-medium">
            <span className="text-tertiary">Lines:</span>
            <span className="font-mono font-bold text-primary tabular-nums">
              {source?.totalLines ?? '—'}
            </span>
          </div>

          <div className="h-3 w-px bg-secondary" />

          <div className="flex items-center gap-1.5 text-secondary font-medium">
            <span className="text-tertiary">Duplications:</span>
            <span className="font-mono font-bold text-primary">0.0%</span>
          </div>

          <div className="h-3 w-px bg-secondary" />

          {/* Quality Domains on this File */}
          <div className="flex items-center gap-3">
            <span
              className={cn(
                'inline-flex items-center gap-1 font-semibold',
                secCount > 0 ? 'text-error-primary' : 'text-tertiary',
              )}
            >
              <ShieldTick className="size-3" />
              <span>Security</span>
              <span className="font-mono font-bold">({secCount})</span>
            </span>

            <span
              className={cn(
                'inline-flex items-center gap-1 font-semibold',
                bugCount > 0 ? 'text-warning-primary' : 'text-tertiary',
              )}
            >
              <Virus className="size-3" />
              <span>Reliability</span>
              <span className="font-mono font-bold">({bugCount})</span>
            </span>

            <span
              className={cn(
                'inline-flex items-center gap-1 font-semibold',
                smellCount > 0 ? 'text-utility-blue-600 dark:text-utility-blue-400' : 'text-tertiary',
              )}
            >
              <Tool01 className="size-3" />
              <span>Maintainability</span>
              <span className="font-mono font-bold">({smellCount})</span>
            </span>

            {hotspotCount > 0 && (
              <span className="inline-flex items-center gap-1 font-semibold text-warning-primary">
                <Zap className="size-3" />
                <span>Hotspots</span>
                <span className="font-mono font-bold">({hotspotCount})</span>
              </span>
            )}
          </div>
        </div>

        {/* Unavailable reason or revision info */}
        {unavailableReason ? (
          <span className="text-xs text-error-primary font-medium">{humanReason(unavailableReason)}</span>
        ) : (
          <div className="hidden xl:flex items-center gap-2 text-[10px] text-tertiary">
            <span>Analysis <span className="font-mono text-secondary">{short(index.analysisId)}</span></span>
          </div>
        )}
      </div>
    </header>
  )
}

function SourcePane({
  source,
  findings,
  selectedFinding,
  onSelectFinding,
  onNavigateLine,
}: {
  source: ProjectCodeFileView
  findings: ProjectCodeFinding[]
  selectedFinding: ProjectCodeFinding | null
  onSelectFinding: (finding: ProjectCodeFinding | null) => void
  onNavigateLine?: (line: number) => void
}) {
  const parent = useRef<HTMLDivElement>(null)

  const byLine = useMemo(() => {
    return source.findings.reduce<Record<number, ProjectCodeFinding[]>>((out, finding) => {
      for (let line = finding.location.startLine; line <= finding.location.endLine; line++) {
        ;(out[line] ??= []).push(finding)
      }
      return out
    }, {})
  }, [source.findings])

  const virtual = useVirtualizer({
    count: source.lines.length,
    getScrollElement: () => parent.current,
    estimateSize: (index) => {
      const line = source.lines[index]
      const isFindingExpanded = selectedFinding && line.number === selectedFinding.location.endLine
      return isFindingExpanded ? 160 : rowHeight
    },
    overscan: 25,
    initialRect: { width: 900, height: 512 },
  })

  useEffect(() => {
    if (!selectedFinding) return
    const index = source.lines.findIndex((line) => line.number === selectedFinding.location.startLine)
    if (index >= 0) {
      virtual.scrollToIndex(index, { align: 'center' })
    }
  }, [selectedFinding, source.lines, virtual])

  const items = virtual.getVirtualItems()
  const visible = items.length ? items : source.lines.map((_, index) => ({ index, size: rowHeight, start: index * rowHeight }))
  const hasPrevious = source.fromLine > 1
  const hasNext = source.toLine < source.totalLines

  const currentFindingIndex = selectedFinding ? findings.findIndex((f) => f.id === selectedFinding.id) : -1

  return (
    <div className="flex min-h-0 flex-1 flex-col bg-primary">
      {/* Lines & Finding Quick Navigator Header */}
      <div className="flex min-h-8.5 shrink-0 items-center justify-between gap-3 border-b border-secondary bg-secondary/30 px-3 text-xs">
        <span className="font-mono text-[11px] tabular-nums text-secondary font-medium">
          Lines {source.fromLine.toLocaleString()}–{source.toLine.toLocaleString()}{' '}
          <span className="text-tertiary">of {source.totalLines.toLocaleString()}</span>
        </span>

        {/* Inline Finding Skipper */}
        {findings.length > 0 && (
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => {
                  const prev = findings[(currentFindingIndex - 1 + findings.length) % findings.length]
                  onSelectFinding(prev)
                }}
                className="inline-flex items-center gap-0.5 rounded px-2 py-0.5 border border-secondary bg-primary text-[11px] font-semibold text-secondary hover:bg-secondary hover:text-primary shadow-2xs transition-all"
                aria-label="Previous finding"
                title="Previous finding (shortcut [)"
              >
                <ChevronLeft className="size-3" />
                <span>Prev</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  const next = findings[(currentFindingIndex + 1) % findings.length]
                  onSelectFinding(next)
                }}
                className="inline-flex items-center gap-0.5 rounded px-2 py-0.5 border border-secondary bg-primary text-[11px] font-semibold text-secondary hover:bg-secondary hover:text-primary shadow-2xs transition-all"
                aria-label="Next finding"
                title="Next finding (shortcut ])"
              >
                <span>Next</span>
                <ChevronRight className="size-3" />
              </button>
            </div>
            <span className="text-[11px] font-semibold text-primary font-mono">
              {selectedFinding ? `${currentFindingIndex + 1}/${findings.length}` : `${findings.length} findings`}
            </span>
          </div>
        )}

        {/* 1,000 Lines Window Skipper */}
        {(hasPrevious || hasNext) && (
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              className="h-7 px-2 text-[11px]"
              disabled={!hasPrevious}
              onClick={() => onNavigateLine?.(Math.max(1, source.fromLine - PROJECT_CODE_SOURCE_WINDOW))}
              aria-label="Previous 1,000 lines"
            >
              <ChevronLeft className="size-3.5" /> Prev 1k
            </Button>
            <Button
              variant="ghost"
              className="h-7 px-2 text-[11px]"
              disabled={!hasNext}
              onClick={() => onNavigateLine?.(source.toLine + 1)}
              aria-label="Next 1,000 lines"
            >
              Next 1k <ChevronRight className="size-3.5" />
            </Button>
          </div>
        )}
      </div>

      {/* Antigravity IDE Code Body */}
      <div
        ref={parent}
        role="grid"
        aria-label="Source code"
        aria-rowcount={source.lines.length}
        className="min-h-0 flex-1 overflow-auto bg-primary font-mono text-xs antialiased selection:bg-brand/30"
      >
        <div
          role="rowgroup"
          className="relative min-w-max"
          style={{ height: `${Math.max(virtual.getTotalSize(), source.lines.length * rowHeight)}px` }}
        >
          {visible.map((item) => {
            const line = source.lines[item.index]
            const lineFindings = byLine[line.number] ?? []
            const isHighlightLine =
              !!selectedFinding &&
              line.number >= selectedFinding.location.startLine &&
              line.number <= selectedFinding.location.endLine
            const isCardLine = !!selectedFinding && line.number === selectedFinding.location.endLine

            return (
              <div
                key={line.number}
                ref={virtual.measureElement}
                data-index={item.index}
                className={cn(
                  'group absolute left-0 top-0 flex flex-col w-full border-b border-secondary/15 transition-colors',
                  isHighlightLine
                    ? 'bg-brand-primary/10 border-l-2 border-l-brand-solid'
                    : 'hover:bg-secondary/40',
                  line.change === 'addition' && !isHighlightLine && 'bg-success-primary/5',
                  line.duplicated && !isHighlightLine && 'bg-warning-primary/5',
                )}
                style={{ transform: `translateY(${item.start}px)` }}
              >
                {/* Code Row */}
                <div className="flex w-full items-stretch min-h-[26px]">
                  {/* Gutter Line Number */}
                  <span
                    role="rowheader"
                    className={cn(
                      'sticky left-0 z-10 w-12 shrink-0 select-none border-r border-secondary bg-primary px-2 text-right leading-6.5 tabular-nums text-tertiary group-hover:text-primary transition-colors',
                      isHighlightLine && 'bg-brand-primary/20 text-brand-secondary font-bold',
                      line.change === 'addition' && 'border-l-2 border-l-success-primary',
                    )}
                  >
                    {line.number}
                  </span>

                  {/* Findings Gutter Column */}
                  <span
                    role="gridcell"
                    className={cn(
                      'sticky left-12 z-10 flex w-7 shrink-0 items-center justify-center border-r border-secondary bg-primary',
                      isHighlightLine && 'bg-brand-primary/20',
                    )}
                  >
                    {lineFindings.length > 0 && (
                      <button
                        type="button"
                        aria-label={`${lineFindings.length} finding${lineFindings.length === 1 ? '' : 's'} on line ${line.number}`}
                        onClick={() => {
                          const isCurrentlySelected = selectedFinding && lineFindings.some((f) => f.id === selectedFinding.id)
                          onSelectFinding(isCurrentlySelected ? null : lineFindings[0])
                        }}
                        className={cn(
                          'flex size-4.5 items-center justify-center rounded-full text-[10px] font-extrabold shadow-2xs transition-all',
                          selectedFinding && lineFindings.some((f) => f.id === selectedFinding.id)
                            ? 'bg-error-primary text-white ring-2 ring-error-primary/40'
                            : 'bg-error-primary/20 text-error-primary ring-1 ring-inset ring-error-primary/40 hover:bg-error-primary hover:text-white',
                        )}
                      >
                        {lineFindings.length}
                      </button>
                    )}
                  </span>

                  {/* Code Content with IDE Syntax Highlighting */}
                  <code
                    role="gridcell"
                    className={cn(
                      'whitespace-pre px-3 leading-6.5 font-mono text-xs flex-1',
                      line.coverage === 'uncovered' && 'decoration-error-primary underline decoration-dotted underline-offset-4',
                    )}
                  >
                    <HighlightedCodeLine
                      content={line.content}
                      filename={source.file.path}
                      finding={selectedFinding}
                      line={line.number}
                    />
                  </code>
                </div>

                {/* Embedded SonarQube Inline Finding Card */}
                {isCardLine && selectedFinding && (
                  <InlineFindingCard
                    finding={selectedFinding}
                    onClose={() => onSelectFinding(null)}
                  />
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function InlineFindingCard({
  finding,
  onClose,
}: {
  finding: ProjectCodeFinding
  onClose: () => void
}) {
  const isVuln = finding.type === 'vulnerability'
  const isBug = finding.type === 'bug'
  const TypeIcon = isVuln ? ShieldTick : isBug ? Virus : Tool01

  return (
    <div className="ml-20 my-2 mr-6 rounded-xl border border-error-primary/35 bg-primary shadow-xs font-sans text-xs overflow-hidden">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 bg-error-primary/10 border-b border-error-primary/20 px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1 rounded bg-error-primary/20 text-error-primary px-2 py-0.5 font-bold text-[11px] border border-error-primary/30">
            <TypeIcon className="size-3.5 shrink-0" />
            <span className="uppercase">{finding.severity}</span>
            <span>·</span>
            <span className="capitalize">{finding.type || finding.kind}</span>
          </span>
          {finding.isNew && (
            <span className="rounded bg-brand-primary/20 text-brand-secondary font-mono text-[10px] font-extrabold uppercase px-1.5 py-0.5 border border-brand/30">
              New
            </span>
          )}
          <span className="font-mono text-tertiary text-[11px]">{finding.ruleKey}</span>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded-lg p-1 text-tertiary hover:bg-secondary hover:text-primary transition-colors"
          aria-label="Close inline finding"
        >
          <XClose className="size-4" />
        </button>
      </div>

      {/* Body with Progressive Disclosure */}
      <div className="p-3.5 space-y-2 bg-primary">
        <h4 className="font-bold text-primary text-sm leading-snug">
          {finding.ruleName || finding.ruleKey}
        </h4>

        {/* Smart Collapsible Message */}
        <FindingMessageContent message={finding.message} />

        {/* Footer Meta */}
        <div className="mt-2.5 pt-2 border-t border-secondary flex flex-wrap items-center justify-between gap-2 text-[11px] text-tertiary">
          <div className="flex items-center gap-3">
            <span>
              Detected: <strong className="text-primary font-medium capitalize">{finding.detectionStatus || 'open'}</strong>
            </span>
            <span>
              Current: <strong className="text-primary font-medium capitalize">{finding.currentStatus || 'to_review'}</strong>
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

function FindingMessageContent({ message }: { message: string }) {
  const [expanded, setExpanded] = useState(false)

  if (!message) {
    return <p className="text-tertiary text-xs italic">No additional message provided.</p>
  }

  // Check for AppSec validation envelope or long technical trace
  const envelopeIndex = message.indexOf('AppSec validation envelope:')

  if (envelopeIndex !== -1) {
    const summary = message.slice(0, envelopeIndex).trim()
    const envelope = message.slice(envelopeIndex).trim()

    return (
      <div className="space-y-2">
        {summary && (
          <p className="text-secondary text-xs leading-relaxed font-sans font-medium">
            {summary}
          </p>
        )}
        <div className="rounded-lg border border-secondary/80 bg-secondary/25 overflow-hidden">
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="flex w-full items-center justify-between px-3 py-1.5 text-[11px] font-semibold text-secondary hover:bg-secondary/50 hover:text-primary transition-colors text-left"
          >
            <span className="inline-flex items-center gap-1.5 text-brand-secondary">
              <span>AppSec Validation Envelope</span>
              <span className="text-[10px] text-tertiary font-normal">
                {expanded ? '(click to collapse)' : '(click to inspect trace)'}
              </span>
            </span>
            <ChevronDown className={cn('size-3.5 transition-transform duration-200', expanded && 'rotate-180')} />
          </button>
          {expanded && (
            <div className="p-3 border-t border-secondary/60 bg-primary/80 font-mono text-[11px] leading-relaxed text-secondary whitespace-pre-wrap max-h-64 overflow-y-auto">
              {envelope}
            </div>
          )}
        </div>
      </div>
    )
  }

  // If long generic message without specific envelope marker
  const isLong = message.length > 220 || message.split('\n').length > 3

  if (!isLong) {
    return (
      <p className="text-secondary text-xs leading-relaxed font-mono whitespace-pre-wrap">
        {message}
      </p>
    )
  }

  return (
    <div className="space-y-1.5">
      <div
        className={cn(
          'font-mono text-xs leading-relaxed text-secondary whitespace-pre-wrap transition-all',
          !expanded && 'line-clamp-2',
        )}
      >
        {message}
      </div>
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="inline-flex items-center gap-1 text-[11px] font-semibold text-brand-secondary hover:underline"
      >
        <span>{expanded ? 'Show less' : 'Show full description'}</span>
        <ChevronDown className={cn('size-3 transition-transform duration-200', expanded && 'rotate-180')} />
      </button>
    </div>
  )
}

type DiffEntry =
  | { kind: 'hunk'; hunk: ProjectCodeDiffHunk; index: number; count: number }
  | { kind: 'unified'; row: ProjectCodeDiffRow; key: string }
  | { kind: 'split'; left: ProjectCodeDiffRow | null; right: ProjectCodeDiffRow | null; key: string }

function DiffPane({
  diff,
  split,
  filename,
}: {
  diff: ProjectCodeDiffResponse
  split: boolean
  filename: string
}) {
  const hunks = diff.diff.change.hunks
  const entries = useMemo<DiffEntry[]>(() => {
    return hunks.flatMap((hunk, hunkIndex) => {
      const header: DiffEntry = { kind: 'hunk', hunk, index: hunkIndex, count: hunks.length }
      if (split) {
        return [
          header,
          ...pairRows(hunk.rows).map(
            (pair, rowIndex): DiffEntry => ({
              kind: 'split',
              ...pair,
              key: `${hunkIndex}-${rowIndex}`,
            }),
          ),
        ]
      }
      return [
        header,
        ...hunk.rows.map(
          (row, rowIndex): DiffEntry => ({
            kind: 'unified',
            row,
            key: `${hunkIndex}-${rowIndex}`,
          }),
        ),
      ]
    })
  }, [hunks, split])

  const parent = useRef<HTMLDivElement>(null)
  const virtual = useVirtualizer({
    count: entries.length,
    getScrollElement: () => parent.current,
    estimateSize: () => rowHeight,
    overscan: 30,
    initialRect: { width: 900, height: 512 },
  })

  if (!hunks.length) {
    return (
      <EmptyState
        icon={GitCompareArrows}
        title="No textual changes"
        hint={
          diff.diff.change.status === 'mode_only'
            ? `File mode changed from ${diff.diff.change.modeOld || 'unknown'} to ${diff.diff.change.modeNew || 'unknown'}.`
            : 'This persisted change has no text rows to display.'
        }
      />
    )
  }

  const virtualItems = virtual.getVirtualItems()
  const visible = virtualItems.length ? virtualItems : entries.slice(0, 50).map((_, index) => ({ index, size: rowHeight, start: index * rowHeight }))

  return (
    <div
      ref={parent}
      role="table"
      aria-label={split ? 'Split code diff' : 'Unified code diff'}
      aria-rowcount={entries.length + 1}
      className="min-h-0 flex-1 overflow-auto bg-primary font-mono text-xs"
    >
      <div className={cn('min-w-max', split ? 'w-[72rem]' : 'w-full')}>
        <div className="sticky top-0 z-20 bg-primary/95 backdrop-blur border-b border-secondary">
          <div role="rowgroup">
            <div
              role="row"
              aria-rowindex={1}
              className={cn(
                'grid h-8 text-[10px] uppercase tracking-wider text-tertiary font-sans font-semibold',
                split ? 'grid-cols-2' : 'grid-cols-[3.5rem_3.5rem_1.5rem_minmax(30rem,1fr)]',
              )}
            >
              {split ? (
                <>
                  <span role="columnheader" className="px-3 leading-8">Base</span>
                  <span role="columnheader" className="border-l border-secondary px-3 leading-8">Head</span>
                </>
              ) : (
                <>
                  <span role="columnheader" className="px-2 text-right leading-8">Old</span>
                  <span role="columnheader" className="px-2 text-right leading-8">New</span>
                  <span role="columnheader" aria-label="Change" />
                  <span role="columnheader" className="px-3 leading-8">Content</span>
                </>
              )}
            </div>
          </div>
          {diff.diff.contextTruncated && (
            <p role="note" className="border-t border-secondary bg-warning-primary/10 px-3 py-1.5 font-sans text-xs text-warning-primary">
              Unchanged context is limited around each change.
            </p>
          )}
        </div>

        <div
          role="rowgroup"
          className="relative"
          style={{ height: `${Math.max(virtual.getTotalSize(), entries.length * rowHeight)}px` }}
        >
          {visible.map((item) => {
            const entry = entries[item.index]
            return (
              <div
                key={entry.kind === 'hunk' ? `hunk-${entry.index}` : entry.key}
                className="absolute left-0 top-0 w-full"
                style={{ height: item.size, transform: `translateY(${item.start}px)` }}
              >
                {entry.kind === 'hunk' ? (
                  <DiffHunkRow hunk={entry.hunk} index={entry.index} count={entry.count} rowIndex={item.index + 2} />
                ) : entry.kind === 'split' ? (
                  <SplitRow left={entry.left} right={entry.right} rowIndex={item.index + 2} filename={filename} />
                ) : (
                  <UnifiedRow row={entry.row} rowIndex={item.index + 2} filename={filename} />
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function DiffHunkRow({ hunk, index, count, rowIndex }: { hunk: ProjectCodeDiffHunk; index: number; count: number; rowIndex: number }) {
  const header = `@@ -${hunk.oldStart},${hunk.oldLines} +${hunk.newStart},${hunk.newLines} @@`
  return (
    <div
      role="row"
      aria-rowindex={rowIndex}
      aria-label={`Hunk ${index + 1} of ${count}`}
      className="flex h-full items-center justify-between border-y border-secondary bg-secondary/50 px-3 text-brand-secondary font-mono text-xs"
    >
      <span role="cell">{header}</span>
      <span role="cell" className="text-[10px] text-tertiary font-sans">
        Hunk {index + 1} / {count}
      </span>
    </div>
  )
}

function UnifiedRow({ row, rowIndex, filename }: { row: ProjectCodeDiffRow; rowIndex: number; filename: string }) {
  return (
    <div
      role="row"
      aria-rowindex={rowIndex}
      aria-label={`${row.kind} line ${row.newLine ?? row.oldLine ?? ''}`}
      className={cn(
        'grid h-full grid-cols-[3.5rem_3.5rem_1.5rem_minmax(30rem,1fr)] border-b border-secondary/15',
        row.kind === 'added' && 'bg-success-primary/10',
        row.kind === 'removed' && 'bg-error-primary/10',
      )}
    >
      <span role="cell" className="select-none border-r border-secondary px-2 text-right leading-6.5 tabular-nums text-tertiary">
        {row.oldLine ?? ''}
      </span>
      <span role="cell" className="select-none border-r border-secondary px-2 text-right leading-6.5 tabular-nums text-tertiary">
        {row.newLine ?? ''}
      </span>
      <span
        role="cell"
        aria-label={row.kind}
        className={cn(
          'select-none text-center leading-6.5 font-bold',
          row.kind === 'added' && 'text-success-primary',
          row.kind === 'removed' && 'text-error-primary',
        )}
      >
        {row.kind === 'added' ? '+' : row.kind === 'removed' ? '−' : ''}
      </span>
      <code role="cell" className="whitespace-pre px-3 leading-6.5 font-mono text-xs">
        <HighlightedCodeLine
          content={row.text}
          filename={filename}
          finding={null}
          line={row.newLine || row.oldLine || 1}
        />
        {row.noFinalNewline && <span className="ml-4 select-none text-tertiary italic">No newline at end of file</span>}
      </code>
    </div>
  )
}

function SplitRow({
  left,
  right,
  rowIndex,
  filename,
}: {
  left: ProjectCodeDiffRow | null
  right: ProjectCodeDiffRow | null
  rowIndex: number
  filename: string
}) {
  return (
    <div role="row" aria-rowindex={rowIndex} className="grid h-full grid-cols-2 border-b border-secondary/15">
      <DiffSide row={left} side="old" filename={filename} />
      <DiffSide row={right} side="new" filename={filename} />
    </div>
  )
}

function DiffSide({
  row,
  side,
  filename,
}: {
  row: ProjectCodeDiffRow | null
  side: 'old' | 'new'
  filename: string
}) {
  const removed = row?.kind === 'removed'
  const added = row?.kind === 'added'
  return (
    <div
      role="cell"
      aria-label={row ? `${row.kind} ${side} line ${side === 'old' ? row.oldLine ?? '' : row.newLine ?? ''}` : `${side} placeholder`}
      className={cn(
        'grid grid-cols-[3.5rem_1.5rem_minmax(28rem,1fr)]',
        removed && 'bg-error-primary/10',
        added && 'bg-success-primary/10',
        side === 'new' && 'border-l border-secondary',
      )}
    >
      <span className="select-none border-r border-secondary px-2 text-right leading-6.5 tabular-nums text-tertiary">
        {row ? (side === 'old' ? row.oldLine : row.newLine) ?? '' : ''}
      </span>
      <span
        aria-hidden="true"
        className={cn('select-none text-center leading-6.5 font-bold', removed && 'text-error-primary', added && 'text-success-primary')}
      >
        {removed ? '−' : added ? '+' : ''}
      </span>
      <code className="whitespace-pre px-3 leading-6.5 font-mono text-xs">
        {row?.text ? (
          <HighlightedCodeLine
            content={row.text}
            filename={filename}
            finding={null}
            line={(side === 'old' ? row.oldLine : row.newLine) || 1}
          />
        ) : (
          ''
        )}
        {row?.noFinalNewline && <span className="ml-4 select-none text-tertiary italic">No newline at end of file</span>}
      </code>
    </div>
  )
}

function pairRows(rows: ProjectCodeDiffRow[]): Array<{ left: ProjectCodeDiffRow | null; right: ProjectCodeDiffRow | null }> {
  const pairs: Array<{ left: ProjectCodeDiffRow | null; right: ProjectCodeDiffRow | null }> = []
  for (let index = 0; index < rows.length; ) {
    if (rows[index].kind === 'removed') {
      const removed: ProjectCodeDiffRow[] = []
      const added: ProjectCodeDiffRow[] = []
      while (rows[index]?.kind === 'removed') removed.push(rows[index++])
      while (rows[index]?.kind === 'added') added.push(rows[index++])
      for (let offset = 0; offset < Math.max(removed.length, added.length); offset++) {
        pairs.push({ left: removed[offset] ?? null, right: added[offset] ?? null })
      }
      continue
    }
    if (rows[index].kind === 'added') pairs.push({ left: null, right: rows[index++] })
    else {
      pairs.push({ left: rows[index], right: rows[index] })
      index++
    }
  }
  return pairs
}

function CodeSkeleton() {
  return (
    <div role="status" aria-label="Loading code" className="min-h-0 flex-1 overflow-hidden bg-primary p-4">
      <div className="mb-4 flex gap-3">
        <Skeleton className="h-8 w-44" />
        <Skeleton className="h-8 w-28" />
      </div>
      {Array.from({ length: 14 }, (_, index) => (
        <div key={index} className="mb-2 flex gap-3">
          <Skeleton className="h-4 w-12" />
          <Skeleton
            className={cn(
              'h-4',
              index % 3 === 0 ? 'w-2/3' : index % 3 === 1 ? 'w-5/6' : 'w-1/2',
            )}
          />
        </div>
      ))}
    </div>
  )
}

function short(value: string): string {
  return value.length > 12 ? value.slice(0, 12) : value
}

function humanReason(reason: string): string {
  return reason.replaceAll('_', ' ').replace(/^./, (letter) => letter.toUpperCase())
}

function Unavailable({ file }: { file: ProjectCodeFile }) {
  return (
    <EmptyState
      icon={FileCode2}
      title={file.binary ? 'Binary file' : 'Source preview unavailable'}
      hint={
        file.sourceReason
          ? `This captured file is unavailable: ${humanReason(file.sourceReason)}.`
          : 'Source was not retained for this immutable analysis.'
      }
    />
  )
}

function PaneError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="m-4 rounded-xl border border-error-primary/30 bg-error-primary/10 p-4">
      <p className="text-sm text-error-primary font-medium">{message}</p>
      <Button className="mt-3" variant="secondary" onClick={onRetry}>
        Retry
      </Button>
    </div>
  )
}
