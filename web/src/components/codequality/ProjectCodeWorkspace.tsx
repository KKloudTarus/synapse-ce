import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ChevronLeft, ChevronRight, FileCode2, Files, GitCompareArrows, Search, X } from 'lucide-react'
import { Button, EmptyState, Input, Pill, Select, SevBadge, Skeleton, cn } from '../ui'
import { PROJECT_CODE_SOURCE_WINDOW } from '../../lib/projectCodeNavigation'
import type { ProjectCodeDiffHunk, ProjectCodeDiffResponse, ProjectCodeDiffRow, ProjectCodeFile, ProjectCodeFileIndex, ProjectCodeFileStatus, ProjectCodeFileView, ProjectCodeFinding, ProjectCodeView } from '../../lib/types'

const rowHeight = 28
const statusOptions = [
  { value: 'all', label: 'All statuses' },
  { value: 'modified', label: 'Modified' },
  { value: 'added', label: 'Added' },
  { value: 'deleted', label: 'Deleted' },
  { value: 'renamed', label: 'Renamed' },
  { value: 'copied', label: 'Copied' },
  { value: 'mode_only', label: 'Mode only' },
  { value: 'unchanged', label: 'Unchanged' },
]

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
  const [filesOpen, setFilesOpen] = useState(false)
  const filesButton = useRef<HTMLButtonElement>(null)
  const filesPanel = useRef<HTMLElement>(null)
  const files = useMemo(() => {
    const query = search.trim().toLowerCase()
    return index.files.filter((file) =>
      (!query || file.path.toLowerCase().includes(query)) &&
      (!changedOnly || file.status !== 'unchanged') &&
      (!findingsOnly || file.findingCount > 0) &&
      (status === 'all' || file.status === status),
    )
  }, [changedOnly, findingsOnly, index.files, search, status])
  const findings = useMemo(() => [...(source?.findings ?? [])].sort((a, b) => a.location.startLine - b.location.startLine || a.id.localeCompare(b.id)), [source])
  const selectedFinding = findings.find((finding) => finding.id === selectedFindingId) ?? null
  const selectedFile = index.files.find((file) => file.path === selectedPath) ?? null
  const workspaceStatus = !selectedFile
    ? 'No source file selected'
    : sourceError || diffError
      ? `${selectedFile.path}: ${sourceError ?? diffError}`
      : view === 'source' && !source || view !== 'source' && !diff
        ? `Loading ${view} view for ${selectedFile.path}`
        : `${selectedFile.path}, ${view} view${selectedFinding ? `, finding ${findings.indexOf(selectedFinding) + 1} of ${findings.length}` : ''}`

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target
      if (target instanceof Element && target.matches('input, textarea, select, [contenteditable=true]')) return
      if (event.key !== '[' && event.key !== ']') return
      if (!findings.length) return
      event.preventDefault()
      const at = selectedFinding ? findings.findIndex((finding) => finding.id === selectedFinding.id) : -1
      onSelectFinding(findings[(at + (event.key === ']' ? 1 : findings.length - 1)) % findings.length])
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [findings, onSelectFinding, selectedFinding])

  useEffect(() => {
    if (!filesOpen) return
    filesPanel.current?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setFilesOpen(false)
        return
      }
      if (event.key !== 'Tab' || !filesPanel.current) return
      const focusable = [...filesPanel.current.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])')]
      if (!focusable.length) return
      const first = focusable[0], last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      filesButton.current?.focus()
    }
  }, [filesOpen])

  const navigator = <FileNavigator
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
    onSelect={(path) => { onSelectFile(path); setFilesOpen(false) }}
  />

  return (
    <div className="space-y-3">
      <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">{workspaceStatus}</div>
      <div className="flex items-center justify-between gap-3 lg:hidden">
        <Button variant="secondary" onClick={(event) => { filesButton.current = event.currentTarget; setFilesOpen(true) }} aria-haspopup="dialog"><Files className="size-4" /> Browse files</Button>
        <span className="min-w-0 truncate font-mono text-xs text-mutedfg">{selectedFile?.path ?? 'Select a file'}</span>
      </div>

      {filesOpen && <div className="fixed inset-0 z-40 lg:hidden">
        <button type="button" aria-label="Close files" onClick={() => setFilesOpen(false)} className="absolute inset-0 bg-black/60" />
        <aside ref={filesPanel} tabIndex={-1} role="dialog" aria-modal="true" aria-label="Captured files" className="absolute inset-y-0 left-0 flex w-[min(90vw,22rem)] flex-col border-r border-border bg-surface shadow-2xl outline-none">
          <div className="flex h-14 items-center justify-between border-b border-border px-4">
            <h2 className="text-sm font-semibold">Captured files</h2>
            <Button variant="ghost" className="min-h-11 min-w-11 px-0" onClick={() => setFilesOpen(false)} aria-label="Close files"><X className="size-5" /></Button>
          </div>
          {navigator}
        </aside>
      </div>}

      <div className="elev flex min-h-[34rem] overflow-hidden rounded-xl border border-border bg-card lg:h-[max(38rem,calc(100dvh-20rem))]">
        <aside className="hidden w-72 shrink-0 flex-col border-r border-border bg-surface lg:flex">{navigator}</aside>
        <section className="flex min-w-0 flex-1 flex-col">
          <WorkspaceHeader file={selectedFile} index={index} view={view} diff={diff} onView={onView} />
          {!selectedFile ? <EmptyState icon={FileCode2} title="Select a source file" hint="Choose a captured file to inspect the immutable analysis snapshot." />
            : !selectedFile.sourceAvailable ? <Unavailable file={selectedFile} />
              : sourceError ? <PaneError message={sourceError} onRetry={onRetrySource} />
                : !source ? <CodeSkeleton />
                  : <>
                    {view === 'source'
                      ? <SourcePane source={source} selectedFinding={selectedFinding} onSelectFinding={onSelectFinding} onNavigateLine={onNavigateLine} />
                      : diffError ? <PaneError message={diffError} onRetry={onRetrySource} />
                        : diff ? <DiffPane diff={diff} split={view === 'split'} />
                          : <CodeSkeleton />}
                    <FindingPanel findings={findings} selected={selectedFinding} onSelect={onSelectFinding} />
                  </>}
        </section>
      </div>
    </div>
  )
}

function FileNavigator({ index, files, selectedPath, search, changedOnly, findingsOnly, status, onSearch, onChangedOnly, onFindingsOnly, onStatus, onSelect }: {
  index: ProjectCodeFileIndex
  files: ProjectCodeFile[]
  selectedPath: string | null
  search: string
  changedOnly: boolean
  findingsOnly: boolean
  status: string
  onSearch: (value: string) => void
  onChangedOnly: (value: boolean) => void
  onFindingsOnly: (value: boolean) => void
  onStatus: (value: string) => void
  onSelect: (path: string) => void
}) {
  const changed = index.files.filter((file) => file.status !== 'unchanged').length
  const withFindings = index.files.filter((file) => file.findingCount > 0).length
  return <>
    <div className="space-y-2.5 border-b border-border p-3">
      <div className="flex items-baseline justify-between gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-mutedfg">Files</h2>
        <span className="font-mono text-[11px] tabular-nums text-subtlefg">{files.length} / {index.files.length}</span>
      </div>
      <label className="relative block">
        <Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-subtlefg" aria-hidden="true" />
        <Input value={search} onChange={(event) => onSearch(event.target.value)} placeholder="Filter by path" aria-label="Filter files by path" className="h-9 py-2 pl-9 text-xs" />
      </label>
      <div className="grid grid-cols-2 gap-1.5">
        <FilterButton pressed={changedOnly} onClick={() => onChangedOnly(!changedOnly)}>Changed <span className="font-mono tabular-nums">{changed}</span></FilterButton>
        <FilterButton pressed={findingsOnly} onClick={() => onFindingsOnly(!findingsOnly)}>Findings <span className="font-mono tabular-nums">{withFindings}</span></FilterButton>
      </div>
      <Select value={status} onValueChange={onStatus} options={statusOptions} ariaLabel="Filter by file status" size="sm" className="w-full" />
    </div>
    <FileList files={files} selectedPath={selectedPath} onSelect={onSelect} />
  </>
}

function FilterButton({ pressed, onClick, children }: { pressed: boolean; onClick: () => void; children: ReactNode }) {
  return <button type="button" aria-pressed={pressed} onClick={onClick} className={cn('flex h-8 items-center justify-between rounded-md border px-2 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60', pressed ? 'border-brand/50 bg-brand/15 text-foreground' : 'border-border bg-card text-mutedfg hover:border-borderstrong hover:text-foreground')}>{children}</button>
}

function FileList({ files, selectedPath, onSelect }: { files: ProjectCodeFile[]; selectedPath: string | null; onSelect: (path: string) => void }) {
  const parent = useRef<HTMLDivElement>(null)
  const virtual = useVirtualizer({ count: files.length, getScrollElement: () => parent.current, estimateSize: () => 64, overscan: 12, initialRect: { width: 288, height: 512 } })
  if (!files.length) return <EmptyState icon={FileCode2} title="No matching files" hint="Change or clear the filters." />
  const items = virtual.getVirtualItems()
  const visible = items.length ? items : files.map((_, index) => ({ index, size: 64, start: index * 64 }))
  return <div ref={parent} className="min-h-0 flex-1 overflow-auto"><div className="relative" style={{ height: `${Math.max(virtual.getTotalSize(), files.length * 64)}px` }}>{visible.map((item) => {
    const file = files[item.index]
    const slash = file.path.lastIndexOf('/')
    const name = slash >= 0 ? file.path.slice(slash + 1) : file.path
    const directory = slash >= 0 ? file.path.slice(0, slash + 1) : ''
    const details = [statusLabel(file.status), file.changedLineCount ? `${file.changedLineCount} changed` : '', file.findingCount ? `${file.findingCount} findings` : '', file.generated ? 'generated' : '', file.binary ? 'binary' : '', !file.sourceAvailable ? 'unavailable' : ''].filter(Boolean)
    return <button key={file.path} type="button" onClick={() => onSelect(file.path)} aria-pressed={file.path === selectedPath} aria-label={`${file.path}, ${details.join(', ')}`} className={cn('absolute left-0 top-0 flex w-full items-stretch border-b border-border/60 text-left text-xs transition-colors hover:bg-elevated/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/60 aria-pressed:bg-brand/10', !file.sourceAvailable && 'text-subtlefg')} style={{ height: item.size, transform: `translateY(${item.start}px)` }}>
      <span className={cn('w-0.5 shrink-0 bg-transparent', file.path === selectedPath && 'bg-brand')} />
      <span className="min-w-0 flex-1 px-3 py-2">
        <span className="flex min-w-0 items-baseline"><span className="truncate font-mono text-subtlefg">{directory}</span><span className="shrink-0 font-mono font-medium text-foreground">{name}</span></span>
        <span className="mt-1.5 flex items-center gap-1.5 overflow-hidden whitespace-nowrap text-[10px] text-subtlefg"><StatusDot status={file.status} /><span className="capitalize">{statusLabel(file.status)}</span>{file.changedLineCount > 0 && <span>· {file.changedLineCount} Δ</span>}{file.findingCount > 0 && <span className="text-high">· {file.findingCount} findings</span>}{!file.sourceAvailable && <span>· unavailable</span>}</span>
      </span>
    </button>
  })}</div></div>
}

function WorkspaceHeader({ file, index, view, diff, onView }: { file: ProjectCodeFile | null; index: ProjectCodeFileIndex; view: ProjectCodeView; diff: ProjectCodeDiffResponse | null; onView: (view: ProjectCodeView) => void }) {
  const enabled = (candidate: ProjectCodeView) => candidate === 'source' || (!!file && file.status !== 'unchanged' && (candidate === 'unified' ? index.capabilities.unifiedDiff : index.capabilities.splitDiff))
  const revision = (value: string, digest: string) => value || digest
  const head = revision(index.head.commit, index.head.artifactDigest)
  const base = index.base && revision(index.base.commit, index.base.artifactDigest)
  const unavailableReason = view === 'unified' ? diff?.capabilities.unifiedDiff.reason : view === 'split' ? diff?.capabilities.splitDiff.reason : null
  return <header className="shrink-0 border-b border-border bg-surface">
    <div className="flex flex-wrap items-start justify-between gap-3 px-4 pb-3 pt-3.5">
      <div className="min-w-0">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h2 className="max-w-full truncate font-mono text-sm font-semibold" title={file?.path}>{file?.path ?? 'Code workspace'}</h2>
          {file && <Pill className="capitalize"><StatusDot status={file.status} />{statusLabel(file.status)}</Pill>}
          {file?.language && <span className="text-[11px] text-mutedfg">{file.language}</span>}
        </div>
        {file?.oldPath && <p className="mt-1.5 text-xs text-mutedfg">From <span className="font-mono text-foreground">{file.oldPath}</span></p>}
        {file?.status === 'deleted' && <p className="mt-1.5 text-xs text-mutedfg">Showing the retained base-side source.</p>}
      </div>
      <div className="flex rounded-lg border border-border bg-bg p-1" aria-label="Code view">
        {(['source', 'unified', 'split'] as const).map((candidate) => <button key={candidate} type="button" disabled={!enabled(candidate)} aria-pressed={view === candidate} onClick={() => onView(candidate)} className={cn('min-h-8 rounded-md px-3 text-xs font-medium capitalize transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 disabled:cursor-not-allowed disabled:text-subtlefg', view === candidate ? 'bg-brand text-brandfg shadow-sm' : 'text-mutedfg hover:bg-elevated hover:text-foreground')}>{candidate}</button>)}
      </div>
    </div>
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border/70 px-4 py-2 text-[11px] text-subtlefg">
      <span>Immutable analysis <span className="font-mono text-mutedfg">{short(index.analysisId)}</span></span>
      <span title={head}>head <span className="font-mono text-mutedfg">{short(head)}</span></span>
      {base && <span title={base}>base <span className="font-mono text-mutedfg">{short(base)}</span></span>}
      {view !== 'source' && !enabled(view) && <span className="text-high">Persisted {view} diff unavailable.</span>}
      {unavailableReason && <span className="text-high">{humanReason(unavailableReason)}</span>}
    </div>
  </header>
}

function SourcePane({ source, selectedFinding, onSelectFinding, onNavigateLine }: { source: ProjectCodeFileView; selectedFinding: ProjectCodeFinding | null; onSelectFinding: (finding: ProjectCodeFinding | null) => void; onNavigateLine?: (line: number) => void }) {
  const parent = useRef<HTMLDivElement>(null)
  const virtual = useVirtualizer({ count: source.lines.length, getScrollElement: () => parent.current, estimateSize: () => rowHeight, overscan: 30, initialRect: { width: 900, height: 512 } })
  const byLine = useMemo(() => source.findings.reduce<Record<number, ProjectCodeFinding[]>>((out, finding) => { for (let line = finding.location.startLine; line <= finding.location.endLine; line++) (out[line] ??= []).push(finding); return out }, {}), [source.findings])
  useEffect(() => { if (!selectedFinding) return; const index = source.lines.findIndex((line) => line.number === selectedFinding.location.startLine); if (index >= 0) virtual.scrollToIndex(index, { align: 'center' }) }, [selectedFinding, source.lines, virtual])
  const items = virtual.getVirtualItems()
  const visible = items.length ? items : source.lines.map((_, index) => ({ index, size: rowHeight, start: index * rowHeight }))
  const hasPrevious = source.fromLine > 1
  const hasNext = source.toLine < source.totalLines
  return <div className="flex min-h-0 flex-1 flex-col">
    <div className="flex min-h-10 shrink-0 items-center justify-between gap-3 border-b border-border bg-card px-3 text-xs">
      <span className="font-mono tabular-nums text-mutedfg">Lines {source.fromLine.toLocaleString()}–{source.toLine.toLocaleString()} <span className="text-subtlefg">of {source.totalLines.toLocaleString()}</span></span>
      {(hasPrevious || hasNext) && <div className="flex items-center gap-1">
        <Button variant="ghost" className="h-8 px-2" disabled={!hasPrevious} onClick={() => onNavigateLine?.(Math.max(1, source.fromLine - PROJECT_CODE_SOURCE_WINDOW))} aria-label="Previous 1,000 lines"><ChevronLeft className="size-4" /> Previous</Button>
        <Button variant="ghost" className="h-8 px-2" disabled={!hasNext} onClick={() => onNavigateLine?.(source.toLine + 1)} aria-label="Next 1,000 lines">Next <ChevronRight className="size-4" /></Button>
      </div>}
    </div>
    <div ref={parent} role="grid" aria-label="Source code" aria-rowcount={source.lines.length} className="min-h-0 flex-1 overflow-auto bg-bg font-mono text-xs">
      <div role="rowgroup" className="relative min-w-max" style={{ height: `${Math.max(virtual.getTotalSize(), source.lines.length * rowHeight)}px` }}>{visible.map((item) => {
        const line = source.lines[item.index]
        const findings = byLine[line.number] ?? []
        const selected = !!selectedFinding && line.number >= selectedFinding.location.startLine && line.number <= selectedFinding.location.endLine
        return <div key={line.number} role="row" aria-rowindex={item.index + 1} aria-label={`Line ${line.number}${line.change === 'addition' ? ', added' : ''}${line.duplicated ? ', duplicated' : ''}${line.coverage ? `, ${line.coverage}` : ''}`} className={cn('absolute left-0 top-0 flex w-full border-b border-border/20', selected && 'bg-brand/15', line.change === 'addition' && !selected && 'bg-accent/[0.06]', line.duplicated && !selected && 'bg-medium/[0.05]')} style={{ height: item.size, transform: `translateY(${item.start}px)` }}>
          <span role="rowheader" className={cn('sticky left-0 z-10 w-14 shrink-0 select-none border-r border-border bg-bg px-2 text-right leading-7 tabular-nums text-subtlefg', selected && 'bg-brand/15', line.change === 'addition' && 'border-l-2 border-l-accent')}>{line.number}</span>
          <span role="gridcell" className={cn('sticky left-14 z-10 flex w-8 shrink-0 items-center justify-center border-r border-border bg-bg', selected && 'bg-brand/15')}>
            {findings.length > 0 && <button type="button" aria-label={`${findings.length} finding${findings.length === 1 ? '' : 's'} on line ${line.number}`} onClick={() => onSelectFinding(findings[0])} className="min-w-5 rounded bg-critical/20 px-1 text-[10px] font-bold text-critical ring-1 ring-inset ring-critical/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand">{findings.length}</button>}
          </span>
          <code role="gridcell" className={cn('whitespace-pre px-3 leading-7', line.coverage === 'uncovered' && 'decoration-critical underline decoration-dotted underline-offset-4')}>{renderLine(line.content, selectedFinding, line.number)}</code>
        </div>
      })}</div>
    </div>
  </div>
}

function renderLine(content: string, finding: ProjectCodeFinding | null, line: number) {
  if (!finding || line < finding.location.startLine || line > finding.location.endLine) return content
  const start = line === finding.location.startLine ? finding.location.startColumn : null
  const end = line === finding.location.endLine ? finding.location.endColumn : null
  if (start === null && end === null) return <mark className="bg-critical/20 text-inherit">{content}</mark>
  const from = Math.max(0, start ?? 0), to = Math.max(from, Math.min(content.length, end ?? content.length))
  return <>{content.slice(0, from)}<mark className="bg-critical/25 text-inherit">{content.slice(from, to)}</mark>{content.slice(to)}</>
}

type DiffEntry =
  | { kind: 'hunk'; hunk: ProjectCodeDiffHunk; index: number; count: number }
  | { kind: 'unified'; row: ProjectCodeDiffRow; key: string }
  | { kind: 'split'; left: ProjectCodeDiffRow | null; right: ProjectCodeDiffRow | null; key: string }

function DiffPane({ diff, split }: { diff: ProjectCodeDiffResponse; split: boolean }) {
  const hunks = diff.diff.change.hunks
  const entries = useMemo<DiffEntry[]>(() => hunks.flatMap((hunk, hunkIndex) => {
    const header: DiffEntry = { kind: 'hunk', hunk, index: hunkIndex, count: hunks.length }
    if (split) return [header, ...pairRows(hunk.rows).map((pair, rowIndex): DiffEntry => ({ kind: 'split', ...pair, key: `${hunkIndex}-${rowIndex}` }))]
    return [header, ...hunk.rows.map((row, rowIndex): DiffEntry => ({ kind: 'unified', row, key: `${hunkIndex}-${rowIndex}` }))]
  }), [hunks, split])
  const parent = useRef<HTMLDivElement>(null)
  const virtual = useVirtualizer({ count: entries.length, getScrollElement: () => parent.current, estimateSize: () => rowHeight, overscan: 30, initialRect: { width: 900, height: 512 } })
  if (!hunks.length) return <EmptyState icon={GitCompareArrows} title="No textual changes" hint={diff.diff.change.status === 'mode_only' ? `File mode changed from ${diff.diff.change.modeOld || 'unknown'} to ${diff.diff.change.modeNew || 'unknown'}.` : 'This persisted change has no text rows to display.'} />
  const virtualItems = virtual.getVirtualItems()
  const visible = virtualItems.length ? virtualItems : entries.slice(0, 50).map((_, index) => ({ index, size: rowHeight, start: index * rowHeight }))
  return <div ref={parent} role="table" aria-label={split ? 'Split code diff' : 'Unified code diff'} aria-rowcount={entries.length + 1} className="min-h-0 flex-1 overflow-auto bg-bg font-mono text-xs">
    <div className={cn('min-w-max', split ? 'w-[72rem]' : 'w-full')}>
      <div className="sticky top-0 z-20 bg-card/95 backdrop-blur">
        <div role="rowgroup"><div role="row" aria-rowindex={1} className={cn('grid h-8 border-b border-border text-[10px] uppercase tracking-wider text-subtlefg', split ? 'grid-cols-2' : 'grid-cols-[4rem_4rem_2rem_minmax(30rem,1fr)]')}>
          {split ? <><span role="columnheader" className="px-3 leading-8">Base</span><span role="columnheader" className="border-l border-border px-3 leading-8">Head</span></> : <><span role="columnheader" className="px-2 text-right leading-8">Old</span><span role="columnheader" className="px-2 text-right leading-8">New</span><span role="columnheader" aria-label="Change" /><span role="columnheader" className="px-3 leading-8">Content</span></>}
        </div></div>
        {diff.diff.contextTruncated && <p role="note" className="border-b border-border bg-medium/10 px-3 py-2 font-sans text-xs text-mutedfg">Unchanged context is limited around each change.</p>}
      </div>
      <div role="rowgroup" className="relative" style={{ height: `${Math.max(virtual.getTotalSize(), entries.length * rowHeight)}px` }}>
        {visible.map((item) => {
          const entry = entries[item.index]
          return <div key={entry.kind === 'hunk' ? `hunk-${entry.index}` : entry.key} className="absolute left-0 top-0 w-full" style={{ height: item.size, transform: `translateY(${item.start}px)` }}>
            {entry.kind === 'hunk' ? <DiffHunkRow hunk={entry.hunk} index={entry.index} count={entry.count} rowIndex={item.index + 2} />
              : entry.kind === 'split' ? <SplitRow left={entry.left} right={entry.right} rowIndex={item.index + 2} />
                : <UnifiedRow row={entry.row} rowIndex={item.index + 2} />}
          </div>
        })}
      </div>
    </div>
  </div>
}

function DiffHunkRow({ hunk, index, count, rowIndex }: { hunk: ProjectCodeDiffHunk; index: number; count: number; rowIndex: number }) {
  const header = `@@ -${hunk.oldStart},${hunk.oldLines} +${hunk.newStart},${hunk.newLines} @@`
  return <div role="row" aria-rowindex={rowIndex} aria-label={`Hunk ${index + 1} of ${count}`} className="flex h-full items-center justify-between border-y border-border bg-elevated px-3 text-branddim"><span role="cell">{header}</span><span role="cell" className="text-[10px] text-subtlefg">Hunk {index + 1} / {count}</span></div>
}

function UnifiedRow({ row, rowIndex }: { row: ProjectCodeDiffRow; rowIndex: number }) {
  return <div role="row" aria-rowindex={rowIndex} aria-label={`${row.kind} line ${row.newLine ?? row.oldLine ?? ''}`} className={cn('grid h-full grid-cols-[4rem_4rem_2rem_minmax(30rem,1fr)] border-b border-border/20', row.kind === 'added' && 'bg-accent/[0.08]', row.kind === 'removed' && 'bg-critical/[0.08]')}>
    <span role="cell" className="select-none border-r border-border/60 px-2 text-right leading-7 tabular-nums text-subtlefg">{row.oldLine ?? ''}</span>
    <span role="cell" className="select-none border-r border-border/60 px-2 text-right leading-7 tabular-nums text-subtlefg">{row.newLine ?? ''}</span>
    <span role="cell" aria-label={row.kind} className={cn('select-none text-center leading-7', row.kind === 'added' && 'text-accent', row.kind === 'removed' && 'text-critical')}>{row.kind === 'added' ? '+' : row.kind === 'removed' ? '−' : ''}</span>
    <code role="cell" className="whitespace-pre px-3 leading-7">{row.text}{row.noFinalNewline && <span className="ml-4 select-none text-subtlefg">No newline at end of file</span>}</code>
  </div>
}

function SplitRow({ left, right, rowIndex }: { left: ProjectCodeDiffRow | null; right: ProjectCodeDiffRow | null; rowIndex: number }) {
  return <div role="row" aria-rowindex={rowIndex} className="grid h-full grid-cols-2 border-b border-border/20">
    <DiffSide row={left} side="old" />
    <DiffSide row={right} side="new" />
  </div>
}

function DiffSide({ row, side }: { row: ProjectCodeDiffRow | null; side: 'old' | 'new' }) {
  const removed = row?.kind === 'removed'
  const added = row?.kind === 'added'
  return <div role="cell" aria-label={row ? `${row.kind} ${side} line ${side === 'old' ? row.oldLine ?? '' : row.newLine ?? ''}` : `${side} placeholder`} className={cn('grid grid-cols-[4rem_2rem_minmax(28rem,1fr)]', removed && 'bg-critical/[0.08]', added && 'bg-accent/[0.08]', side === 'new' && 'border-l border-border')}>
    <span className="select-none border-r border-border/60 px-2 text-right leading-7 tabular-nums text-subtlefg">{row ? (side === 'old' ? row.oldLine : row.newLine) ?? '' : ''}</span>
    <span aria-hidden="true" className={cn('select-none text-center leading-7', removed && 'text-critical', added && 'text-accent')}>{removed ? '−' : added ? '+' : ''}</span>
    <code className="whitespace-pre px-3 leading-7">{row?.text ?? ''}{row?.noFinalNewline && <span className="ml-4 select-none text-subtlefg">No newline at end of file</span>}</code>
  </div>
}

function pairRows(rows: ProjectCodeDiffRow[]): Array<{ left: ProjectCodeDiffRow | null; right: ProjectCodeDiffRow | null }> {
  const pairs: Array<{ left: ProjectCodeDiffRow | null; right: ProjectCodeDiffRow | null }> = []
  for (let index = 0; index < rows.length;) {
    if (rows[index].kind === 'removed') {
      const removed: ProjectCodeDiffRow[] = []
      const added: ProjectCodeDiffRow[] = []
      while (rows[index]?.kind === 'removed') removed.push(rows[index++])
      while (rows[index]?.kind === 'added') added.push(rows[index++])
      for (let offset = 0; offset < Math.max(removed.length, added.length); offset++) pairs.push({ left: removed[offset] ?? null, right: added[offset] ?? null })
      continue
    }
    if (rows[index].kind === 'added') pairs.push({ left: null, right: rows[index++] })
    else { pairs.push({ left: rows[index], right: rows[index] }); index++ }
  }
  return pairs
}

function FindingPanel({ findings, selected, onSelect }: { findings: ProjectCodeFinding[]; selected: ProjectCodeFinding | null; onSelect: (finding: ProjectCodeFinding | null) => void }) {
  const panel = useRef<HTMLElement>(null)
  const drag = useRef<{ y: number; height: number } | null>(null)
  const [height, setHeight] = useState(192)
  const resize = useCallback((next: number) => {
    const workspaceHeight = panel.current?.parentElement?.clientHeight ?? 0
    const max = workspaceHeight ? Math.max(128, Math.min(480, Math.floor(workspaceHeight * 0.6))) : 480
    setHeight(Math.max(128, Math.min(max, next)))
  }, [])
  useEffect(() => {
    const onMove = (event: PointerEvent) => { if (drag.current) resize(drag.current.height + drag.current.y - event.clientY) }
    const onUp = () => { drag.current = null }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
    window.addEventListener('pointercancel', onUp)
    return () => {
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', onUp)
      window.removeEventListener('pointercancel', onUp)
    }
  }, [resize])
  if (!findings.length) return null
  const index = selected ? findings.findIndex((finding) => finding.id === selected.id) : -1
  return <aside ref={panel} aria-label="Findings" className="flex shrink-0 flex-col border-t border-border bg-surface" style={selected ? { height } : undefined}>
    {selected && <div
      role="separator"
      aria-label="Resize finding details"
      aria-orientation="horizontal"
      aria-valuemin={128}
      aria-valuemax={480}
      aria-valuenow={height}
      tabIndex={0}
      title="Drag or use arrow keys to resize finding details"
      className="group flex h-2 shrink-0 touch-none cursor-row-resize items-center justify-center outline-none focus-visible:bg-brand/10"
      onPointerDown={(event) => { event.preventDefault(); drag.current = { y: event.clientY, height } }}
      onKeyDown={(event) => {
        if (event.key !== 'ArrowUp' && event.key !== 'ArrowDown') return
        event.preventDefault()
        resize(height + (event.key === 'ArrowUp' ? 24 : -24))
      }}
    ><span className="h-0.5 w-12 rounded-full bg-borderstrong transition-colors group-hover:bg-brand group-focus-visible:bg-brand" /></div>}
    <div className="flex min-h-11 shrink-0 items-center justify-between gap-2 px-3">
      <div className="flex items-center gap-1">
        <Button variant="ghost" className="h-8 px-2" onClick={() => onSelect(findings[(index + findings.length - 1) % findings.length])} aria-label="Previous finding, shortcut left bracket"><ChevronLeft className="size-4" /></Button>
        <Button variant="ghost" className="h-8 px-2" onClick={() => onSelect(findings[(index + 1) % findings.length])} aria-label="Next finding, shortcut right bracket"><ChevronRight className="size-4" /></Button>
        <span className="ml-1 text-xs font-medium">{selected ? `Finding ${index + 1} of ${findings.length}` : `${findings.length} findings`}</span>
        <span className="hidden text-[10px] text-subtlefg sm:inline">Use [ and ] to navigate</span>
      </div>
      {selected && <Button variant="ghost" className="h-8 px-2" onClick={() => onSelect(null)}>Close details</Button>}
    </div>
    {selected && <div className="grid min-h-0 flex-1 gap-3 overflow-auto border-t border-border bg-card px-4 py-3 text-sm lg:grid-cols-[minmax(0,1fr)_18rem]">
      <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><SevBadge sev={selected.severity} /><Pill>{selected.type || selected.kind}</Pill>{selected.isNew && <Pill>New</Pill>}</div><p className="mt-2 font-medium">{selected.ruleName || selected.ruleKey}</p><p className="mt-1 text-xs leading-relaxed text-mutedfg">{selected.message || selected.location.file}</p></div>
      <dl className="grid grid-cols-2 gap-2 text-xs"><div className="rounded-md bg-elevated px-3 py-2"><dt className="text-subtlefg">Detected status</dt><dd className="mt-1 font-medium">{selected.detectionStatus || 'Unavailable'}</dd></div><div className="rounded-md bg-elevated px-3 py-2"><dt className="text-subtlefg">Current status</dt><dd className="mt-1 font-medium">{selected.currentStatus ?? 'Unavailable'}</dd></div></dl>
    </div>}
  </aside>
}

function CodeSkeleton() {
  return <div role="status" aria-label="Loading code" className="min-h-0 flex-1 overflow-hidden bg-bg p-4"><div className="mb-4 flex gap-3"><Skeleton className="h-8 w-44" /><Skeleton className="h-8 w-28" /></div>{Array.from({ length: 12 }, (_, index) => <div key={index} className="mb-2 flex gap-3"><Skeleton className="h-4 w-12" /><Skeleton className={cn('h-4', index % 3 === 0 ? 'w-2/3' : index % 3 === 1 ? 'w-5/6' : 'w-1/2')} /></div>)}</div>
}

function StatusDot({ status }: { status: ProjectCodeFileStatus }) {
  return <span aria-hidden="true" className={cn('inline-block size-1.5 shrink-0 rounded-sm', status === 'added' && 'bg-accent', status === 'deleted' && 'bg-critical', status === 'unchanged' && 'bg-borderstrong', status !== 'added' && status !== 'deleted' && status !== 'unchanged' && 'bg-brand')} />
}

function statusLabel(status: ProjectCodeFileStatus): string { return status === 'mode_only' ? 'mode only' : status }
function short(value: string): string { return value.length > 12 ? value.slice(0, 12) : value }
function humanReason(reason: string): string { return reason.replaceAll('_', ' ').replace(/^./, (letter) => letter.toUpperCase()) }
function Unavailable({ file }: { file: ProjectCodeFile }) { return <EmptyState icon={FileCode2} title={file.binary ? 'Binary file' : 'Source preview unavailable'} hint={file.sourceReason ? `This captured file is unavailable: ${humanReason(file.sourceReason)}.` : 'Source was not retained for this immutable analysis.'} /> }
function PaneError({ message, onRetry }: { message: string; onRetry: () => void }) { return <div className="m-4 rounded-lg border border-critical/40 bg-critical/10 p-4"><p className="text-sm text-foreground">{message}</p><Button className="mt-3" variant="secondary" onClick={onRetry}>Retry</Button></div> }
