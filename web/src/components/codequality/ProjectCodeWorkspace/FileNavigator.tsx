import { useRef, type ReactNode } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { FileCode01 as FileCode2, File02, SearchLg as Search, XClose } from '@untitledui/icons'
import { EmptyState, Select, cn } from '../../ui'
import type { ProjectCodeFile, ProjectCodeFileIndex, ProjectCodeFileStatus } from '../../../lib/types'

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

export function FileNavigator({
  index,
  files,
  selectedPath,
  search,
  changedOnly,
  findingsOnly,
  status,
  onSearch,
  onChangedOnly,
  onFindingsOnly,
  onStatus,
  onSelect,
}: {
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

  return (
    <>
      <div className="space-y-2.5 border-b border-secondary p-3 bg-primary">
        <div className="flex items-baseline justify-between gap-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-tertiary">Files</h2>
          <span className="font-mono text-[11px] tabular-nums text-secondary font-semibold">
            {files.length} / {index.files.length}
          </span>
        </div>

        {/* Search Input */}
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-tertiary" aria-hidden="true" />
          <input
            type="text"
            value={search}
            onChange={(event) => onSearch(event.target.value)}
            placeholder="Filter by path..."
            aria-label="Filter files by path"
            className="w-full rounded-lg border border-secondary bg-primary py-1.5 pl-8 pr-7 text-xs text-primary shadow-xs placeholder:text-tertiary focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/60"
          />
          {search && (
            <button
              type="button"
              onClick={() => onSearch('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-tertiary hover:bg-secondary hover:text-primary"
              aria-label="Clear search"
            >
              <XClose className="size-3" />
            </button>
          )}
        </div>

        {/* Filter Buttons */}
        <div className="grid grid-cols-2 gap-1.5">
          <FilterButton pressed={changedOnly} onClick={() => onChangedOnly(!changedOnly)}>
            <span>Changed</span>
            <span className="font-mono tabular-nums font-bold">{changed}</span>
          </FilterButton>
          <FilterButton pressed={findingsOnly} onClick={() => onFindingsOnly(!findingsOnly)}>
            <span>Findings</span>
            <span className="font-mono tabular-nums font-bold text-error-primary">{withFindings}</span>
          </FilterButton>
        </div>

        <Select
          value={status}
          onValueChange={onStatus}
          options={statusOptions}
          ariaLabel="Filter by file status"
          size="sm"
          className="w-full text-xs"
        />
      </div>

      <FileList files={files} selectedPath={selectedPath} onSelect={onSelect} />
    </>
  )
}

function FilterButton({ pressed, onClick, children }: { pressed: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={onClick}
      className={cn(
        'flex h-7.5 items-center justify-between rounded-lg border px-2 text-[11px] font-semibold transition-all shadow-2xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
        pressed
          ? 'border-brand-solid bg-brand-primary/10 text-brand-secondary ring-1 ring-brand-solid'
          : 'border-secondary bg-primary text-secondary hover:bg-secondary/60 hover:text-primary',
      )}
    >
      {children}
    </button>
  )
}

function FileList({
  files,
  selectedPath,
  onSelect,
}: {
  files: ProjectCodeFile[]
  selectedPath: string | null
  onSelect: (path: string) => void
}) {
  const parent = useRef<HTMLDivElement>(null)
  const virtual = useVirtualizer({
    count: files.length,
    getScrollElement: () => parent.current,
    estimateSize: () => 56,
    overscan: 12,
    initialRect: { width: 288, height: 512 },
  })

  if (!files.length) {
    return <EmptyState icon={FileCode2} title="No matching files" hint="Change or clear the filters." />
  }

  const items = virtual.getVirtualItems()
  const visible = items.length ? items : files.map((_, index) => ({ index, size: 56, start: index * 56 }))

  return (
    <div ref={parent} className="min-h-0 flex-1 overflow-auto bg-primary">
      <div className="relative" style={{ height: `${Math.max(virtual.getTotalSize(), files.length * 56)}px` }}>
        {visible.map((item) => {
          const file = files[item.index]
          const slash = file.path.lastIndexOf('/')
          const name = slash >= 0 ? file.path.slice(slash + 1) : file.path
          const directory = slash >= 0 ? file.path.slice(0, slash + 1) : ''
          const isSelected = file.path === selectedPath

          return (
            <button
              key={file.path}
              type="button"
              onClick={() => onSelect(file.path)}
              aria-pressed={isSelected}
              className={cn(
                'group absolute left-0 top-0 flex w-full items-stretch border-b border-secondary/40 text-left text-xs transition-all select-none',
                isSelected
                  ? 'bg-brand-primary/15 border-l-3 border-l-brand-solid shadow-2xs'
                  : 'border-l-3 border-l-transparent hover:bg-secondary/40',
                !file.sourceAvailable && 'opacity-60',
              )}
              style={{ height: item.size, transform: `translateY(${item.start}px)` }}
            >
              <div className="min-w-0 flex-1 px-3 py-1.5 flex flex-col justify-center">
                {/* File Name & Path */}
                <div className="flex min-w-0 items-center gap-1.5">
                  <File02 className={cn('size-3.5 shrink-0', isSelected ? 'text-brand-secondary' : 'text-tertiary')} aria-hidden="true" />
                  <div className="min-w-0 truncate font-mono">
                    {directory && <span className="text-tertiary text-[11px]">{directory}</span>}
                    <span className={cn('font-semibold', isSelected ? 'text-brand-secondary' : 'text-primary')}>
                      {name}
                    </span>
                  </div>
                </div>

                {/* Sub Metadata Pill Line */}
                <div className="mt-1 flex items-center gap-1.5 overflow-hidden whitespace-nowrap text-[10px] text-tertiary font-sans">
                  <StatusDot status={file.status} />
                  <span className="capitalize">{statusLabel(file.status)}</span>
                  {file.changedLineCount > 0 && <span className="font-mono text-success-primary font-bold">+{file.changedLineCount}</span>}
                  {file.findingCount > 0 && (
                    <span className="font-mono font-extrabold text-error-primary bg-error-primary/10 px-1 py-0.2 rounded border border-error-primary/25">
                      {file.findingCount} issues
                    </span>
                  )}
                  {!file.sourceAvailable && <span>(unavailable)</span>}
                </div>
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

export function StatusDot({ status }: { status: ProjectCodeFileStatus }) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        'inline-block size-1.5 shrink-0 rounded-full',
        status === 'added' && 'bg-success-primary',
        status === 'deleted' && 'bg-error-primary',
        status === 'unchanged' && 'bg-tertiary',
        status !== 'added' && status !== 'deleted' && status !== 'unchanged' && 'bg-brand-secondary',
      )}
    />
  )
}

export function statusLabel(status: ProjectCodeFileStatus): string {
  return status === 'mode_only' ? 'mode only' : status
}
