import { useRef, type ReactNode } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { FileCode2, Search } from 'lucide-react'
import { EmptyState, Input, Select, cn } from '../../ui'
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

export function FileNavigator({ index, files, selectedPath, search, changedOnly, findingsOnly, status, onSearch, onChangedOnly, onFindingsOnly, onStatus, onSelect }: {
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

export function StatusDot({ status }: { status: ProjectCodeFileStatus }) {
  return <span aria-hidden="true" className={cn('inline-block size-1.5 shrink-0 rounded-sm', status === 'added' && 'bg-accent', status === 'deleted' && 'bg-critical', status === 'unchanged' && 'bg-borderstrong', status !== 'added' && status !== 'deleted' && status !== 'unchanged' && 'bg-brand')} />
}

export function statusLabel(status: ProjectCodeFileStatus): string { return status === 'mode_only' ? 'mode only' : status }
