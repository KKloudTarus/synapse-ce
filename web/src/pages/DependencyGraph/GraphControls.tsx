import { GitFork, Network, Scale, Search, ShieldAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import { cn, Input, Select } from '../../components/ui'
import type { ScanResult } from '../../lib/types'
import { type GraphIndex, type SubGraph, resolveToId, shortName } from '../../lib/dependencyGraphUtils'

export type Mode = 'finding' | 'explorer' | 'license' | 'blast'

export const MODES: { id: Mode; label: string; icon: typeof Network; hint: string }[] = [
  { id: 'finding', label: 'Finding path', icon: ShieldAlert, hint: 'Why does this finding exist?' },
  { id: 'explorer', label: 'Package explorer', icon: Search, hint: 'Parents, children, and risk of a package.' },
  { id: 'license', label: 'License path', icon: Scale, hint: 'Why is this license here?' },
  { id: 'blast', label: 'Blast radius', icon: GitFork, hint: 'What depends on this package?' },
]

// ---- Mode Switcher ----

export function ModeSwitcher({ mode, setMode }: { mode: Mode; setMode: (m: Mode) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5 border-b border-border p-3">
      {MODES.map((m) => {
        const active = mode === m.id
        return (
          <button
            key={m.id}
            onClick={() => setMode(m.id)}
            title={m.hint}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
              active ? 'bg-brand/15 text-branddim ring-1 ring-inset ring-brand/30' : 'text-mutedfg hover:bg-elevated hover:text-foreground',
            )}
          >
            <m.icon className="size-4" />
            {m.label}
          </button>
        )
      })}
    </div>
  )
}

// ---- Per-mode Controls ----

interface ControlsProps {
  mode: Mode
  scan: ScanResult
  idx: GraphIndex
  sub: SubGraph
  vulnIdx: number
  setVulnIdx: (i: number) => void
  focusId: string | null
  setFocusId: (id: string) => void
  depth: number
  setDepth: (d: number) => void
  licId: string | null
  setLicId: (id: string | null) => void
  licenseOptions: { value: string; label: string }[]
  effLic: string | null
}

export function GraphControlsBar(props: ControlsProps) {
  const { mode, scan, idx, sub, vulnIdx, setVulnIdx, focusId, setFocusId, depth, setDepth, setLicId, licenseOptions, effLic } = props
  const focusMeta = sub.focus ? idx.meta.get(sub.focus) : null
  const focusVulns = sub.focus ? idx.vulnsById.get(sub.focus) ?? [] : []
  const selectedVuln = scan.vulnerabilities[vulnIdx]

  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
      {mode === 'finding' &&
        (scan.vulnerabilities.length === 0 ? (
          <span className="text-sm text-mutedfg">No vulnerabilities to trace.</span>
        ) : (
          <>
            <Select
              value={String(vulnIdx)}
              onValueChange={(v) => setVulnIdx(Number(v))}
              ariaLabel="Finding to trace"
              className="min-w-[18rem] max-w-full"
              options={scan.vulnerabilities.map((v, i) => ({
                value: String(i),
                label: `${v.severity.toUpperCase()} · ${v.id} · ${shortName(v.component)}`,
              }))}
            />
            {selectedVuln && (
              <div className="flex flex-wrap items-center gap-x-5 gap-y-1 font-mono text-xs text-mutedfg">
                <KV label="CVSS" value={selectedVuln.cvssScore > 0 ? selectedVuln.cvssScore.toFixed(1) : '–'} />
                <KV label="current" value={`${selectedVuln.component}@${selectedVuln.version}`} />
                <KV
                  label="fixed in"
                  value={selectedVuln.fixedVersion || '–'}
                  valueClass={selectedVuln.fixedVersion ? 'text-accent' : 'text-subtlefg'}
                />
              </div>
            )}
          </>
        ))}

      {(mode === 'explorer' || mode === 'blast') && (
        <>
          <ComponentPicker idx={idx} value={focusId} onPick={setFocusId} />
          {mode === 'explorer' && (
            <Select
              value={String(depth)}
              onValueChange={(v) => setDepth(Number(v))}
              ariaLabel="Explore depth"
              size="sm"
              options={[1, 2, 3].map((d) => ({ value: String(d), label: `depth ${d}` }))}
            />
          )}
          {focusMeta && (
            <span className="font-mono text-xs tabular-nums text-mutedfg">
              {mode === 'blast' ? `${sub.ids.size - 1} dependent package(s)` : `${sub.ids.size} package(s) in view`}
              {focusVulns.length > 0 && <span className="text-high"> · {focusVulns.length} finding(s)</span>}
            </span>
          )}
        </>
      )}

      {mode === 'license' &&
        (licenseOptions.length === 0 ? (
          <span className="text-sm text-mutedfg">No flagged-license packages in this scan.</span>
        ) : (
          <>
            <Select
              value={effLic ?? ''}
              onValueChange={setLicId}
              ariaLabel="Flagged-license component"
              className="min-w-[18rem] max-w-full"
              options={licenseOptions}
            />
            {focusMeta && (
              <span className="text-xs text-mutedfg">
                Why <span className="font-mono text-foreground">{focusMeta.name}</span> is here.
              </span>
            )}
          </>
        ))}
    </div>
  )
}

// ---- Helpers used by controls ----

export function useLicenseOptions(scan: ScanResult | null, idx: GraphIndex | null) {
  return useMemo(() => {
    if (!scan || !idx) return []
    const out: { value: string; label: string }[] = []
    const seen = new Set<string>()
    for (const l of scan.licenses) {
      const flagged = l.verdict !== 'allow' || l.category === 'copyleft' || l.category === 'weak-copyleft'
      if (!flagged) continue
      for (const c of l.components) {
        const id = resolveToId(idx, c)
        if (!id || seen.has(id)) continue
        seen.add(id)
        out.push({ value: id, label: `${l.license} · ${shortName(idx.meta.get(id)?.name ?? c)}` })
      }
    }
    return out
  }, [scan, idx])
}

// ---- ComponentPicker ----

function ComponentPicker({
  idx,
  value,
  onPick,
}: {
  idx: GraphIndex
  value: string | null
  onPick: (id: string) => void
}) {
  const [q, setQ] = useState('')
  const [active, setActive] = useState(0)
  const meta = value ? idx.meta.get(value) : null
  const matches = useMemo(() => {
    const s = q.trim().toLowerCase()
    if (!s) return []
    return idx.nameIndex.filter((n) => n.name.toLowerCase().includes(s)).slice(0, 8)
  }, [q, idx])

  const showList = q.trim().length > 0
  const act = matches.length ? Math.min(active, matches.length - 1) : 0

  function commit(i: number) {
    const m = matches[i]
    if (!m) return
    onPick(m.id)
    setQ('')
    setActive(0)
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Escape') {
      setQ('')
      setActive(0)
      return
    }
    if (!matches.length) return
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive(Math.min(act + 1, matches.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive(Math.max(act - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      commit(act)
    }
  }

  return (
    <div className="relative w-72 max-w-full">
      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-subtlefg" />
        <Input
          value={q}
          onChange={(e) => {
            setQ(e.target.value)
            setActive(0)
          }}
          onKeyDown={onKeyDown}
          role="combobox"
          aria-expanded={showList}
          aria-controls="component-picker-list"
          aria-autocomplete="list"
          aria-activedescendant={matches.length ? `cp-opt-${act}` : undefined}
          placeholder={meta ? `${meta.name}@${meta.version}` : 'Search a component…'}
          aria-label="Search a component"
          className="h-9 pl-8 font-mono text-xs"
        />
      </div>
      {showList && (
        <ul
          id="component-picker-list"
          role="listbox"
          className="absolute z-20 mt-1 max-h-64 w-full overflow-auto rounded-lg border border-border bg-card p-1 shadow-lg"
        >
          {matches.length === 0 ? (
            <li className="px-2 py-1.5 text-xs text-mutedfg">No packages match &ldquo;{q.trim()}&rdquo;.</li>
          ) : (
            matches.map((m, i) => (
              <li key={m.id} id={`cp-opt-${i}`} role="option" aria-selected={i === act}>
                <button
                  onClick={() => commit(i)}
                  onMouseEnter={() => setActive(i)}
                  tabIndex={-1}
                  className={cn(
                    'flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left text-xs transition-colors',
                    i === act ? 'bg-elevated' : 'hover:bg-elevated',
                  )}
                >
                  <span className="truncate font-mono text-foreground">{m.name}</span>
                  <span className="shrink-0 font-mono tabular-nums text-subtlefg">{m.version}</span>
                </button>
              </li>
            ))
          )}
        </ul>
      )}
    </div>
  )
}

function KV({ label, value, valueClass }: { label: string; value: string; valueClass?: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="text-[11px] uppercase tracking-wide text-subtlefg">{label}</span>
      <span className={cn('text-foreground tabular-nums', valueClass)}>{value}</span>
    </span>
  )
}
