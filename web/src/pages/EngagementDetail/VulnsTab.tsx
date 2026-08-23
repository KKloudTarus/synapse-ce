import { CheckCircle, Scale01, SearchLg, ShieldZap } from '@untitledui/icons'
import { useMemo, useState } from 'react'
import { Column, VirtualTable } from '../../components/synapse/VirtualTable'
import { Card, EmptyState, SevBadge, cn } from '../../components/ui'
import { findingKindLabel } from '../../lib/format'
import { SEVERITY_ORDER, sevSoft } from '../../lib/severity'
import type { ScanResult, Severity, Vulnerability } from '../../lib/types'

export function vulnKey(v: Vulnerability): string {
  return `vuln:${v.id}:${v.component}:${v.version}`
}

export function shortPkg(id: string): string {
  const last = id.split('/').pop() ?? id
  return last.split('@')[0] || last
}

export function packageVersionKey(component: string, version: string): string {
  return `${component}\x00${version}`
}

export function vulnPackageKey(v: Vulnerability): string {
  return packageVersionKey(v.component, v.version)
}

export function packageLocationMap(components: ScanResult['components']): Map<string, string[]> {
  const m = new Map<string, string[]>()
  for (const c of components) {
    const loc = c.location.trim()
    if (!loc) continue
    const key = packageVersionKey(c.name, c.version)
    const cur = m.get(key) ?? []
    if (!cur.includes(loc)) m.set(key, [...cur, loc])
  }
  return m
}

export function countVulnerabilityFindings(vulns: Vulnerability[], locations: Map<string, string[]>): number {
  let n = 0
  for (const v of vulns) {
    const locs = locations.get(vulnPackageKey(v))
    n += locs && locs.length > 0 ? locs.length : 1
  }
  return n
}

export interface VulnerabilityDisplayRow {
  key: string
  component: string
  cve: string
  severity: Severity
  installed: string
  fixedVersion: string
  location: string
  direct: boolean
  via: string
  sourceLabel: string
  sourceFile: string
  relationshipLabel: string
  dependencyPath: string
  isFirstInPackage: boolean
  packageCveCount: number
}

export const LOCKFILE_BASENAMES = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'gemfile.lock',
  'poetry.lock',
  'pipfile.lock',
  'uv.lock',
  'go.sum',
  'cargo.lock',
  'composer.lock',
  'packages.lock.json',
  'gradle.lockfile',
])

export const MANIFEST_BASENAMES = new Set([
  'package.json',
  'go.mod',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'settings.gradle',
  'settings.gradle.kts',
  'requirements.txt',
  'requirements-dev.txt',
  'requirements-test.txt',
  'pyproject.toml',
  'pipfile',
  'cargo.toml',
  'gemfile',
  'composer.json',
  'packages.config',
  'csproj',
  'libs.versions.toml',
])

export function basename(path: string): string {
  const normalized = path.replace(/\\/g, '/')
  return normalized.slice(normalized.lastIndexOf('/') + 1).toLowerCase()
}

export function dependencySourceLabel(location: string): { label: string; file: string } {
  const file = location.trim()
  if (!file) return { label: 'SBOM / resolver', file: '' }
  const base = basename(file)
  if (LOCKFILE_BASENAMES.has(base)) return { label: 'Lockfile', file }
  if (MANIFEST_BASENAMES.has(base) || base.endsWith('.csproj') || base.endsWith('.fsproj') || base.endsWith('.vbproj')) {
    return { label: 'Manifest', file }
  }
  if (file.includes('node_modules/') || file.endsWith('.jar') || file.includes('/target/') || file.includes('/build/')) {
    return { label: 'Build output', file }
  }
  return { label: 'SBOM location', file }
}

export function dependencyRelationshipLabel(direct: boolean, path: string[], via: string): string {
  if (direct) return 'Direct'
  if (via) return `Transitive via ${via}`
  if (path.length > 1) return 'Transitive'
  return 'Unknown path'
}

export function vulnerabilityRowMatchesSearch(row: VulnerabilityDisplayRow, query: string): boolean {
  if (!query) return true
  return [
    row.component,
    row.cve,
    row.severity,
    row.installed,
    row.fixedVersion,
    row.location,
    row.sourceLabel,
    row.relationshipLabel,
    row.dependencyPath,
  ].some((value) => value.toLowerCase().includes(query))
}

export function componentIdentity(name: string, version: string, purl: string): string {
  if (purl) return purl
  if (version) return `${name}@${version}`
  return name
}

export function dependencyPathToRoot(dependencies: ScanResult['dependencies'], target: string): string[] {
  if (!target) return []
  const dependents = new Map<string, string[]>()
  const hasDependent = new Set<string>()
  const inGraph = new Set<string>()
  for (const dep of dependencies) {
    inGraph.add(dep.ref)
    for (const child of dep.dependsOn) {
      inGraph.add(child)
      hasDependent.add(child)
      dependents.set(child, [...(dependents.get(child) ?? []), dep.ref])
    }
  }
  if (!inGraph.has(target)) return []
  if (!hasDependent.has(target)) return [target]
  const seen = new Set([target])
  const queue: Array<{ id: string; path: string[] }> = [{ id: target, path: [target] }]
  while (queue.length) {
    const cur = queue.shift()!
    for (const parent of dependents.get(cur.id) ?? []) {
      if (seen.has(parent)) continue
      seen.add(parent)
      const path = [parent, ...cur.path]
      if (!hasDependent.has(parent)) return path
      queue.push({ id: parent, path })
    }
  }
  return [target]
}

export function buildVulnerabilityDisplayRows(vulns: Vulnerability[], packageLocations: Map<string, string[]>): VulnerabilityDisplayRow[] {
  // Group rows by package, ordering packages (and CVEs within a package) by their FIRST
  // appearance in the already-risk-ordered (KEV -> EPSS x CVSS) input. Never re-rank by raw
  // CVSS severity – that would violate the risk-priority invariant.
  const packageOrder = new Map<string, number>()
  const cveOrder = new Map<string, number>()
  vulns.forEach((vuln, i) => {
    if (!packageOrder.has(vuln.component)) packageOrder.set(vuln.component, i)
    const ck = `${vuln.component}\x00${vuln.id}`
    if (!cveOrder.has(ck)) cveOrder.set(ck, i)
  })

  const rows = vulns.flatMap((vuln) => {
    const locations = packageLocations.get(vulnPackageKey(vuln)) ?? ['']
    return locations.map((location, index) => ({
      ...(() => {
        const via = vuln.path.length >= 2 ? shortPkg(vuln.path[vuln.path.length - 2]) : ''
        const source = dependencySourceLabel(location)
        return {
          key: `${vuln.id}\x00${vuln.component}\x00${vuln.version}\x00${vuln.fixedVersion}\x00${location}\x00${index}`,
          component: vuln.component,
          cve: vuln.id,
          severity: vuln.severity,
          installed: vuln.version,
          fixedVersion: vuln.fixedVersion,
          location,
          direct: vuln.direct,
          via,
          sourceLabel: source.label,
          sourceFile: source.file,
          relationshipLabel: dependencyRelationshipLabel(vuln.direct, vuln.path, via),
          dependencyPath: vuln.path.map(shortPkg).join(' › '),
          isFirstInPackage: false,
        }
      })(),
    }))
  })

  rows.sort((a, b) => {
    const pkgDelta = (packageOrder.get(a.component) ?? 0) - (packageOrder.get(b.component) ?? 0)
    if (pkgDelta !== 0) return pkgDelta
    const cveDelta =
      (cveOrder.get(`${a.component}\x00${a.cve}`) ?? 0) - (cveOrder.get(`${b.component}\x00${b.cve}`) ?? 0)
    if (cveDelta !== 0) return cveDelta
    // same CVE expanded across install paths/locations – stable, deterministic tiebreak
    return a.installed.localeCompare(b.installed) || a.location.localeCompare(b.location)
  })

  const packageCves = new Map<string, Set<string>>()
  for (const row of rows) {
    const cves = packageCves.get(row.component) ?? new Set<string>()
    cves.add(row.cve)
    packageCves.set(row.component, cves)
  }

  let previousPackage = ''
  return rows.map((row) => {
    const isFirstInPackage = row.component !== previousPackage
    previousPackage = row.component
    return { ...row, isFirstInPackage, packageCveCount: packageCves.get(row.component)?.size ?? 0 }
  })
}

export function VulnsTab({ scan }: { scan: ScanResult | null }) {
  const [filter, setFilter] = useState<Severity | 'all'>('all')
  const [search, setSearch] = useState('')
  const available = useMemo(() => new Set((scan?.vulnerabilities ?? []).map((v) => v.severity)), [scan?.vulnerabilities])
  // vulnerabilities arrive already risk-ordered (KEV -> EPSS x CVSS) from the API.
  const severityRows = useMemo(
    () => (scan?.vulnerabilities ?? []).filter((v) => filter === 'all' || v.severity === filter),
    [filter, scan?.vulnerabilities],
  )
  const packageLocations = useMemo(() => packageLocationMap(scan?.components ?? []), [scan?.components])
  const allSeverityDisplayRows = useMemo(() => buildVulnerabilityDisplayRows(severityRows, packageLocations), [packageLocations, severityRows])
  const query = search.trim().toLowerCase()
  const displayRows = useMemo(
    () => allSeverityDisplayRows.filter((row) => vulnerabilityRowMatchesSearch(row, query)),
    [allSeverityDisplayRows, query],
  )
  const shownPackages = new Set(displayRows.map((row) => packageVersionKey(row.component, row.installed))).size
  // Counts MUST equal the rows actually rendered: every advisory×package×location (incl.
  // non-CVE advisories), not distinct CVE ids – otherwise the headline undercounts the table.
  const shownAdvisories = displayRows.length
  const totalAdvisories = allSeverityDisplayRows.length
  const vulnColumns = useMemo<Column<VulnerabilityDisplayRow>[]>(
    () => [
      {
        header: 'Package',
        className: 'sticky left-0 z-10 w-64 bg-primary pr-2 font-mono text-xs text-primary',
        cell: (row) => (
          <div
            className={cn(
              'rounded-md px-2 py-1',
              row.isFirstInPackage ? 'bg-secondary/80 ring-1 ring-secondary/80' : 'select-none text-transparent',
            )}
            title={row.component}
          >
            <div className="truncate">{row.component}</div>
            {row.isFirstInPackage && (
              <div className="mt-0.5 font-sans text-[10px] uppercase tracking-wide text-quaternary">
                {row.packageCveCount.toLocaleString()} advisor{row.packageCveCount === 1 ? 'y' : 'ies'}
              </div>
            )}
          </div>
        ),
      },
      {
        header: 'Severity',
        className: 'w-24',
        cell: (row) => <SevBadge sev={row.severity} />,
      },
      {
        header: 'Advisory',
        className: 'w-44',
        cell: (row) => (
          <span
            className={cn(
              'inline-flex w-fit rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold ring-1 ring-inset',
              sevSoft[row.severity],
            )}
          >
            {row.cve}
          </span>
        ),
      },
      {
        header: 'Installed',
        className: 'w-28 font-mono text-xs',
        cell: (row) => (
          <span className="truncate text-critical" title={`${row.component}@${row.installed || 'unknown'}`}>
            {row.installed || 'unknown'}
          </span>
        ),
      },
      {
        header: 'Fixed Version',
        className: 'w-32 font-mono text-xs',
        cell: (row) =>
          row.fixedVersion ? <span className="text-accent">{row.fixedVersion}</span> : <span className="text-quaternary">–</span>,
      },
      {
        header: 'Source / Path',
        className: 'w-80 text-xs',
        cell: (row) => {
          const title = [
            row.sourceFile ? `${row.sourceLabel}: ${row.sourceFile}` : row.sourceLabel,
            row.dependencyPath ? `Path: ${row.dependencyPath}` : row.relationshipLabel,
          ].join('\n')
          return (
            <div className="min-w-0 space-y-1" title={title}>
              <div className="flex min-w-0 items-center gap-2">
                <span className="shrink-0 rounded-md bg-secondary px-1.5 py-0.5 font-mono text-[10px] uppercase text-tertiary ring-1 ring-secondary">
                  {row.sourceLabel}
                </span>
                <span className="truncate font-mono text-[11px] text-quaternary">{row.sourceFile || 'no source file'}</span>
              </div>
              <div className="truncate text-tertiary">
                {row.relationshipLabel}
                {row.dependencyPath && <span className="text-quaternary"> · {row.dependencyPath}</span>}
              </div>
            </div>
          )
        },
      },
    ],
    [],
  )

  if (!scan) return <ScanPrompt icon={ShieldZap} what="vulnerabilities" />
  if (scan.scanMode === 'licenses') {
    return <EmptyState icon={Scale01} title="Vulnerabilities skipped" hint="This run used license-only scan mode." />
  }
  if (scan.vulnerabilities.length === 0) {
    return (
      <EmptyState
        icon={CheckCircle}
        title="No known vulnerabilities"
        hint="OSV reported no advisories for these packages."
      />
    )
  }
  return (
    <Card bodyClass="p-0">
      <div className="space-y-3 border-b border-secondary p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <SeverityFilter value={filter} onChange={setFilter} available={available} />
          <div className="relative">
            <SearchLg className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-quaternary" />
            <input
              value={search}
              onChange={(event) => setSearch(event.currentTarget.value)}
              placeholder="Search CVE, package, source, path…"
              aria-label="Search vulnerabilities"
              className="h-8 w-72 rounded-md border border-secondary bg-primary pl-8 pr-3 text-xs text-primary placeholder:text-quaternary focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20"
            />
          </div>
        </div>
        <div className="grid gap-2 text-xs text-tertiary tabular-nums sm:grid-cols-2 xl:grid-cols-3">
          <div className="rounded-md bg-secondary/60 px-3 py-2 ring-1 ring-secondary">
            <div className="font-mono text-base font-semibold text-primary">{shownPackages.toLocaleString()}</div>
            <div>packages shown</div>
          </div>
          <div className="rounded-md bg-secondary/60 px-3 py-2 ring-1 ring-secondary">
            <div className="font-mono text-base font-semibold text-primary">{shownAdvisories.toLocaleString()}</div>
            <div>advisories shown</div>
          </div>
          <div className="rounded-md bg-secondary/60 px-3 py-2 ring-1 ring-secondary">
            <div className="font-mono text-base font-semibold text-tertiary">{totalAdvisories.toLocaleString()}</div>
            <div>total advisories after filters</div>
          </div>
        </div>
      </div>
      {displayRows.length === 0 ? (
        <div className="p-8 text-center">
          <div className="text-sm font-medium text-primary">No vulnerabilities match this filter.</div>
          <div className="mx-auto mt-2 max-w-xl text-xs leading-5 text-tertiary">
            Clear the search query or choose another severity to review all scanner advisories.
          </div>
        </div>
      ) : (
        <VirtualTable
          items={displayRows}
          totalItems={allSeverityDisplayRows.length}
          tableMinWidthClass="min-w-[1120px]"
          rowKey={(row) => row.key}
          rowHeight={64}
          rowClassName={(row) =>
            cn('items-center py-3', row.isFirstInPackage && 'border-t-2 border-t-primary bg-secondary/20')
          }
          columns={vulnColumns}
        />
      )}
    </Card>
  )
}

export function PriorityBadge({ priority }: { priority: number }) {
  const tone =
    priority <= 1
      ? 'bg-critical/15 text-critical ring-critical/30'
      : priority === 2
        ? 'bg-high/15 text-high ring-high/30'
        : priority === 3
          ? 'bg-medium/15 text-medium ring-medium/30'
          : 'bg-secondary text-quaternary ring-secondary'
  return (
    <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 font-mono text-xs font-semibold ring-1 ring-inset', tone)}>
      P{priority}
    </span>
  )
}

export const SCOPE_LABEL: Record<string, string> = {
  production: 'prod',
  development: 'dev',
  test: 'test',
  example: 'example',
  fixture: 'fixture',
  benchmark: 'bench',
  documentation: 'docs',
  unknown: '–',
}

export function ScopeBadge({ scope }: { scope: string }) {
  const bg = scope !== 'production' && scope !== 'unknown'
  return (
    <span className={cn('font-mono text-[11px]', bg ? 'text-quaternary' : 'text-tertiary')}>
      {SCOPE_LABEL[scope] ?? scope}
    </span>
  )
}

export function DetectedBy({ sources }: { sources: string[] }) {
  if (!sources || sources.length === 0) return <span className="text-quaternary">–</span>
  return (
    <div className="flex flex-wrap gap-1">
      {sources.map((s) => (
        <span
          key={s}
          className={cn(
            'rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1 ring-inset',
            s === 'grype' ? 'bg-brand-primary text-brand-secondary ring-brand' : 'bg-secondary text-tertiary ring-secondary',
          )}
        >
          {s}
        </span>
      ))}
    </div>
  )
}

export const CONFIDENCE_LABEL: Record<string, string> = {
  very_high: 'Very high',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  if (!confidence) return <span className="text-quaternary">–</span>
  const tone =
    confidence === 'very_high'
      ? 'bg-accent/10 text-accent ring-accent/25'
      : confidence === 'high'
        ? 'bg-brand-primary text-brand-secondary ring-brand'
        : confidence === 'medium'
          ? 'bg-secondary text-tertiary ring-secondary'
          : 'text-quaternary ring-secondary'
  return (
    <span className={cn('inline-flex rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset', tone)}>
      {CONFIDENCE_LABEL[confidence] ?? confidence}
    </span>
  )
}

export function KindBadge({ kind }: { kind: string }) {
  return (
    <span className="rounded bg-secondary px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide text-tertiary">
      {findingKindLabel(kind)}
    </span>
  )
}

export function KindFilter({ value, onChange, kinds }: { value: string; onChange: (v: string) => void; kinds: string[] }) {
  const opts = ['all', ...kinds]
  return (
    <div className="inline-flex items-center gap-0.5 rounded-lg bg-secondary p-1">
      {opts.map((o) => (
        <button
          key={o}
          onClick={() => onChange(o)}
          className={cn(
            'rounded-md px-3 py-1.5 text-xs font-medium transition-all',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
            value === o
              ? 'bg-primary text-primary shadow-xs'
              : 'text-tertiary hover:text-primary',
          )}
        >
          {o === 'all' ? 'All Kinds' : findingKindLabel(o)}
        </button>
      ))}
    </div>
  )
}

export function SeverityFilter({
  value,
  onChange,
  available,
}: {
  value: Severity | 'all'
  onChange: (v: Severity | 'all') => void
  available: Set<Severity>
}) {
  const opts: (Severity | 'all')[] = ['all', ...SEVERITY_ORDER.filter((s) => available.has(s))]
  return (
    <div className="inline-flex items-center gap-0.5 rounded-lg bg-secondary p-1">
      {opts.map((o) => (
        <button
          key={o}
          onClick={() => onChange(o)}
          className={cn(
            'rounded-md px-3 py-1.5 text-xs font-medium capitalize transition-all',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
            value === o
              ? 'bg-primary text-primary shadow-xs'
              : 'text-tertiary hover:text-primary',
          )}
        >
          {o === 'all' ? 'All' : o}
        </button>
      ))}
    </div>
  )
}

export function ScanPrompt({ icon, what }: { icon: React.ComponentType<{ className?: string }>; what: string }) {
  return <EmptyState icon={icon} title={`Run a scan to populate ${what}`} hint="Use the “Run scan” panel above." />
}

export function countEdges(scan: ScanResult): number {
  return scan.dependencies.reduce((n, d) => n + d.dependsOn.length, 0)
}

export function fmtDuration(start: string | null, end: string | null): string {
  if (!start) return '–'
  const s = new Date(start).getTime()
  const e = end ? new Date(end).getTime() : Date.now()
  const sec = Math.max(0, Math.round((e - s) / 1000))
  if (sec < 60) return `${sec}s`
  const m = Math.floor(sec / 60)
  return `${m}m ${sec % 60}s`
}

export function fmtWindow(from: string | null, to: string | null): string {
  const f = from ? new Date(from).toLocaleDateString() : '–'
  const t = to ? new Date(to).toLocaleDateString() : 'open'
  return `${f} → ${t}`
}
