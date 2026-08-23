import { useState } from 'react'
import { Scale01, SearchLg, ShieldZap } from '@untitledui/icons'
import { Column, VirtualTable } from '../../components/synapse/VirtualTable'
import { Card, EmptyState, cn } from '../../components/ui'
import { CATEGORY_LABEL, sevSoft } from '../../lib/severity'
import type { ScanResult, Severity } from '../../lib/types'
import { ScanPrompt, componentIdentity, dependencyPathToRoot, dependencyRelationshipLabel, dependencySourceLabel, shortPkg } from './VulnsTab'

export interface LicenseEntry {
  license: string
  category: string
  severity: Severity
}

export interface LicenseDisplayRow {
  key: string
  component: string
  version: string
  licenses: string[]
  categories: string[]
  // entries = the package's licenses kept SEPARATE (dual/multi-license packages are a
  // choice/OR, shown as one chip each with its own severity – not collapsed into one row).
  entries: LicenseEntry[]
  severity: Severity
  location: string
  source: string
  confidence: string
  sourceLabel: string
  sourceFile: string
  relationshipLabel: string
  dependencyPath: string
}

export const LICENSE_SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 }

export function licenseComponentKey(component: string): string {
  return component.trim().toLowerCase()
}

export function licenseSeverity(category: string): Severity {
  switch (category) {
    case 'proprietary':
      return 'critical'
    case 'copyleft':
      return 'high'
    case 'weak-copyleft':
      return 'medium'
    case 'permissive':
      return 'low'
    default:
      return 'unknown'
  }
}

export function LicenseChipStack({
  entries,
  render,
  title,
}: {
  entries: LicenseEntry[]
  render: (e: LicenseEntry) => string
  title?: (e: LicenseEntry) => string
}) {
  const items: LicenseEntry[] = entries.length ? entries : [{ license: 'UNKNOWN', category: 'unknown', severity: 'unknown' }]
  return (
    <div className="flex flex-col gap-1">
      {items.map((e, i) => (
        <span
          key={i}
          title={title?.(e)}
          className={cn(
            'inline-flex h-6 w-fit max-w-full items-center truncate rounded-md px-2 font-mono text-[11px] font-semibold ring-1 ring-inset',
            sevSoft[e.severity],
          )}
        >
          {render(e)}
        </span>
      ))}
    </div>
  )
}

export function buildLicenseComponentIndex(components: ScanResult['components']) {
  const byName = new Map<string, ScanResult['components'][number][]>()
  for (const component of components) {
    const keys = [component.name, component.version ? `${component.name}@${component.version}` : '']
      .map(licenseComponentKey)
      .filter(Boolean)
    for (const key of keys) {
      const existing = byName.get(key) ?? []
      byName.set(key, [...existing, component])
    }
  }
  return byName
}

export function licenseDisplayRowMatchesSearch(row: LicenseDisplayRow, query: string): boolean {
  if (!query) return true
  return [
    row.component,
    row.version,
    row.licenses.join(' '),
    row.categories.join(' '),
    row.severity,
    row.location,
    row.source,
    row.confidence,
    row.sourceLabel,
    row.sourceFile,
    row.relationshipLabel,
    row.dependencyPath,
  ].some((value) => value.toLowerCase().includes(query))
}

export function buildLicenseDisplayRows(
  licenses: ScanResult['licenses'],
  unknownPackages: ScanResult['components'],
  componentIndex: Map<string, ScanResult['components'][number][]>,
  dependencies: ScanResult['dependencies'],
): LicenseDisplayRow[] {
  const byPackage = new Map<string, LicenseDisplayRow>()
  const upsertRow = (
    componentName: string,
    component: ScanResult['components'][number] | null,
    licenseName: string,
    category: string,
    severity: Severity,
  ) => {
    const source = dependencySourceLabel(component?.location ?? '')
    const id = component ? componentIdentity(component.name, component.version, component.purl) : ''
    const path = dependencyPathToRoot(dependencies, id)
    const via = path.length >= 2 ? shortPkg(path[path.length - 2]) : ''
    const inferredDirect = path.length === 1
    const rowKey = `${component?.name || componentName || '–'}\x00${component?.version ?? ''}\x00${component?.location ?? ''}`
    const existing = byPackage.get(rowKey) ?? {
      key: rowKey,
      component: component?.name || componentName || '–',
      version: component?.version ?? '',
      licenses: [],
      categories: [],
      entries: [] as LicenseEntry[],
      severity: 'unknown' as Severity,
      location: component?.location ?? '',
      source: component?.licenseSource ?? '',
      confidence: component?.licenseConfidence ?? '',
      sourceLabel: source.label,
      sourceFile: source.file,
      relationshipLabel: dependencyRelationshipLabel(inferredDirect, path, via),
      dependencyPath: path.map(shortPkg).join(' › '),
    }
    if (licenseName && !existing.licenses.includes(licenseName)) {
      existing.licenses.push(licenseName)
      existing.entries.push({ license: licenseName, category: category || 'unknown', severity })
    }
    if (category && !existing.categories.includes(category)) existing.categories.push(category)
    // Authoritative server risk severity; keep the most severe across a package's licenses (row sort key).
    if (LICENSE_SEVERITY_RANK[severity] < LICENSE_SEVERITY_RANK[existing.severity]) existing.severity = severity
    byPackage.set(rowKey, existing)
  }

  for (const license of licenses) {
    const componentNames = license.components.length > 0 ? license.components : ['']
    for (const componentName of componentNames) {
      const matchedComponents = componentIndex.get(licenseComponentKey(componentName)) ?? []
      const componentRows = matchedComponents.length > 0 ? matchedComponents : [null]
      for (const component of componentRows) {
        upsertRow(
          componentName,
          component,
          license.license || 'UNKNOWN',
          license.category || 'unknown',
          (license.severity || licenseSeverity(license.category || 'unknown')) as Severity,
        )
      }
    }
  }

  for (const component of unknownPackages) {
    upsertRow(component.name, component, 'UNKNOWN', 'unknown', 'unknown')
  }

  return [...byPackage.values()].sort(
    (a, b) => LICENSE_SEVERITY_RANK[a.severity] - LICENSE_SEVERITY_RANK[b.severity] || a.component.localeCompare(b.component),
  )
}

export function LicenseCoverageHeader({ scan }: { scan: ScanResult }) {
  const c = scan.licenseCoverage
  if (c.total === 0) return null
  const tone = c.pct >= 90 ? 'bg-accent' : c.pct >= 60 ? 'bg-medium' : 'bg-critical'
  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm">
        <span className="font-medium text-primary">License coverage</span>
        <span className="font-mono tabular-nums text-tertiary">
          {c.pct.toFixed(0)}% · {c.detected.toLocaleString()} detected · {c.unknown.toLocaleString()} unknown
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-secondary">
        <div className={cn('h-full rounded-full transition-[width]', tone)} style={{ width: `${Math.max(1, c.pct)}%` }} />
      </div>
    </Card>
  )
}

export function LicensesTab({ scan }: { scan: ScanResult | null }) {
  const [search, setSearch] = useState('')

  if (!scan) return <ScanPrompt icon={Scale01} what="the license report" />
  if (scan.scanMode === 'vulnerabilities') {
    return <EmptyState icon={ShieldZap} title="Licenses skipped" hint="This run used vulnerability-only scan mode." />
  }
  const componentIndex = buildLicenseComponentIndex(scan.components)
  const unknownPackages = scan.components
    .filter((c) => !c.firstParty && c.licenses.length === 0)
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name))
  const allDisplayRows = buildLicenseDisplayRows(scan.licenses, unknownPackages, componentIndex, scan.dependencies)
  const displayRows = allDisplayRows.filter((row) => licenseDisplayRowMatchesSearch(row, search.trim().toLowerCase()))
  const packagesImpacted = displayRows.length
  const licenseColumns: Column<LicenseDisplayRow>[] = [
    {
      header: 'Packages',
      className: 'sticky left-0 z-10 w-72 bg-primary pr-2 font-mono text-xs text-primary',
      cell: (row) => <span title={row.version ? `${row.component}@${row.version}` : row.component}>{row.component}</span>,
    },
    {
      header: 'License',
      className: 'w-72 font-mono text-xs text-primary',
      // Multi-license packages are a CHOICE (OR) – show one chip per license (coloured by
      // its own severity), not a collapsed "A AND B" string.
      cell: (row) => <LicenseChipStack entries={row.entries} render={(e) => e.license} title={(e) => e.license} />,
    },
    {
      header: 'Severity',
      className: 'w-28',
      cell: (row) => <LicenseChipStack entries={row.entries} render={(e) => e.severity.toUpperCase()} />,
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
    {
      header: 'Category',
      className: 'w-56 text-sm text-tertiary',
      cell: (row) => (
        <div className="flex flex-col gap-1">
          {(row.entries.length ? row.entries : [{ category: 'unknown', severity: 'unknown' as Severity, license: '' }]).map((e, i) => (
            <span key={i} className="leading-6" title={e.category}>
              {CATEGORY_LABEL[e.category] ?? e.category.toUpperCase()}
            </span>
          ))}
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      <LicenseCoverageHeader scan={scan} />
      {scan.licenses.length === 0 ? (
        <EmptyState
          icon={Scale01}
          title="No licenses classified"
          hint="No license metadata resolved for these packages – see coverage above."
        />
      ) : (
        <Card bodyClass="p-0">
          <div className="space-y-3 border-b border-secondary p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-sm font-medium text-primary">License inventory</div>
                <div className="text-xs text-tertiary">All detected package licenses are listed without hiding allowed entries.</div>
              </div>
              <div className="relative">
                <SearchLg className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-quaternary" />
                <input
                  value={search}
                  onChange={(event) => setSearch(event.currentTarget.value)}
                  placeholder="Search package, license, source, path…"
                  aria-label="Search licenses"
                  className="h-8 w-72 rounded-md border border-secondary bg-primary pl-8 pr-3 text-xs text-primary placeholder:text-quaternary focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20"
                />
              </div>
            </div>
            <div className="grid gap-2 text-xs text-tertiary tabular-nums sm:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-md bg-secondary/60 px-3 py-2 ring-1 ring-secondary">
                <div className="font-mono text-base font-semibold text-primary">{displayRows.length.toLocaleString()}</div>
                <div>packages listed</div>
              </div>
              <div className="rounded-md bg-secondary/60 px-3 py-2 ring-1 ring-secondary">
                <div className="font-mono text-base font-semibold text-primary">{packagesImpacted.toLocaleString()}</div>
                <div>packages impacted</div>
              </div>
              <div className="rounded-md bg-secondary/60 px-3 py-2 ring-1 ring-secondary">
                <div className="font-mono text-base font-semibold text-tertiary">{allDisplayRows.length.toLocaleString()}</div>
                <div>total package rows</div>
              </div>
              <div className="rounded-md bg-secondary/60 px-3 py-2 ring-1 ring-secondary">
                <div className="font-mono text-base font-semibold text-quaternary">{unknownPackages.length.toLocaleString()}</div>
                <div>unknown-license packages</div>
              </div>
            </div>
          </div>
          {displayRows.length === 0 ? (
            <div className="p-8 text-center">
              <div className="text-sm font-medium text-primary">No licenses match this search.</div>
              <div className="mx-auto mt-2 max-w-xl text-xs leading-5 text-tertiary">
                Clear the search query to review the full license inventory.
              </div>
            </div>
          ) : (
            <VirtualTable
              items={displayRows}
              totalItems={allDisplayRows.length}
              tableMinWidthClass="min-w-[1120px]"
              rowKey={(row) => row.key}
              rowClassName={(row) => cn('py-3', row.entries.length > 1 ? 'items-start' : 'items-center')}
              rowHeight={(row) => Math.max(64, (row.entries.length || 1) * 32 + 20)}
              columns={licenseColumns}
            />
          )}
        </Card>
      )}
    </div>
  )
}
