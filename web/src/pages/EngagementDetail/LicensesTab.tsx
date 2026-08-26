import { useState } from 'react'
import { Package, Scale01, SearchLg, ShieldZap, XClose } from '@untitledui/icons'
import { Column, VirtualTable } from '../../components/synapse/VirtualTable'
import { Card, EmptyState, cn } from '../../components/ui'
import { CATEGORY_LABEL } from '../../lib/severity'
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
  const items: LicenseEntry[] = entries.length ? entries : [{ license: 'None', category: 'unknown', severity: 'unknown' }]
  return (
    <div className="flex flex-col gap-1">
      {items.map((e, i) => {
        const isPermissive = e.category === 'permissive' || e.severity === 'low'
        const isCopyleft = e.category === 'copyleft' || e.severity === 'high' || e.severity === 'critical'
        const tone = isPermissive
          ? 'border-utility-green-300 bg-success-primary text-success-primary'
          : isCopyleft
            ? 'border-utility-orange-300 bg-warning-primary text-warning-primary'
            : 'border-secondary bg-secondary text-tertiary'

        return (
          <span
            key={i}
            title={title?.(e)}
            className={cn(
              'inline-flex h-6 w-fit max-w-full items-center truncate rounded-md border px-2 font-mono text-xs font-semibold',
              tone,
            )}
          >
            {render(e)}
          </span>
        )
      })}
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
    const rowKey = `${component?.name || componentName || 'unknown'}\x00${component?.version ?? ''}\x00${component?.location ?? ''}`
    const existing = byPackage.get(rowKey) ?? {
      key: rowKey,
      component: component?.name || componentName || 'unknown',
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
          license.license || 'None',
          license.category || 'unknown',
          (license.severity || licenseSeverity(license.category || 'unknown')) as Severity,
        )
      }
    }
  }

  for (const component of unknownPackages) {
    upsertRow(component.name, component, 'None', 'unknown', 'unknown')
  }

  return [...byPackage.values()].sort(
    (a, b) => LICENSE_SEVERITY_RANK[a.severity] - LICENSE_SEVERITY_RANK[b.severity] || a.component.localeCompare(b.component),
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

  const coverage = scan.licenseCoverage
  const toneBar = coverage.pct >= 90 ? 'bg-utility-green-600' : coverage.pct >= 60 ? 'bg-utility-orange-600' : 'bg-error-primary'

  const licenseColumns: Column<LicenseDisplayRow>[] = [
    {
      header: 'Package',
      className: 'sticky left-0 z-10 w-72 bg-primary pr-2 font-semibold text-xs text-primary',
      cell: (row) => (
        <span className="truncate font-semibold text-primary" title={row.version ? `${row.component}@${row.version}` : row.component}>
          {row.component}
        </span>
      ),
    },
    {
      header: 'License',
      className: 'w-64 font-mono text-xs text-primary',
      cell: (row) => <LicenseChipStack entries={row.entries} render={(e) => e.license} title={(e) => e.license} />,
    },
    {
      header: 'Category',
      className: 'w-52 text-xs',
      cell: (row) => (
        <div className="flex flex-col gap-1">
          {(row.entries.length ? row.entries : [{ category: 'unknown', severity: 'unknown' as Severity, license: '' }]).map((e, i) => {
            const isPermissive = e.category === 'permissive'
            const isCopyleft = e.category === 'copyleft' || e.category === 'weak-copyleft'
            const tone = isPermissive
              ? 'border-utility-green-300 bg-success-primary text-success-primary'
              : isCopyleft
                ? 'border-utility-orange-300 bg-warning-primary text-warning-primary'
                : 'border-secondary bg-secondary text-tertiary'
            return (
              <span
                key={i}
                className={cn('inline-flex w-fit items-center rounded-md border px-2 py-0.5 text-xs font-semibold', tone)}
                title={e.category}
              >
                {CATEGORY_LABEL[e.category] ?? e.category.toUpperCase()}
              </span>
            )
          })}
        </div>
      ),
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
              <span className="shrink-0 rounded-md border border-secondary bg-secondary px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase text-tertiary">
                {row.sourceLabel}
              </span>
              <span className="truncate font-mono text-xs text-quaternary">{row.sourceFile || 'no source file'}</span>
            </div>
            <div className="truncate text-tertiary">
              {row.relationshipLabel}
              {row.dependencyPath && <span className="text-quaternary font-mono"> · {row.dependencyPath}</span>}
            </div>
          </div>
        )
      },
    },
  ]

  return (
    <Card bodyClass="p-0" className="overflow-hidden shadow-xs">
      {/* Unified Toolbar & Coverage Bar */}
      <div className="space-y-3.5 border-b border-secondary p-4 bg-primary">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative min-w-[16rem] sm:max-w-xs">
            <SearchLg className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-fg-tertiary" />
            <input
              value={search}
              onChange={(event) => setSearch(event.currentTarget.value)}
              placeholder="Search package, license, category..."
              aria-label="Search licenses"
              className="h-9 w-full rounded-lg border border-secondary bg-primary pl-9 pr-8 text-xs text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-quaternary hover:text-primary"
                title="Clear search"
              >
                <XClose className="size-3.5" />
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="inline-flex items-center gap-1.5 rounded-lg border border-utility-blue-200 bg-utility-blue-50 px-2.5 py-1 font-semibold text-utility-blue-700">
              <Package className="size-3.5" />
              <span>{displayRows.length} packages</span>
            </span>
            <span className="inline-flex items-center rounded-lg border border-utility-green-300 bg-success-primary px-2.5 py-1 font-semibold text-success-primary">
              {coverage.detected} detected
            </span>
            {coverage.unknown > 0 && (
              <span className="inline-flex items-center rounded-lg border border-secondary bg-secondary px-2.5 py-1 font-medium text-tertiary">
                {coverage.unknown} unknown
              </span>
            )}
          </div>
        </div>

        {/* Integrated Progress Coverage Bar */}
        {coverage.total > 0 && (
          <div className="space-y-1.5 pt-1">
            <div className="flex items-center justify-between text-xs font-semibold">
              <span className="text-secondary flex items-center gap-1.5">
                <Scale01 className="size-3.5 text-brand-secondary" />
                <span>License Coverage</span>
              </span>
              <span className="font-mono tabular-nums text-primary font-bold">
                {coverage.pct.toFixed(0)}%
              </span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
              <div
                className={cn('h-full rounded-full transition-all duration-300', toneBar)}
                style={{ width: `${Math.max(2, coverage.pct)}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Table */}
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
  )
}
