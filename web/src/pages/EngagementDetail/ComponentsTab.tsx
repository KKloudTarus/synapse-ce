import { Package, SearchLg } from '@untitledui/icons'
import { useState } from 'react'
import { VirtualTable } from '../../components/synapse/VirtualTable'
import { Card, EmptyState } from '../../components/ui'
import type { ScanResult } from '../../lib/types'
import { ScanPrompt } from './VulnsTab'

export function ComponentsTab({ scan }: { scan: ScanResult | null }) {
  const [search, setSearch] = useState('')

  if (!scan) return <ScanPrompt icon={Package} what="the component inventory" />
  if (scan.components.length === 0) {
    return <EmptyState icon={Package} title="No packages" hint="Syft found no packages in this target." />
  }

  const query = search.trim().toLowerCase()
  const rows = scan.components
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name))
    .filter((c) => {
      if (!query) return true
      return [
        c.name,
        c.version,
        c.purl,
        ...c.licenses.map((l) => l.spdxId || l.name),
      ].some((v) => v?.toLowerCase().includes(query))
    })

  return (
    <Card bodyClass="p-0">
      <div className="flex items-center justify-between border-b border-secondary px-4 py-3">
        <span className="text-xs text-tertiary">
          {rows.length === scan.components.length
            ? `${scan.components.length} packages`
            : `${rows.length} of ${scan.components.length} packages`}
        </span>
        <div className="relative">
          <SearchLg className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-quaternary" />
          <input
            value={search}
            onChange={(e) => setSearch(e.currentTarget.value)}
            placeholder="Search packages…"
            aria-label="Search packages"
            className="h-8 w-56 rounded-md border border-secondary bg-primary pl-8 pr-3 text-xs text-primary placeholder:text-quaternary focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20"
          />
        </div>
      </div>
      <VirtualTable
        items={rows}
        rowKey={(c, i) => `${c.purl}-${i}`}
        columns={[
          { header: 'Package', className: 'flex-1 font-medium text-primary', cell: (c) => c.name },
          {
            header: 'Version',
            className: 'w-28 font-mono text-xs tabular-nums text-tertiary',
            cell: (c) => c.version || '–',
          },
          {
            header: 'License',
            className: 'w-44 text-xs text-tertiary',
            cell: (c) =>
              c.licenses.length === 0
                ? '–'
                : c.licenses.map((l) => l.spdxId || l.name).filter(Boolean).join(', ') || '–',
          },
          { header: 'PURL', className: 'flex-1 font-mono text-xs text-quaternary', cell: (c) => c.purl || '–' },
        ]}
      />
    </Card>
  )
}
