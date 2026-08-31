import { Check, Copy01, Package, SearchLg, XClose } from '@untitledui/icons'
import { copyText } from '../../lib/clipboard'
import { useState } from 'react'
import { VirtualTable } from '../../components/synapse/VirtualTable'
import { Card, EmptyState } from '../../components/ui'
import type { ScanResult } from '../../lib/types'
import { ScanPrompt } from './VulnsTab'

function CopyPurlButton({ purl }: { purl: string }) {
  const [copied, setCopied] = useState(false)

  function copy(e: React.MouseEvent) {
    e.stopPropagation()
    if (!purl) return
    copyText(purl)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (!purl) return <span className="font-mono text-xs text-quaternary">None</span>

  return (
    <div className="flex items-center gap-1.5 group max-w-full">
      <span className="truncate font-mono text-xs text-tertiary group-hover:text-primary transition-colors" title={purl}>
        {purl}
      </span>
      <button
        type="button"
        onClick={copy}
        title={copied ? 'Copied PURL' : 'Copy PURL'}
        className="shrink-0 rounded p-1 text-quaternary hover:bg-secondary hover:text-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
      >
        {copied ? <Check className="size-3.5 text-success-primary" /> : <Copy01 className="size-3.5" />}
      </button>
    </div>
  )
}

export function ComponentsTab({ scan }: { scan: ScanResult | null }) {
  const [search, setSearch] = useState('')

  if (!scan) return <ScanPrompt icon={Package} what="the component inventory" />
  if (scan.components.length === 0) {
    return <EmptyState icon={Package} title="No packages" hint="Syft found no packages in this target." />
  }

  const query = search.trim().toLowerCase()
  const allComponents = scan.components.slice().sort((a, b) => a.name.localeCompare(b.name))
  const rows = allComponents.filter((c) => {
    if (!query) return true
    return [
      c.name,
      c.version,
      c.purl,
      ...c.licenses.map((l) => l.spdxId || l.name),
    ].some((v) => v?.toLowerCase().includes(query))
  })

  const licensedCount = allComponents.filter((c) => c.licenses.length > 0).length
  const unknownCount = allComponents.length - licensedCount

  return (
    <Card bodyClass="p-0" className="overflow-hidden shadow-xs">
      {/* Unified Toolbar */}
      <div className="flex flex-col gap-3 border-b border-secondary p-4 sm:flex-row sm:items-center sm:justify-between bg-primary">
        {/* Search input */}
        <div className="relative min-w-[16rem] sm:max-w-xs">
          <SearchLg className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-fg-tertiary" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search packages, versions, PURL..."
            aria-label="Search packages"
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

        {/* Status Counter Badges */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="inline-flex items-center gap-1.5 rounded-lg border border-utility-blue-200 bg-utility-blue-50 px-2.5 py-1 font-semibold text-utility-blue-700">
            <Package className="size-3.5" />
            <span>{rows.length} packages</span>
          </span>
          <span className="inline-flex items-center rounded-lg border border-utility-green-300 bg-success-primary px-2.5 py-1 font-semibold text-success-primary">
            {licensedCount} licensed
          </span>
          {unknownCount > 0 && (
            <span className="inline-flex items-center rounded-lg border border-secondary bg-secondary px-2.5 py-1 font-medium text-tertiary">
              {unknownCount} unknown
            </span>
          )}
        </div>
      </div>

      {/* Package Virtual Table */}
      {rows.length === 0 ? (
        <div className="p-8 text-center text-sm text-tertiary">
          No packages match your search for "{search}".
        </div>
      ) : (
        <VirtualTable
          items={rows}
          rowKey={(c, i) => `${c.purl}-${i}`}
          columns={[
            {
              header: 'Package',
              className: 'flex-1 font-semibold text-primary',
              cell: (c) => (
                <div className="flex items-center gap-2 truncate" title={c.name}>
                  <span className="font-semibold text-primary">{c.name}</span>
                </div>
              ),
            },
            {
              header: 'Version',
              className: 'w-32 font-mono text-xs font-bold tabular-nums text-secondary',
              cell: (c) => c.version || <span className="font-normal text-quaternary">None</span>,
            },
            {
              header: 'License',
              className: 'w-48 text-xs',
              cell: (c) => {
                const lic = c.licenses.map((l) => l.spdxId || l.name).filter(Boolean).join(', ')
                if (!lic) {
                  return (
                    <span className="inline-flex items-center rounded-md border border-secondary bg-secondary px-2 py-0.5 text-xs font-medium text-tertiary">
                      None
                    </span>
                  )
                }
                return (
                  <span className="inline-flex items-center rounded-md border border-utility-green-300 bg-success-primary px-2 py-0.5 text-xs font-semibold text-success-primary">
                    {lic}
                  </span>
                )
              },
            },
            {
              header: 'PURL',
              className: 'flex-1 min-w-0 pr-4',
              cell: (c) => <CopyPurlButton purl={c.purl} />,
            },
          ]}
        />
      )}
    </Card>
  )
}
