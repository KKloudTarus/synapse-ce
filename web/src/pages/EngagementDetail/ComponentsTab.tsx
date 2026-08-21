import { Boxes } from 'lucide-react'
import { VirtualTable } from '../../components/synapse/VirtualTable'
import { Card, EmptyState } from '../../components/ui'
import type { ScanResult } from '../../lib/types'
import { ScanPrompt } from './VulnsTab'

export function ComponentsTab({ scan }: { scan: ScanResult | null }) {
  if (!scan) return <ScanPrompt icon={Boxes} what="the component inventory" />
  if (scan.components.length === 0) {
    return <EmptyState icon={Boxes} title="No packages" hint="Syft found no packages in this target." />
  }
  const rows = scan.components.slice().sort((a, b) => a.name.localeCompare(b.name))
  return (
    <Card bodyClass="p-0">
      <VirtualTable
        items={rows}
        rowKey={(c, i) => `${c.purl}-${i}`}
        columns={[
          { header: 'Package', className: 'flex-1 font-medium text-foreground', cell: (c) => c.name },
          {
            header: 'Version',
            className: 'w-28 font-mono text-xs tabular-nums text-mutedfg',
            cell: (c) => c.version || '–',
          },
          {
            header: 'License',
            className: 'w-44 text-xs text-mutedfg',
            cell: (c) =>
              c.licenses.length === 0
                ? '–'
                : c.licenses.map((l) => l.spdxId || l.name).filter(Boolean).join(', ') || '–',
          },
          { header: 'PURL', className: 'flex-1 font-mono text-xs text-subtlefg', cell: (c) => c.purl || '–' },
        ]}
      />
    </Card>
  )
}
