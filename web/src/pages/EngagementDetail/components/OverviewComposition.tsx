import { Database01, Dataflow03, File06, Package, Scale01, Tool01 } from '@untitledui/icons'
import { type ComponentType } from 'react'
import { Card, cn } from '../../../components/ui'
import type { ScanResult } from '../../../lib/types'
import { countEdges } from '../VulnsTab'
import type { Tab } from '../index'

const LANG_COLORS = [
  'bg-utility-blue-600',
  'bg-utility-green-600',
  'bg-utility-orange-600',
  'bg-utility-pink-600',
  'bg-brand-solid',
  'bg-utility-neutral-600',
]

export function CardEmpty({ icon: Icon, text }: { icon: ComponentType<{ className?: string }>; text: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-6 text-center">
      <Icon className="size-6 text-fg-quaternary" />
      <p className="text-xs font-medium text-tertiary">{text}</p>
    </div>
  )
}

export function CompTile({
  icon: Icon,
  label,
  value,
  tone = 'blue',
  onClick,
}: {
  icon: ComponentType<{ className?: string }>
  label: string
  value: number
  tone?: 'blue' | 'purple' | 'green'
  onClick: () => void
}) {
  const toneStyles = {
    blue: {
      border: 'border-utility-blue-200',
      bg: 'bg-utility-blue-50',
      text: 'text-utility-blue-700',
      icon: 'text-utility-blue-600',
    },
    purple: {
      border: 'border-utility-purple-200',
      bg: 'bg-utility-purple-50',
      text: 'text-utility-purple-700',
      icon: 'text-utility-purple-600',
    },
    green: {
      border: 'border-utility-green-300',
      bg: 'bg-success-primary',
      text: 'text-success-primary',
      icon: 'text-fg-success-primary',
    },
  }[tone]

  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-2 rounded-lg border px-2.5 py-2 transition-all shadow-2xs hover:shadow-xs',
        toneStyles.border,
        toneStyles.bg,
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid',
      )}
    >
      <Icon className={cn('size-4 shrink-0', toneStyles.icon)} />
      <div className="min-w-0 text-left">
        <div className={cn('font-mono text-sm font-bold tabular-nums', toneStyles.text)}>{value}</div>
        <div className={cn('text-[10px] font-bold uppercase tracking-wider', toneStyles.text)}>{label}</div>
      </div>
    </button>
  )
}

export function CompositionProvenanceCard({ scan, onGoTab }: { scan: ScanResult; onGoTab: (t: Tab) => void }) {
  const langs = scan.languages.slice().sort((a, b) => b.percent - a.percent)
  const m = scan.manifest

  return (
    <Card title="Composition & Provenance" className="shadow-xs" bodyClass="p-4">
      <div className="grid grid-cols-1 items-stretch divide-y divide-secondary lg:grid-cols-12 lg:divide-y-0 lg:divide-x">
        {/* Col 1 (6 cols): Codebase Languages & Inventory Summary */}
        <div className="flex flex-col justify-between space-y-4 pb-4 lg:col-span-6 lg:pb-0 lg:pr-5">
          {/* Languages Section */}
          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-secondary">
                Languages
              </span>
              <span className="text-[11px] text-tertiary">
                {langs.length} detected
              </span>
            </div>

            {langs.length === 0 ? (
              <p className="text-xs text-quaternary">No source languages detected.</p>
            ) : (
              <div className="space-y-2">
                {/* Multi-segment Language Distribution Bar */}
                <div className="flex h-2 w-full overflow-hidden rounded-full bg-secondary">
                  {langs.slice(0, 6).map((l, idx) => (
                    <div
                      key={l.name}
                      className={cn('h-full transition-all', LANG_COLORS[idx % LANG_COLORS.length])}
                      style={{ width: `${Math.max(1, l.percent)}%` }}
                      title={`${l.name}: ${l.percent.toFixed(1)}%`}
                    />
                  ))}
                </div>

                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                  {langs.slice(0, 6).map((l, idx) => (
                    <div key={l.name} className="flex items-center gap-1.5 text-xs">
                      <span className={cn('size-2 rounded-full shrink-0', LANG_COLORS[idx % LANG_COLORS.length])} />
                      <span className="truncate font-medium text-primary">{l.name}</span>
                      <span className="font-mono font-bold tabular-nums text-secondary">{l.percent.toFixed(1)}%</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Inventory Counts Section */}
          <div className="border-t border-secondary pt-3">
            <div className="mb-2 text-xs font-bold uppercase tracking-wider text-secondary">
              Inventory Counts
            </div>
            <div className="grid grid-cols-1 gap-2 xs:grid-cols-3">
              <CompTile
                icon={Package}
                label="packages"
                value={scan.components.length}
                tone="blue"
                onClick={() => onGoTab('components')}
              />
              <CompTile
                icon={Scale01}
                label="licenses"
                value={scan.licenses.length}
                tone="purple"
                onClick={() => onGoTab('licenses')}
              />
              <CompTile
                icon={Dataflow03}
                label="dep. edges"
                value={countEdges(scan)}
                tone="green"
                onClick={() => onGoTab('graph')}
              />
            </div>
          </div>
        </div>

        {/* Col 2 (6 cols): Tool Versions & Integrity Metadata */}
        <div className="flex flex-col justify-between pt-4 lg:col-span-6 lg:pt-0 lg:pl-5">
          <div>
            <div className="mb-2.5">
              <span className="text-xs font-bold uppercase tracking-wider text-secondary">
                Tool Versions &amp; Integrity
              </span>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {Object.entries(scan.toolVersions).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between gap-2 rounded-lg border border-secondary bg-secondary px-3 py-2 text-xs">
                  <span className="flex items-center gap-1.5 text-tertiary">
                    <Tool01 className="size-3.5 text-fg-tertiary" />
                    <span>{k}</span>
                  </span>
                  <span className="truncate font-mono font-bold tabular-nums text-primary">{v}</span>
                </div>
              ))}
              <div className="flex items-center justify-between gap-2 rounded-lg border border-secondary bg-secondary px-3 py-2 text-xs">
                <span className="flex items-center gap-1.5 text-tertiary">
                  <Database01 className="size-3.5 text-fg-tertiary" />
                  <span>vuln DB</span>
                </span>
                <span className="truncate font-mono font-bold text-primary">{scan.vulnDBSnapshot || '0'}</span>
              </div>
              {m.sbomSha256 && (
                <div className="flex items-center justify-between gap-2 rounded-lg border border-secondary bg-secondary px-3 py-2 text-xs">
                  <span className="flex items-center gap-1.5 text-tertiary">
                    <File06 className="size-3.5 text-fg-tertiary" />
                    <span>SBOM sha</span>
                  </span>
                  <span className="truncate font-mono font-bold text-primary" title={m.sbomSha256}>
                    {m.sbomSha256.slice(0, 12)}
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </Card>
  )
}
