import { useRef } from 'react'
import { Link } from 'react-router-dom'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Card } from '../ui'
import { RuleMetadata } from './RuleMetadata'
import { ChevronRight } from 'lucide-react'
import type { RuleSummary } from '../../lib/types'

interface VirtualRuleCardsProps {
  rules: RuleSummary[]
  detailFrom: string
}

export function VirtualRuleCards({ rules, detailFrom }: VirtualRuleCardsProps) {
  const parentRef = useRef<HTMLDivElement>(null)

  const virtualizer = useVirtualizer({
    count: rules.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 220,
    overscan: 8,
  })

  return (
    <div
      ref={parentRef}
      className="max-h-[70vh] overflow-auto md:hidden"
      aria-label="Rule results"
      aria-rowcount={rules.length}
    >
      <div
        className="relative w-full"
        style={{ height: `${virtualizer.getTotalSize()}px` }}
      >
        {virtualizer.getVirtualItems().map((virtualItem) => {
          const rule = rules[virtualItem.index]

          return (
            <div
              key={rule.key}
              data-index={virtualItem.index}
              ref={virtualizer.measureElement}
              className="absolute left-0 top-0 w-full pb-3"
              style={{
                transform: `translateY(${virtualItem.start}px)`,
              }}
            >
              <Link
                to={`/rules/${encodeURIComponent(rule.key)}`}
                state={{ from: detailFrom }}
                className="group block focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-surface rounded-xl"
              >
                <Card className="flex items-center gap-4 p-5 transition-colors hover:border-brand/40 elev card-sheen">
                  <div className="flex-1 min-w-0">
                    <div className="mb-1.5 flex flex-wrap items-center gap-2">
                      <h3 className="font-semibold text-foreground group-hover:text-brand">
                        {rule.name}
                      </h3>
                      <span className="shrink-0 rounded bg-elevated px-1.5 py-0.5 font-mono text-[11px] text-mutedfg">{rule.key}</span>
                    </div>
                    <p className="text-xs text-mutedfg line-clamp-2 mb-3">{rule.description}</p>
                    <RuleMetadata rule={rule} variant="compact" />
                  </div>
                  <ChevronRight className="size-5 shrink-0 text-mutedfg opacity-0 transition-all group-hover:-translate-x-1 group-hover:opacity-100" />
                </Card>
              </Link>
            </div>
          )
        })}
      </div>
    </div>
  )
}
