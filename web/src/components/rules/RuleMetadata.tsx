import {
  formatRuleType,
  formatRuleQuality,
  formatRuleSeverity,
  formatRuleDetection,
  formatRemediationEffort,
} from '../../lib/ruleFormat'
import { sevSoft } from '../../lib/severity'
import type { RuleDetail, RuleSummary } from '../../lib/types'
import { cn, Pill } from '../ui'

interface RuleMetadataProps {
  rule: RuleSummary | RuleDetail
  variant?: 'compact' | 'detail'
}

export function RuleMetadata({ rule, variant = 'detail' }: RuleMetadataProps) {
  const isDetail = variant === 'detail'

  return (
    <div className={cn('flex flex-wrap items-center gap-2', isDetail && 'text-sm')}>
      <span
        className={cn(
          'inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset',
          sevSoft[rule.defaultSeverity] || sevSoft.unknown,
        )}
      >
        {formatRuleSeverity(rule.defaultSeverity)}
      </span>

      <span className="text-mutedfg flex items-center gap-2">
        <span className="font-mono text-xs">{rule.language}</span>
        <span className="text-border px-1">•</span>
        <span>{formatRuleType(rule.type)}</span>

        {isDetail && rule.detection && (
          <>
            <span className="text-border px-1">•</span>
            <span>{formatRuleDetection(rule.detection)}</span>
          </>
        )}

        {isDetail && rule.remediationEffort > 0 && (
          <>
            <span className="text-border px-1">•</span>
            <span>{formatRemediationEffort(rule.remediationEffort)}</span>
          </>
        )}
      </span>

      {rule.qualities?.length > 0 && (
        <>
          <span className="text-border px-1">•</span>
          <div className="flex gap-1.5">
            {rule.qualities.map((q) => (
              <Pill key={q} className="bg-elevated">
                {formatRuleQuality(q)}
              </Pill>
            ))}
          </div>
        </>
      )}

      {isDetail && (
        <div className="mt-2 flex w-full flex-wrap gap-1.5">
          {rule.cwe?.map((c) => (
            <Pill key={c} className="bg-surface border-border">
              {c}
            </Pill>
          ))}
          {rule.owasp?.map((o) => (
            <Pill key={o} className="bg-surface border-border">
              {o}
            </Pill>
          ))}
          {rule.tags?.map((t) => (
            <Pill key={t} className="bg-surface border-border">
              {t}
            </Pill>
          ))}
        </div>
      )}
    </div>
  )
}
