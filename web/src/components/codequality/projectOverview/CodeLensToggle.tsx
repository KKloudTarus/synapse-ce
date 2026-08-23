import type { CodeLens } from '../../../lib/projectOverviewPresentation'
import { cn } from '../../ui'

export function CodeLensToggle({ value, onChange }: { value: CodeLens; onChange: (value: CodeLens) => void }) {
  return (
    <div className="inline-flex rounded-lg border border-secondary bg-secondary p-1" role="group" aria-label="Overview lens">
      <LensButton active={value === 'overall'} onClick={() => onChange('overall')}>Overall Code</LensButton>
      <LensButton active={value === 'new-code'} onClick={() => onChange('new-code')}>New Code</LensButton>
    </div>
  )
}

function LensButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={cn(
        'rounded-md px-3 py-1.5 text-sm font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
        active ? 'bg-primary text-brand-secondary shadow-xs' : 'text-tertiary hover:text-primary',
      )}
    >
      {children}
    </button>
  )
}
