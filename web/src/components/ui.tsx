import * as RSelect from '@radix-ui/react-select'
import { Check, ChevronDown, Loader2, type LucideIcon } from 'lucide-react'
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react'
import { sevSoft, VERDICT_STYLE } from '../lib/severity'
import type { Severity, Verdict } from '../lib/types'

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ')
}

// ---- Button ----

type ButtonVariant = 'primary' | 'brand' | 'secondary' | 'ghost' | 'danger'

const BTN: Record<ButtonVariant, string> = {
  // indigo gradient + top-highlight + glow (.btn-primary in index.css)
  primary: 'btn-primary text-brandfg hover:brightness-110',
  brand: 'btn-primary text-brandfg hover:brightness-110',
  secondary: 'border border-border bg-elevated text-foreground hover:border-borderstrong hover:bg-raised',
  ghost: 'text-mutedfg hover:bg-elevated hover:text-foreground',
  danger: 'bg-critical text-criticalfg shadow-sm hover:brightness-110',
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  loading?: boolean
}

export function Button({ variant = 'primary', loading, className, children, disabled, ...rest }: ButtonProps) {
  return (
    <button
      className={cn(
        'inline-flex select-none items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-semibold transition duration-150',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
        'disabled:pointer-events-none disabled:opacity-50',
        BTN[variant],
        className,
      )}
      disabled={loading || disabled}
      {...rest}
    >
      {loading && <Loader2 className="size-4 animate-spin" />}
      {children}
    </button>
  )
}

// ---- Card ----

export function Card({
  title,
  actions,
  bodyClass,
  className,
  children,
}: {
  title?: ReactNode
  actions?: ReactNode
  bodyClass?: string
  className?: string
  children: ReactNode
}) {
  return (
    <section className={cn('card-sheen elev rounded-xl border border-border bg-card', className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-border px-6 py-4">
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          {actions}
        </header>
      )}
      <div className={cn('p-6', bodyClass)}>{children}</div>
    </section>
  )
}

// ---- Badges ----

export function SevBadge({ sev }: { sev: Severity }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ring-1 ring-inset',
        sevSoft[sev],
      )}
    >
      {sev}
    </span>
  )
}

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const v = VERDICT_STYLE[verdict]
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset',
        v.soft,
      )}
    >
      <span className={cn('size-1.5 rounded-full', v.dot)} />
      {v.label}
    </span>
  )
}

export function KevBadge() {
  return (
    <span
      title="CISA Known Exploited Vulnerability – actively exploited in the wild"
      className="inline-flex items-center rounded-md bg-critical/15 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-critical ring-1 ring-inset ring-critical/30"
    >
      KEV
    </span>
  )
}

export function Pill({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md bg-muted px-2 py-0.5 text-xs font-medium text-mutedfg',
        className,
      )}
    >
      {children}
    </span>
  )
}

// ---- Inputs ----

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        'input-inset w-full rounded-lg border border-border bg-elevated px-3.5 py-2.5 text-sm text-foreground outline-none transition-colors',
        'placeholder:text-subtlefg focus:border-brand focus:ring-2 focus:ring-brand/40',
        className,
      )}
      {...rest}
    />
  )
}

export function Field({
  label,
  hint,
  htmlFor,
  children,
}: {
  label: string
  hint?: string
  htmlFor?: string
  children: ReactNode
}) {
  return (
    <label htmlFor={htmlFor} className="block space-y-1.5">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-mutedfg">{label}</span>
      {children}
      {hint && <span className="block text-xs text-subtlefg">{hint}</span>}
    </label>
  )
}

// ---- Select (custom dropdown – Radix, styled with design tokens) ----

export type SelectOption = { value: string; label: ReactNode }

export function Select({
  id,
  value,
  onValueChange,
  options,
  ariaLabel,
  disabled,
  size = 'md',
  className,
}: {
  id?: string
  value: string
  onValueChange: (value: string) => void
  options: SelectOption[]
  ariaLabel?: string
  disabled?: boolean
  size?: 'sm' | 'md'
  className?: string
}) {
  return (
    <RSelect.Root value={value} onValueChange={onValueChange} disabled={disabled}>
      <RSelect.Trigger
        id={id}
        aria-label={ariaLabel}
        className={cn(
          'input-inset group inline-flex items-center justify-between gap-2 rounded-lg border border-border bg-elevated text-foreground transition-colors',
          size === 'sm' ? 'h-8 px-2.5 text-xs' : 'h-9 px-3 text-sm',
          'hover:border-borderstrong focus-visible:border-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40 focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
          'disabled:cursor-not-allowed disabled:opacity-50',
          className,
        )}
      >
        <RSelect.Value />
        <RSelect.Icon asChild>
          <ChevronDown className="size-4 shrink-0 text-mutedfg transition-transform duration-150 group-data-[state=open]:rotate-180" />
        </RSelect.Icon>
      </RSelect.Trigger>
      <RSelect.Portal>
        <RSelect.Content
          position="popper"
          sideOffset={6}
          className="dropdown-content elev z-50 max-h-[var(--radix-select-content-available-height)] min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-lg border border-borderstrong bg-elevated p-1"
        >
          <RSelect.Viewport className="overflow-y-auto">
            {options.map((o) => (
              <RSelect.Item
                key={o.value}
                value={o.value}
                className="relative flex cursor-pointer select-none items-center rounded-md py-1.5 pl-7 pr-3 text-sm text-foreground outline-none transition-colors data-[highlighted]:bg-raised data-[disabled]:opacity-50"
              >
                <RSelect.ItemIndicator className="absolute left-2 inline-flex">
                  <Check className="size-3.5 text-brand" />
                </RSelect.ItemIndicator>
                <RSelect.ItemText>{o.label}</RSelect.ItemText>
              </RSelect.Item>
            ))}
          </RSelect.Viewport>
        </RSelect.Content>
      </RSelect.Portal>
    </RSelect.Root>
  )
}

// ---- States ----

export function Spinner({ label, className }: { label?: string; className?: string }) {
  return (
    <div className={cn("flex items-center justify-center gap-2 py-10 text-sm text-mutedfg", className)}>
      <Loader2 className="size-4 animate-spin" />
      {label ?? 'Loading…'}
    </div>
  )
}

export function EmptyState({
  icon: Icon,
  title,
  hint,
  action,
}: {
  icon: LucideIcon
  title: string
  hint?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border px-6 py-12 text-center">
      <div className="flex size-11 items-center justify-center rounded-full bg-muted text-mutedfg">
        <Icon className="size-5" />
      </div>
      <div>
        <p className="text-sm font-medium text-foreground">{title}</p>
        {hint && <p className="mt-1 text-sm text-mutedfg">{hint}</p>}
      </div>
      {action}
    </div>
  )
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-high/30 bg-high/10 px-4 py-3 text-sm text-high">
      {message}
    </div>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded bg-muted motion-reduce:animate-none', className)} />
}
