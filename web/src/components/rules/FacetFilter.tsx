import { Check, ChevronDown, XClose } from '@untitledui/icons'
import { useEffect, useRef, useState } from 'react'
import { cn } from '../ui'

interface FacetFilterProps<T extends string> {
  label: string
  values: T[]
  selected: T[]
  formatValue?: (value: T) => string
  onChange: (next: T[]) => void
}

export function FacetFilter<T extends string>({
  label,
  values,
  selected,
  formatValue = (v) => v,
  onChange,
}: FacetFilterProps<T>) {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (!containerRef.current?.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false)
        triggerRef.current?.focus()
      }
    }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const toggleValue = (val: T) => {
    if (selected.includes(val)) {
      onChange(selected.filter((v) => v !== val))
    } else {
      onChange([...selected, val])
    }
  }

  const clear = () => {
    onChange([])
    setOpen(false)
    triggerRef.current?.focus()
  }

  return (
    <div className="relative inline-block text-left" ref={containerRef}>
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className={cn(
          'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand',
          open
            ? 'border-brand bg-secondary text-primary'
            : 'border-secondary border-dashed bg-transparent text-secondary hover:bg-secondary hover:text-primary',
          selected.length > 0 && 'border-solid border-brand/40 bg-brand-primary text-brand-secondary hover:bg-brand-primary_hover',
        )}
      >
        {label}
        {selected.length > 0 && (
          <>
            <span className="mx-1 h-4 w-[1px] bg-border-secondary" />
            <span className="flex size-5 items-center justify-center rounded-sm bg-brand/20 text-[11px] font-semibold text-brand-secondary">
              {selected.length}
            </span>
          </>
        )}
        <ChevronDown className="ml-1 size-3.5 opacity-60" />
      </button>

      {open && (
        <div
          role="dialog"
          aria-label={`Filter by ${label}`}
          className="absolute left-0 top-full z-50 mt-1.5 w-64 rounded-xl border border-secondary bg-primary p-2 shadow-xl outline-none motion-reduce:transition-none ring-1 ring-secondary_alt"
        >
          {values.length === 0 ? (
            <div className="p-4 text-center text-sm text-tertiary">No options available</div>
          ) : (
            <div className="max-h-60 overflow-y-auto outline-none">
              <ul className="space-y-1">
                {values.map((v) => {
                  const isSelected = selected.includes(v)
                  return (
                    <li key={v}>
                      <label className="flex cursor-pointer items-center gap-3 rounded-lg px-2 py-1.5 text-sm transition-colors hover:bg-secondary focus-within:ring-2 focus-within:ring-brand">
                        <div
                          className={cn(
                            'flex size-4 shrink-0 items-center justify-center rounded-[4px] border transition-colors',
                            isSelected ? 'border-brand bg-brand text-white' : 'border-secondary bg-transparent',
                          )}
                        >
                          {isSelected && <Check className="size-3 stroke-[2.5]" />}
                        </div>
                        <input
                          type="checkbox"
                          className="sr-only"
                          checked={isSelected}
                          onChange={() => toggleValue(v)}
                          name={v}
                          aria-label={formatValue(v)}
                        />
                        <span className="flex-1 truncate text-primary">{formatValue(v)}</span>
                      </label>
                    </li>
                  )
                })}
              </ul>
            </div>
          )}

          {selected.length > 0 && (
            <div className="mt-2 border-t border-secondary pt-2">
              <button
                type="button"
                onClick={clear}
                className="flex w-full items-center justify-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium text-tertiary transition-colors hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
              >
                <XClose className="size-3.5" />
                Clear
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
