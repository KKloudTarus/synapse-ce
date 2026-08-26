import { Check, ChevronDown, SearchLg, XClose } from '@untitledui/icons'
import { useEffect, useMemo, useRef, useState } from 'react'
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
  const [search, setSearch] = useState('')
  const containerRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const searchInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) {
      setSearch('')
      return
    }
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

  useEffect(() => {
    if (open && values.length > 5) {
      // Focus search input when popover opens
      setTimeout(() => searchInputRef.current?.focus(), 50)
    }
  }, [open, values.length])

  const filteredValues = useMemo(() => {
    if (!search.trim()) return values
    const query = search.toLowerCase()
    return values.filter((v) => formatValue(v).toLowerCase().includes(query))
  }, [values, search, formatValue])

  const toggleValue = (val: T) => {
    if (selected.includes(val)) {
      onChange(selected.filter((v) => v !== val))
    } else {
      onChange([...selected, val])
    }
  }

  const selectAllFiltered = () => {
    const combined = Array.from(new Set([...selected, ...filteredValues]))
    onChange(combined)
  }

  const clear = () => {
    onChange([])
    setOpen(false)
    triggerRef.current?.focus()
  }

  const hasSearch = values.length > 5

  return (
    <div className="relative inline-block text-left" ref={containerRef}>
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className={cn(
          'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold shadow-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand',
          open
            ? 'border-brand bg-secondary text-primary ring-1 ring-brand/30'
            : selected.length > 0
              ? 'border-brand/40 bg-brand-primary text-brand-secondary ring-1 ring-brand/20 hover:bg-brand-primary_hover'
              : 'border-secondary bg-primary text-secondary hover:bg-secondary hover:text-primary hover:border-primary',
        )}
      >
        <span>{label}</span>
        {selected.length > 0 && (
          <span className="flex size-4.5 items-center justify-center rounded-full bg-brand-solid text-[10px] font-bold text-white tabular-nums">
            {selected.length}
          </span>
        )}
        <ChevronDown
          className={cn(
            'size-3.5 transition-transform duration-150',
            open ? 'rotate-180 text-brand-secondary' : 'text-quaternary',
          )}
        />
      </button>

      {open && (
        <div
          role="dialog"
          aria-label={`Filter by ${label}`}
          className="absolute left-0 top-full z-50 mt-1.5 w-64 rounded-xl border border-secondary bg-primary p-2 shadow-xl outline-none ring-1 ring-secondary_alt animate-fade-in"
        >
          {/* Header Search if many items */}
          {hasSearch && (
            <div className="relative mb-2 px-1">
              <SearchLg className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-quaternary" />
              <input
                ref={searchInputRef}
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={`Search ${label.toLowerCase()}...`}
                className="w-full rounded-md border border-secondary bg-primary py-1 pl-7 pr-7 text-xs text-primary placeholder:text-placeholder focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand shadow-xs"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch('')}
                  aria-label="Clear search"
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-tertiary hover:bg-secondary hover:text-primary"
                >
                  <XClose className="size-3" />
                </button>
              )}
            </div>
          )}

          {/* Quick Select All (when search is active) */}
          {search && filteredValues.length > 0 && (
            <div className="mb-1 flex items-center justify-between px-2 py-1 text-[11px] text-tertiary border-b border-secondary">
              <span>{filteredValues.length} matching</span>
              <button
                type="button"
                onClick={selectAllFiltered}
                className="font-medium text-brand-secondary hover:underline"
              >
                Select all
              </button>
            </div>
          )}

          {/* Options List */}
          {filteredValues.length === 0 ? (
            <div className="py-4 text-center text-xs text-tertiary">
              {search ? 'No matches found' : 'No options available'}
            </div>
          ) : (
            <div className="max-h-56 overflow-y-auto outline-none pr-0.5">
              <ul className="space-y-0.5">
                {filteredValues.map((v) => {
                  const isSelected = selected.includes(v)
                  return (
                    <li key={v}>
                      <label className="flex cursor-pointer select-none items-center gap-2.5 rounded-lg px-2 py-1.5 text-xs font-medium transition-colors hover:bg-secondary focus-within:ring-2 focus-within:ring-brand">
                        <div
                          className={cn(
                            'flex size-4 shrink-0 items-center justify-center rounded-[4px] border transition-colors',
                            isSelected
                              ? 'border-brand-solid bg-brand-solid text-white shadow-xs'
                              : 'border-secondary bg-primary hover:border-primary',
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
                        <span className={cn('flex-1 truncate', isSelected ? 'font-semibold text-primary' : 'text-secondary')}>
                          {formatValue(v)}
                        </span>
                      </label>
                    </li>
                  )
                })}
              </ul>
            </div>
          )}

          {/* Footer Actions */}
          {selected.length > 0 && (
            <div className="mt-2 border-t border-secondary pt-1.5 flex items-center justify-between px-1">
              <span className="text-[11px] text-tertiary font-medium">
                {selected.length} selected
              </span>
              <button
                type="button"
                onClick={clear}
                className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium text-tertiary transition-colors hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
              >
                <XClose className="size-3" />
                Clear
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
