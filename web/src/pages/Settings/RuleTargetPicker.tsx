import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react'

export type RuleTarget = {
  id: string
  label: string
  archived?: boolean
}

export type RuleTargetPage = {
  items: RuleTarget[]
  next?: string
}

type Props = {
  label: string
  hint?: string
  selected: string[]
  onChange: (ids: string[]) => void
  disabled?: boolean
  search: (query: string, cursor: string | undefined, signal: AbortSignal) => Promise<RuleTargetPage>
}

function denied(err: unknown) {
  if (typeof err !== 'object' || err === null || !('status' in err)) return false
  const status = (err as { status: unknown }).status
  return status === 401 || status === 403
}

function aborted(err: unknown) {
  return err instanceof DOMException && err.name === 'AbortError'
}

function remember(prev: Record<string, RuleTarget>, items: RuleTarget[]) {
  const next = { ...prev }
  for (const item of items) next[item.id] = item
  return next
}

function optionName(item: RuleTarget, active: boolean) {
  return `${item.label} (${item.id})${item.archived ? ' Archived' : ''}${active ? ' Selected' : ''}`
}

export function RuleTargetPicker({ label, hint, selected, onChange, disabled = false, search }: Props) {
  const searchId = useId()
  const listId = useId()
  const hintId = useId()
  const [query, setQuery] = useState('')
  const [items, setItems] = useState<RuleTarget[]>([])
  const [next, setNext] = useState<string>()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [forbidden, setForbidden] = useState(false)
  const [known, setKnown] = useState<Record<string, RuleTarget>>({})
  const generation = useRef(0)

  useEffect(() => {
    const current = ++generation.current
    const controller = new AbortController()
    setLoading(true)
    setError('')
    setForbidden(false)
    setItems([])
    setNext(undefined)
    const timer = setTimeout(() => {
      void search(query, undefined, controller.signal)
        .then((page) => {
          if (current !== generation.current) return
          setItems(page.items)
          setNext(page.next)
          setKnown((prev) => remember(prev, page.items))
        })
        .catch((err: unknown) => {
          if (current !== generation.current || controller.signal.aborted || aborted(err)) return
          if (denied(err)) {
            setForbidden(true)
            return
          }
          setError(err instanceof Error ? err.message : 'Could not search')
        })
        .finally(() => {
          if (current === generation.current) setLoading(false)
        })
    }, 200)
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [query, search])

  async function more() {
    if (!next || loading || disabled) return
    const current = generation.current
    const controller = new AbortController()
    setLoading(true)
    setError('')
    try {
      const page = await search(query, next, controller.signal)
      if (current !== generation.current) return
      setItems((prev) => {
        const seen = new Set(prev.map((item) => item.id))
        return [...prev, ...page.items.filter((item) => !seen.has(item.id))]
      })
      setNext(page.next)
      setKnown((prev) => remember(prev, page.items))
    } catch (err: unknown) {
      if (current !== generation.current || aborted(err)) return
      if (denied(err)) setForbidden(true)
      else setError(err instanceof Error ? err.message : 'Could not search')
    } finally {
      if (current === generation.current) setLoading(false)
    }
  }

  function toggle(item: RuleTarget) {
    setKnown((prev) => remember(prev, [item]))
    onChange(selected.includes(item.id) ? selected.filter((id) => id !== item.id) : [...selected, item.id])
  }

  function onListKeyDown(event: KeyboardEvent<HTMLUListElement>) {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
    const buttons = [...event.currentTarget.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')]
    if (buttons.length === 0) return
    event.preventDefault()
    const index = buttons.indexOf(document.activeElement as HTMLButtonElement)
    const nextIndex = event.key === 'ArrowDown' ? index + 1 : index - 1
    buttons[Math.min(Math.max(nextIndex, 0), buttons.length - 1)]?.focus()
  }

  return (
    <div className="space-y-2">
      <label htmlFor={searchId} className="text-sm font-medium text-secondary">
        {label}
      </label>
      {hint && (
        <p id={hintId} className="text-sm text-tertiary">
          {hint}
        </p>
      )}
      {selected.length > 0 && (
        <ul aria-label={`Selected ${label}`} className="flex flex-wrap gap-2">
          {selected.map((id) => {
            const item = known[id]
            const name = item ? `${item.label} (${item.id})` : id
            return (
              <li key={id} className="flex max-w-full flex-wrap items-center gap-2 rounded-lg border border-secondary bg-primary px-2 py-1 text-sm text-primary">
                <span className="truncate">{name}</span>
                {item?.archived && <span className="text-warning-primary">Archived</span>}
                {!item && <span className="text-warning-primary">Not in the current directory</span>}
                <button
                  type="button"
                  disabled={disabled}
                  onClick={() => onChange(selected.filter((value) => value !== id))}
                  className="text-brand-primary underline disabled:opacity-50"
                >
                  <span className="sr-only">Remove {name}</span>
                  <span aria-hidden="true">Remove</span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
      <input
        id={searchId}
        type="search"
        value={query}
        disabled={disabled}
        aria-describedby={hint ? hintId : undefined}
        aria-controls={items.length > 0 ? listId : undefined}
        onChange={(event) => setQuery(event.target.value)}
        className="w-full rounded-lg border border-primary bg-primary px-3 py-2 text-primary disabled:opacity-50"
      />
      {forbidden && (
        <p role="alert" className="text-sm text-error-primary">
          You do not have permission to search these records. Existing selections stay on the rule.
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-error-primary">
          {error}
        </p>
      )}
      {loading && (
        <p role="status" className="text-sm text-secondary">
          Searching…
        </p>
      )}
      {!loading && !error && !forbidden && items.length === 0 && (
        <p className="text-sm text-secondary">No matches.</p>
      )}
      {items.length > 0 && (
        <ul id={listId} role="listbox" aria-label={`${label} results`} aria-multiselectable="true" onKeyDown={onListKeyDown} className="max-h-48 overflow-y-auto rounded-lg border border-secondary">
          {items.map((item) => {
            const active = selected.includes(item.id)
            return (
              <li key={item.id} role="option" aria-selected={active}>
                <button
                  type="button"
                  disabled={disabled}
                  onClick={() => toggle(item)}
                  className="w-full px-3 py-2 text-left text-sm text-primary hover:bg-primary_hover focus-visible:outline-2 focus-visible:outline-brand disabled:opacity-50"
                >
                  {optionName(item, active)}
                </button>
              </li>
            )
          })}
        </ul>
      )}
      {next && (
        <button type="button" disabled={disabled || loading} onClick={() => void more()} className="text-sm text-brand-primary underline disabled:opacity-50">
          Load more
        </button>
      )}
    </div>
  )
}
