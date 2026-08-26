import { useEffect, useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import {
  AlertCircle,
  Check,
  Copy01,
  FileCode01,
  LayersThree01,
  Link01,
  Plus,
  SearchLg,
  ShieldTick,
  ShieldZap,
  Trash01,
  XClose,
} from '@untitledui/icons'
import { api, ApiError } from '../../lib/api'
import type { QualityProfile, RuleSummary, Severity } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Input, Select, Spinner, cn } from '../../components/ui'
import { SeverityBadge } from '../../components/synapse/SeverityBadge'
import { useFetch } from '../../hooks'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']
const RULE_RENDER_CAP = 100

type TypeFilter = 'all' | 'builtin' | 'custom'
type RuleFilter = 'all' | 'active' | 'inactive'

export function QualityProfiles() {
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all')

  const { data: profiles, error: err } = useFetch<QualityProfile[]>(
    () => api.listQualityProfiles(),
    { deps: [refresh] },
  )

  // Auto-select first profile when profiles load or if current selection is invalid
  useEffect(() => {
    if (!profiles || profiles.length === 0) return
    if (!selectedKey || !profiles.some((p) => p.key === selectedKey)) {
      setSelectedKey(profiles[0].key)
    }
  }, [profiles, selectedKey])

  // Aggregate stats for KPI cards
  const stats = useMemo(() => {
    if (!profiles) return { total: 0, languages: 0, builtIn: 0, custom: 0 }
    const languages = new Set(profiles.map((p) => p.language)).size
    const builtIn = profiles.filter((p) => p.builtIn).length
    const custom = profiles.filter((p) => !p.builtIn).length
    return {
      total: profiles.length,
      languages,
      builtIn,
      custom,
    }
  }, [profiles])

  // Filtered profiles for Master Sidebar
  const filteredProfiles = useMemo(() => {
    if (!profiles) return []
    const q = searchQuery.trim().toLowerCase()
    return profiles.filter((p) => {
      // Type filter
      if (typeFilter === 'builtin' && !p.builtIn) return false
      if (typeFilter === 'custom' && p.builtIn) return false

      // Search query (profile name, key, or language)
      if (!q) return true
      return (
        p.name.toLowerCase().includes(q) ||
        p.key.toLowerCase().includes(q) ||
        p.language.toLowerCase().includes(q)
      )
    })
  }, [profiles, searchQuery, typeFilter])

  // Group filtered profiles by language
  const byLanguage = useMemo(() => {
    const map = new Map<string, QualityProfile[]>()
    for (const p of filteredProfiles) {
      const list = map.get(p.language) ?? []
      list.push(p)
      map.set(p.language, list)
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [filteredProfiles])

  const selected = profiles?.find((p) => p.key === selectedKey) ?? null

  if (err) {
    return (
      <div className="space-y-3">
        <ErrorState message={err} />
        <Button variant="secondary" onClick={() => setRefresh((c) => c + 1)}>
          Retry
        </Button>
      </div>
    )
  }

  if (!profiles) {
    return (
      <div className="flex h-40 items-center justify-center">
        <Spinner label="Loading quality profiles…" />
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Quality Profiles</h1>
        </div>
      </header>

      {/* Top KPI Stat Cards (DESIGN-REFERENCE.md standard) */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4">
        {/* Total Profiles */}
        <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <span className="block truncate text-sm font-semibold text-secondary">Total Profiles</span>
              <div className="mt-2 font-mono text-3xl font-bold tabular-nums text-primary sm:text-4xl">
                {stats.total}
              </div>
            </div>
            <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary shadow-2xs">
              <LayersThree01 className="size-5 text-brand-secondary" aria-hidden="true" />
            </span>
          </div>
        </div>

        {/* Languages */}
        <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <span className="block truncate text-sm font-semibold text-secondary">Languages</span>
              <div className="mt-2 font-mono text-3xl font-bold tabular-nums text-primary sm:text-4xl">
                {stats.languages}
              </div>
            </div>
            <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary shadow-2xs">
              <FileCode01 className="size-5 text-utility-blue-600 dark:text-utility-blue-400" aria-hidden="true" />
            </span>
          </div>
        </div>

        {/* Built-in Profiles */}
        <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <span className="block truncate text-sm font-semibold text-secondary">Built-in Defaults</span>
              <div className="mt-2 font-mono text-3xl font-bold tabular-nums text-primary sm:text-4xl">
                {stats.builtIn}
              </div>
            </div>
            <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary shadow-2xs">
              <ShieldTick className="size-5 text-utility-green-600 dark:text-utility-green-400" aria-hidden="true" />
            </span>
          </div>
        </div>

        {/* Custom Profiles */}
        <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <span className="block truncate text-sm font-semibold text-secondary">Custom Profiles</span>
              <div className="mt-2 font-mono text-3xl font-bold tabular-nums text-primary sm:text-4xl">
                {stats.custom}
              </div>
            </div>
            <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary shadow-2xs">
              <ShieldZap className="size-5 text-utility-orange-600 dark:text-utility-orange-400" aria-hidden="true" />
            </span>
          </div>
        </div>
      </div>

      {/* Main Master-Detail Layout aligned with 4-col KPI grid */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4 items-start">
        {/* Left Column: Master Sidebar with Internal Sticky Scroll */}
        <aside
          className="w-full rounded-xl border border-secondary bg-primary shadow-xs lg:sticky lg:top-4 lg:max-h-[calc(100vh-220px)] flex flex-col overflow-hidden"
          aria-label="Quality profiles master list"
        >
          {/* Master Toolbar: Search & Segmented Filter */}
          <div className="border-b border-secondary bg-secondary/20 p-3 space-y-2.5">
            {/* Search Input */}
            <div className="relative">
              <SearchLg className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-tertiary" aria-hidden="true" />
              <Input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search profile or language…"
                className="h-8 pl-8 pr-7 text-xs font-medium"
                aria-label="Search profiles or languages"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  aria-label="Clear search"
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-tertiary transition hover:text-primary"
                >
                  <XClose className="size-3" />
                </button>
              )}
            </div>

            {/* Segmented Filter Pills */}
            <div className="flex items-center rounded-lg border border-secondary bg-secondary/30 p-0.5 shadow-xs">
              <button
                type="button"
                onClick={() => setTypeFilter('all')}
                className={cn(
                  'flex-1 rounded-md py-1 text-center text-[11px] font-semibold transition-all',
                  typeFilter === 'all'
                    ? 'bg-primary text-primary shadow-xs border border-secondary/60'
                    : 'text-tertiary hover:text-primary'
                )}
              >
                All <span className="font-mono tabular-nums text-quaternary">({profiles.length})</span>
              </button>
              <button
                type="button"
                onClick={() => setTypeFilter('builtin')}
                className={cn(
                  'flex-1 rounded-md py-1 text-center text-[11px] font-semibold transition-all',
                  typeFilter === 'builtin'
                    ? 'bg-primary text-brand-secondary shadow-xs border border-secondary/60'
                    : 'text-tertiary hover:text-primary'
                )}
              >
                Built-in <span className="font-mono tabular-nums text-quaternary">({stats.builtIn})</span>
              </button>
              <button
                type="button"
                onClick={() => setTypeFilter('custom')}
                className={cn(
                  'flex-1 rounded-md py-1 text-center text-[11px] font-semibold transition-all',
                  typeFilter === 'custom'
                    ? 'bg-primary text-utility-blue-700 dark:text-utility-blue-300 shadow-xs border border-secondary/60'
                    : 'text-tertiary hover:text-primary'
                )}
              >
                Custom <span className="font-mono tabular-nums text-quaternary">({stats.custom})</span>
              </button>
            </div>
          </div>

          {/* Scrollable Master List Area */}
          <div className="flex-1 overflow-y-auto p-2.5 space-y-4">
            {byLanguage.length === 0 ? (
              <div className="py-6 text-center">
                <EmptyState
                  icon={ShieldTick}
                  title="No matching profiles"
                  hint={searchQuery ? 'Try adjusting your search or filter.' : 'No profiles found.'}
                />
                {searchQuery && (
                  <Button
                    variant="secondary"
                    className="mt-3 text-xs"
                    onClick={() => {
                      setSearchQuery('')
                      setTypeFilter('all')
                    }}
                  >
                    Reset filters
                  </Button>
                )}
              </div>
            ) : (
              byLanguage.map(([lang, list]) => (
                <div key={lang} className="space-y-1.5">
                  {/* Language Section Header */}
                  <div className="flex items-center justify-between px-1.5 text-xs font-bold uppercase tracking-wider text-secondary">
                    <span className="truncate">{lang}</span>
                    <span className="text-[10px] font-mono text-tertiary tabular-nums">
                      {list.length} {list.length === 1 ? 'profile' : 'profiles'}
                    </span>
                  </div>

                  {/* Profile Items */}
                  <ul className="space-y-1">
                    {list.map((p) => {
                      const isSelected = p.key === selectedKey
                      const activeRuleCount = Object.keys(p.activatedRules ?? {}).length
                      return (
                        <li key={p.key}>
                          <button
                            type="button"
                            onClick={() => setSelectedKey(p.key)}
                            aria-pressed={isSelected}
                            className={cn(
                              'group flex w-full flex-col gap-1 rounded-lg border px-3 py-2 text-left transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
                              isSelected
                                ? 'border-brand-solid bg-brand-primary/10 shadow-xs ring-1 ring-brand-solid'
                                : 'border-secondary bg-primary hover:bg-secondary/40'
                            )}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span
                                className={cn(
                                  'min-w-0 flex-1 truncate text-xs font-semibold',
                                  isSelected ? 'text-brand-secondary' : 'text-primary group-hover:text-primary'
                                )}
                                title={p.name}
                              >
                                {p.name}
                              </span>
                              {p.builtIn ? (
                                <span className="shrink-0 whitespace-nowrap inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-semibold bg-brand-primary/20 text-brand-secondary border border-brand/30">
                                  Built-in
                                </span>
                              ) : (
                                <span className="shrink-0 whitespace-nowrap inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-semibold bg-utility-blue-50 text-utility-blue-700 border border-utility-blue-200 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 dark:border-utility-blue-800">
                                  Custom
                                </span>
                              )}
                            </div>

                            {/* Subtitle with key and active count */}
                            <div className="flex items-center justify-between gap-2 text-[11px]">
                              <span className="min-w-0 font-mono text-tertiary italic truncate" title={p.key}>
                                {p.key}
                              </span>
                              <span className="shrink-0 whitespace-nowrap inline-flex items-center rounded-md px-1.5 py-0.5 font-mono text-[10px] font-semibold bg-utility-green-50 text-utility-green-700 border border-utility-green-200 dark:bg-utility-green-950/40 dark:text-utility-green-300 tabular-nums">
                                {activeRuleCount} active
                              </span>
                            </div>
                          </button>
                        </li>
                      )
                    })}
                  </ul>
                </div>
              ))
            )}
          </div>

          {/* Footer summary in Master Sidebar */}
          <div className="border-t border-secondary bg-secondary/10 px-3 py-2 text-[11px] text-tertiary flex items-center justify-between">
            <span>Showing {filteredProfiles.length} profiles</span>
            <span className="font-mono">{byLanguage.length} stacks</span>
          </div>
        </aside>

        {/* Right Column: Profile Detail (3 cols) */}
        <main className="min-w-0 lg:col-span-3">
          {selected ? (
            <ProfileDetail
              key={selected.key}
              profile={selected}
              onChanged={() => setRefresh((c) => c + 1)}
            />
          ) : (
            <Card title="Select a profile">
              <EmptyState
                icon={ShieldTick}
                title="No profile selected"
                hint="Choose a profile from the list on the left to view and edit its rules."
              />
            </Card>
          )}
        </main>
      </div>
    </div>
  )
}

function ProfileDetail({
  profile,
  onChanged,
}: {
  profile: QualityProfile
  onChanged: () => void
}) {
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [copyModalOpen, setCopyModalOpen] = useState(false)
  const [assignModalOpen, setAssignModalOpen] = useState(false)
  const [deleteModalOpen, setDeleteModalOpen] = useState(false)
  const [ruleQuery, setRuleQuery] = useState('')
  const [ruleFilter, setRuleFilter] = useState<RuleFilter>('all')
  const [detailCopiedKey, setDetailCopiedKey] = useState<string | null>(null)

  function copyKey(text: string) {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text).catch(() => {})
    }
    setDetailCopiedKey(text)
    setTimeout(() => {
      setDetailCopiedKey((curr) => (curr === text ? null : curr))
    }, 1500)
  }

  const { data: rules, error: rulesErr } = useFetch<RuleSummary[]>(
    () => api.listRules({ languages: [profile.language] }),
    { deps: [profile.language] },
  )

  const activeRulesCount = Object.keys(profile.activatedRules ?? {}).length

  // Filter rules
  const filtered = useMemo(() => {
    const q = ruleQuery.trim().toLowerCase()
    const all = rules ?? []
    return all.filter((r) => {
      const active = profile.activatedRules[r.key] !== undefined

      if (ruleFilter === 'active' && !active) return false
      if (ruleFilter === 'inactive' && active) return false

      if (!q) return true
      return r.key.toLowerCase().includes(q) || r.name.toLowerCase().includes(q)
    })
  }, [rules, ruleQuery, ruleFilter, profile.activatedRules])

  const shown = filtered.slice(0, RULE_RENDER_CAP)

  async function run(action: () => Promise<unknown>) {
    setBusy(true)
    setErr(null)
    try {
      await action()
      onChanged()
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'Action failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Profile Header Card */}
      <Card
        title={
          <div className="space-y-1">
            <h2 className="text-base font-bold text-primary sm:text-lg">{profile.name}</h2>
            <div className="flex items-center gap-1.5 font-mono text-xs italic">
              <button
                type="button"
                onClick={() => copyKey(profile.key)}
                title={`Click to copy key: ${profile.key}`}
                aria-label={`Copy key ${profile.key}`}
                className="group/copy flex items-center gap-1.5 rounded px-1.5 py-0.5 -mx-1.5 text-utility-blue-700 dark:text-utility-blue-300 hover:bg-utility-blue-50 dark:hover:bg-utility-blue-950/40 hover:text-utility-blue-800 dark:hover:text-utility-blue-200 transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-utility-blue-500/60"
              >
                {detailCopiedKey === profile.key ? (
                  <Check className="size-3.5 text-success-primary not-italic animate-scale-in" aria-hidden="true" />
                ) : (
                  <Copy01 className="size-3.5 text-utility-blue-600 dark:text-utility-blue-400 not-italic group-hover/copy:text-utility-blue-700 dark:group-hover/copy:text-utility-blue-200 transition-colors" aria-hidden="true" />
                )}
                <span className={cn(detailCopiedKey === profile.key ? 'text-success-primary font-semibold not-italic' : 'text-utility-blue-700 dark:text-utility-blue-300 font-medium')}>
                  {detailCopiedKey === profile.key ? 'Copied key!' : profile.key}
                </span>
              </button>
              {profile.parent && (
                <span className="not-italic text-quaternary font-sans ml-2">
                  (Copied from <span className="font-mono text-secondary font-medium">{profile.parent}</span>)
                </span>
              )}
            </div>
          </div>
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="brand"
              className="h-8 text-xs !bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs"
              disabled={busy}
              onClick={() => setAssignModalOpen(true)}
            >
              <Link01 className="size-3.5 text-white" aria-hidden="true" /> Assign to project
            </Button>
            <Button
              variant="secondary"
              className="h-8 text-xs shadow-xs"
              disabled={busy}
              onClick={() => setCopyModalOpen(true)}
            >
              <Copy01 className="size-3.5 text-secondary" aria-hidden="true" /> Copy profile
            </Button>
            {!profile.builtIn && (
              <Button
                variant="secondary"
                className="h-8 text-xs text-error-primary hover:bg-error-primary/10 border-error shadow-xs"
                disabled={busy}
                onClick={() => setDeleteModalOpen(true)}
              >
                <Trash01 className="size-3.5 text-fg-error-primary" aria-hidden="true" /> Delete
              </Button>
            )}
          </div>
        }
      >
        {err && (
          <div className="mb-4">
            <ErrorState message={err} />
          </div>
        )}

        {/* Info Note Banner */}
        <div
          className={cn(
            'mb-6 flex items-start gap-3 rounded-xl border p-3 text-xs leading-relaxed',
            profile.builtIn
              ? 'border-secondary bg-secondary/30 text-secondary'
              : 'border-utility-blue-200 bg-utility-blue-50/60 text-utility-blue-900 dark:border-utility-blue-800 dark:bg-utility-blue-950/30 dark:text-utility-blue-200'
          )}
        >
          <AlertCircle
            className={cn(
              'size-4 shrink-0 mt-0.5',
              profile.builtIn ? 'text-brand-secondary' : 'text-utility-blue-600 dark:text-utility-blue-400'
            )}
            aria-hidden="true"
          />
          <div>
            {profile.builtIn ? (
              <span>
                <strong className="font-semibold text-brand-secondary">Built-in profile is read-only.</strong> To activate or deactivate specific rules, or adjust severity thresholds, click <strong className="font-semibold text-brand-secondary">Copy profile</strong> to create a customized copy.
              </span>
            ) : (
              <span>
                <strong className="font-semibold text-utility-blue-700 dark:text-utility-blue-300">Custom profile active.</strong> You can toggle rule checkboxes and customize severity overrides below. Changes apply automatically to all projects assigned to this profile.
              </span>
            )}
          </div>
        </div>

        {/* Rules Section */}
        <div className="space-y-4">
          {/* Rules Toolbar */}
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-primary">Rules Activation</span>
              <span className="inline-flex items-center rounded-full bg-brand-primary/15 px-2.5 py-0.5 text-xs font-semibold text-brand-secondary border border-brand/20">
                {activeRulesCount} active
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {/* Active/Inactive Segmented Filter */}
              <div className="flex items-center rounded-lg border border-secondary bg-secondary/30 p-0.5 shadow-xs">
                <button
                  type="button"
                  onClick={() => setRuleFilter('all')}
                  className={cn(
                    'rounded-md px-2 py-1 text-xs font-semibold transition-all',
                    ruleFilter === 'all'
                      ? 'bg-primary text-primary shadow-xs border border-secondary/60'
                      : 'text-tertiary hover:text-primary'
                  )}
                >
                  All
                </button>
                <button
                  type="button"
                  onClick={() => setRuleFilter('active')}
                  className={cn(
                    'rounded-md px-2 py-1 text-xs font-semibold transition-all',
                    ruleFilter === 'active'
                      ? 'bg-primary text-brand-secondary shadow-xs border border-secondary/60'
                      : 'text-tertiary hover:text-primary'
                  )}
                >
                  Active ({activeRulesCount})
                </button>
                <button
                  type="button"
                  onClick={() => setRuleFilter('inactive')}
                  className={cn(
                    'rounded-md px-2 py-1 text-xs font-semibold transition-all',
                    ruleFilter === 'inactive'
                      ? 'bg-primary text-secondary shadow-xs border border-secondary/60'
                      : 'text-tertiary hover:text-primary'
                  )}
                >
                  Inactive ({(rules?.length ?? 0) - activeRulesCount})
                </button>
              </div>

              {/* Rules Search Input */}
              <div className="relative w-full sm:w-64">
                <SearchLg className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-tertiary" aria-hidden="true" />
                <Input
                  value={ruleQuery}
                  onChange={(e) => setRuleQuery(e.target.value)}
                  placeholder="Filter rules by name or key…"
                  className="h-8 pl-8 pr-7 text-xs"
                  aria-label="Filter rules by name or key"
                />
                {ruleQuery && (
                  <button
                    type="button"
                    onClick={() => setRuleQuery('')}
                    aria-label="Clear rule filter"
                    className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-tertiary transition hover:text-primary"
                  >
                    <XClose className="size-3" />
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Rules Table Content */}
          {rulesErr ? (
            <div className="space-y-3">
              <ErrorState message={rulesErr} />
            </div>
          ) : !rules ? (
            <div className="flex h-32 items-center justify-center">
              <Spinner label="Loading rules catalog…" />
            </div>
          ) : rules.length === 0 ? (
            <EmptyState
              icon={ShieldTick}
              title="No rules found"
              hint="The catalog has no rules available for this language."
            />
          ) : filtered.length === 0 ? (
            <EmptyState
              icon={ShieldTick}
              title="No matching rules"
              hint="No rules match your search or status filter."
            />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 max-h-[580px] overflow-y-auto p-0.5">
              {shown.map((r) => {
                const active = profile.activatedRules[r.key] !== undefined
                const override = profile.activatedRules[r.key]?.severity ?? ''
                const effectiveSeverity = (override || r.defaultSeverity) as Severity

                return (
                  <div
                    key={r.key}
                    className={cn(
                      'group flex items-center justify-between gap-3 rounded-xl border p-3 transition-all',
                      active
                        ? 'border-secondary bg-primary hover:border-brand/40 hover:bg-secondary/20 shadow-xs'
                        : 'border-secondary/60 bg-secondary/15 opacity-70 hover:opacity-100 hover:bg-secondary/30'
                    )}
                  >
                    {/* Checkbox + Rule Info */}
                    <div className="flex min-w-0 items-start gap-2.5">
                      <input
                        type="checkbox"
                        checked={active}
                        disabled={profile.builtIn || busy}
                        aria-label={`Activate ${r.name}`}
                        className="mt-0.5 size-4 shrink-0 rounded border-secondary text-brand-solid accent-brand-solid focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 cursor-pointer disabled:cursor-not-allowed"
                        onChange={(e) =>
                          run(() =>
                            e.target.checked
                              ? api.activateProfileRule(profile.key, r.key)
                              : api.deactivateProfileRule(profile.key, r.key),
                          )
                        }
                      />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-xs font-semibold text-primary" title={r.name}>
                          {r.name}
                        </div>
                        <div className="mt-0.5 flex items-center gap-1 font-mono text-[11px] text-tertiary italic">
                          <button
                            type="button"
                            onClick={() => copyKey(r.key)}
                            title={`Click to copy rule key: ${r.key}`}
                            aria-label={`Copy rule key ${r.key}`}
                            className="group/copy flex max-w-full items-center gap-1 rounded px-1 py-0.5 -mx-1 hover:bg-secondary/70 hover:text-primary transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-brand/60"
                          >
                            {detailCopiedKey === r.key ? (
                              <Check className="size-3 shrink-0 text-success-primary not-italic animate-scale-in" aria-hidden="true" />
                            ) : (
                              <Copy01 className="size-3 shrink-0 text-quaternary not-italic group-hover/copy:text-brand-secondary transition-colors" aria-hidden="true" />
                            )}
                            <span className={cn('truncate', detailCopiedKey === r.key && 'text-success-primary font-semibold not-italic')}>
                              {detailCopiedKey === r.key ? 'Copied!' : r.key}
                            </span>
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Severity Override */}
                    <div className="shrink-0">
                      {profile.builtIn || !active ? (
                        <SeverityBadge
                          severity={
                            effectiveSeverity === 'unknown'
                              ? 'info'
                              : (effectiveSeverity as 'critical' | 'high' | 'medium' | 'low' | 'info')
                          }
                          size="sm"
                          showIcon={true}
                        />
                      ) : (
                        <Select
                          size="sm"
                          className="h-6 text-[11px] w-28"
                          value={override || r.defaultSeverity}
                          ariaLabel={`Severity for ${r.name}`}
                          disabled={busy}
                          onValueChange={(v) =>
                            run(() =>
                              api.setProfileRuleSeverity(
                                profile.key,
                                r.key,
                                v === r.defaultSeverity ? '' : v,
                              ),
                            )
                          }
                          options={SEVERITIES.map((s) => ({
                            value: s,
                            label: s.charAt(0).toUpperCase() + s.slice(1),
                          }))}
                        />
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          {rules && filtered.length > shown.length && (
            <p className="text-xs text-tertiary">
              Showing {shown.length} of <span className="font-mono tabular-nums font-semibold text-secondary">{filtered.length}</span> rules. Refine your search query to narrow the list.
            </p>
          )}
        </div>
      </Card>

      {/* Modals via createPortal */}
      {copyModalOpen && (
        <CopyProfileModal
          profile={profile}
          onClose={() => setCopyModalOpen(false)}
          onDone={() => {
            setCopyModalOpen(false)
            onChanged()
          }}
          onError={setErr}
        />
      )}

      {assignModalOpen && (
        <AssignProfileModal
          profile={profile}
          onClose={() => setAssignModalOpen(false)}
          onDone={() => {
            setAssignModalOpen(false)
            onChanged()
          }}
          onError={setErr}
        />
      )}

      {deleteModalOpen && (
        <DeleteProfileModal
          profile={profile}
          onClose={() => setDeleteModalOpen(false)}
          onDeleted={() => {
            setDeleteModalOpen(false)
            onChanged()
          }}
          onError={setErr}
        />
      )}
    </div>
  )
}

// -------------------------------------------------------------
// Modals (rendered via createPortal onto document.body)
// -------------------------------------------------------------

function CopyProfileModal({
  profile,
  onClose,
  onDone,
  onError,
}: {
  profile: QualityProfile
  onClose: () => void
  onDone: () => void
  onError: (m: string) => void
}) {
  const [key, setKey] = useState('')
  const [name, setName] = useState('')
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    const cleanKey = key.trim()
    const cleanName = name.trim()

    if (!cleanKey || !cleanName) {
      setFormError('Both key and name are required.')
      return
    }

    setSaving(true)
    setFormError(null)
    try {
      await api.copyQualityProfile(profile.key, cleanKey, cleanName)
      onDone()
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to copy quality profile'
      setFormError(msg)
      onError(msg)
    } finally {
      setSaving(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="copy-modal-title"
        className="relative z-10 w-full max-w-lg rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden animate-scale-in text-left"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4 bg-secondary/30">
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-xl border border-brand/30 bg-brand-primary/10 text-brand-secondary shadow-sm">
              <Copy01 className="size-5" aria-hidden="true" />
            </div>
            <div>
              <h2 id="copy-modal-title" className="text-base font-bold text-primary">
                Copy Quality Profile
              </h2>
              <p className="text-xs text-secondary">
                Duplicate rules from &quot;{profile.name}&quot; ({profile.language})
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-lg p-1.5 text-tertiary transition hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
          >
            <XClose className="size-4" />
          </button>
        </div>

        {/* Modal Body */}
        <form onSubmit={submit} className="p-6 space-y-4">
          {formError && <ErrorState message={formError} />}

          <label htmlFor="copy-key" className="block space-y-1.5">
            <div className="flex items-center justify-between text-xs font-semibold text-secondary">
              <span>New Profile Key</span>
              <span className="font-mono text-[11px] font-normal text-tertiary">lowercase-hyphenated</span>
            </div>
            <Input
              id="copy-key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder={`custom-${profile.language.toLowerCase()}`}
              className="h-9 text-xs"
              autoFocus
            />
          </label>

          <label htmlFor="copy-name" className="block space-y-1.5">
            <span className="text-xs font-semibold text-secondary">Profile Display Name</span>
            <Input
              id="copy-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={`Custom ${profile.language.toUpperCase()}`}
              className="h-9 text-xs"
            />
          </label>

          {/* Modal Footer */}
          <div className="mt-6 flex items-center justify-end gap-3 pt-2">
            <Button
              variant="brand"
              type="submit"
              loading={saving}
              className="!bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs"
            >
              <Plus className="size-4" aria-hidden="true" /> Create copy
            </Button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  )
}

function AssignProfileModal({
  profile,
  onClose,
  onDone,
  onError,
}: {
  profile: QualityProfile
  onClose: () => void
  onDone: () => void
  onError: (m: string) => void
}) {
  const [projectKey, setProjectKey] = useState('')
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    const cleanProject = projectKey.trim()

    if (!cleanProject) {
      setFormError('Project key is required.')
      return
    }

    setSaving(true)
    setFormError(null)
    try {
      await api.assignProjectProfile(cleanProject, profile.language, profile.key)
      onDone()
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to assign profile to project'
      setFormError(msg)
      onError(msg)
    } finally {
      setSaving(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="assign-modal-title"
        className="relative z-10 w-full max-w-lg rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden animate-scale-in text-left"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4 bg-secondary/30">
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-xl border border-brand/30 bg-brand-primary/10 text-brand-secondary shadow-sm">
              <Link01 className="size-5" aria-hidden="true" />
            </div>
            <div>
              <h2 id="assign-modal-title" className="text-base font-bold text-primary">
                Assign Profile to Project
              </h2>
              <p className="text-xs text-secondary">
                Set &quot;{profile.name}&quot; for language <strong>{profile.language}</strong>
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-lg p-1.5 text-tertiary transition hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
          >
            <XClose className="size-4" />
          </button>
        </div>

        {/* Modal Body */}
        <form onSubmit={submit} className="p-6 space-y-4">
          {formError && <ErrorState message={formError} />}

          <label htmlFor="assign-project-key" className="block space-y-1.5">
            <div className="flex items-center justify-between text-xs font-semibold text-secondary">
              <span>Target Project Key</span>
              <span className="font-mono text-[11px] font-normal text-tertiary">e.g. backend-service</span>
            </div>
            <Input
              id="assign-project-key"
              value={projectKey}
              onChange={(e) => setProjectKey(e.target.value)}
              placeholder="my-project-key"
              className="h-9 text-xs"
              autoFocus
            />
          </label>

          {/* Modal Footer */}
          <div className="mt-6 flex items-center justify-end gap-3 pt-2">
            <Button
              variant="brand"
              type="submit"
              loading={saving}
              className="!bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs"
            >
              <Link01 className="size-4" aria-hidden="true" /> Assign profile
            </Button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  )
}

function DeleteProfileModal({
  profile,
  onClose,
  onDeleted,
  onError,
}: {
  profile: QualityProfile
  onClose: () => void
  onDeleted: () => void
  onError: (m: string) => void
}) {
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  async function handleDelete() {
    setSaving(true)
    setFormError(null)
    try {
      await api.deleteQualityProfile(profile.key)
      onDeleted()
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to delete quality profile'
      setFormError(msg)
      onError(msg)
    } finally {
      setSaving(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="delete-profile-title"
        className="relative z-10 w-full max-w-md rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden animate-scale-in text-left"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4 bg-secondary/30">
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-xl border border-error bg-error-primary/10 text-error-primary shadow-sm">
              <Trash01 className="size-5 text-fg-error-primary" aria-hidden="true" />
            </div>
            <div>
              <h2 id="delete-profile-title" className="text-base font-bold text-primary">
                Delete Quality Profile
              </h2>
              <p className="text-xs text-secondary">This action cannot be undone.</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-lg p-1.5 text-tertiary transition hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
          >
            <XClose className="size-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4">
          {formError && <ErrorState message={formError} />}

          <p className="text-xs text-secondary leading-relaxed">
            Are you sure you want to permanently delete custom profile{' '}
            <strong className="text-primary font-semibold">&quot;{profile.name}&quot;</strong> (
            <span className="font-mono text-xs">{profile.key}</span>)?
          </p>
          <p className="text-xs text-tertiary">
            Any projects previously assigned to this profile will fall back to the built-in default for {profile.language}.
          </p>

          {/* Modal Footer */}
          <div className="mt-6 flex items-center justify-end gap-3 pt-2">
            <Button
              variant="danger"
              type="button"
              loading={saving}
              onClick={handleDelete}
              className="bg-error-solid text-white hover:bg-error-solid/90 shadow-xs"
            >
              <Trash01 className="size-4" aria-hidden="true" /> Delete profile
            </Button>
          </div>
        </div>
      </div>
    </div>,
    document.body,
  )
}
