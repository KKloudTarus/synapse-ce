import { AlertCircle, Check, Copy01, Link01, SearchLg, ShieldTick, Trash01, XClose } from '@untitledui/icons'
import { useMemo, useState } from 'react'
import { Button, Card, EmptyState, ErrorState, Input, Select, Spinner, cn } from '../../../components/ui'
import { SeverityBadge } from '../../../components/synapse/SeverityBadge'
import { useFetch } from '../../../hooks'
import { api, ApiError } from '../../../lib/api'
import type { QualityProfile, RuleSummary, Severity } from '../../../lib/types'
import { RULE_RENDER_CAP, SEVERITIES, type RuleFilter } from './qualityProfileTypes'
import { AssignProfileModal, CopyProfileModal, DeleteProfileModal } from './ProfileModals'

export function ProfileDetail({
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
    // Copies the rule/profile key so it can be pasted into search, the CLI (--rule), .synapseignore,
    // or a VEX file. Falls back to a hidden textarea + execCommand for non-secure contexts where the
    // async Clipboard API is unavailable, so the button always does something visible.
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text).catch(() => fallbackCopy(text))
    } else {
      fallbackCopy(text)
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
            <div className="flex items-center gap-1.5 font-mono text-xs">
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
              variant="primary"
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
                    {/* Rule activation indicator. A native disabled checkbox greys out even when
                        checked, so a read-only built-in profile's ACTIVE rules looked inactive. This
                        custom box keeps active rules vividly brand-filled whether or not they're
                        editable; only editable (custom) profiles toggle on click. */}
                    <div className="flex min-w-0 items-start gap-2.5">
                      <RuleActivationBox
                        active={active}
                        readOnly={profile.builtIn}
                        busy={busy}
                        name={r.name}
                        onToggle={() =>
                          run(() =>
                            active
                              ? api.deactivateProfileRule(profile.key, r.key)
                              : api.activateProfileRule(profile.key, r.key),
                          )
                        }
                      />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-xs font-semibold text-primary" title={r.name}>
                          {r.name}
                        </div>
                        <div className="mt-0.5 flex items-center gap-1 font-mono text-[11px] text-tertiary">
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

// RuleActivationBox shows whether a rule is active in the profile. Unlike a native disabled checkbox
// (which the browser greys out even when checked), an ACTIVE rule stays vividly brand-filled here even
// on a read-only built-in profile. Only editable (custom) profiles are clickable.
function RuleActivationBox({
  active,
  readOnly,
  busy,
  name,
  onToggle,
}: {
  active: boolean
  readOnly: boolean
  busy: boolean
  name: string
  onToggle: () => void
}) {
  const box = (
    <span
      className={cn(
        'flex size-4 items-center justify-center rounded border transition-colors',
        active ? 'border-brand-solid bg-brand-solid text-white' : 'border-secondary bg-primary',
      )}
    >
      {active && <Check className="size-3" aria-hidden="true" />}
    </span>
  )

  if (readOnly) {
    return (
      <span
        role="checkbox"
        aria-checked={active}
        aria-disabled="true"
        aria-label={`${name} — ${active ? 'active' : 'inactive'} (read-only)`}
        className="mt-0.5 shrink-0 cursor-not-allowed"
      >
        {box}
      </span>
    )
  }

  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={active}
      aria-label={`${active ? 'Deactivate' : 'Activate'} ${name}`}
      disabled={busy}
      onClick={onToggle}
      className="mt-0.5 shrink-0 cursor-pointer rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 disabled:cursor-not-allowed disabled:opacity-50"
    >
      {box}
    </button>
  )
}

// fallbackCopy copies text without the async Clipboard API (unavailable in non-secure contexts).
function fallbackCopy(text: string) {
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
  } catch {
    /* best-effort; the transient "Copied" state still confirms the intent */
  }
}
