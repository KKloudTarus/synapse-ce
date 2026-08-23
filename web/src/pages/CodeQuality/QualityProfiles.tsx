import { useMemo, useState } from 'react'
import { Copy01, Plus, ShieldTick, Trash01 } from '@untitledui/icons'
import { api, ApiError } from '../../lib/api'
import type { QualityProfile, RuleSummary } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Input, Pill, Select, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'

const SEVERITIES = ['critical', 'high', 'medium', 'low'] // matches RuleSeverity
const RULE_RENDER_CAP = 100

// QualityProfiles is the management page for named, per-language rule sets: browse the built-in default
// per language, copy it into a custom profile, toggle rules + severities, assign it to a project.
export function QualityProfiles() {
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)

  const { data: profiles, error: err } = useFetch<QualityProfile[]>(
    () => api.listQualityProfiles(),
    { deps: [refresh] },
  )

  const byLanguage = useMemo(() => {
    const map = new Map<string, QualityProfile[]>()
    for (const p of profiles ?? []) {
      const list = map.get(p.language) ?? []
      list.push(p)
      map.set(p.language, list)
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [profiles])

  const selected = profiles?.find((p) => p.key === selectedKey) ?? null

  if (err) return <div className="space-y-3"><ErrorState message={err} /><Button variant="secondary" onClick={() => setRefresh((c) => c + 1)}>Retry</Button></div>
  if (!profiles) return <div className="flex h-40 items-center justify-center"><Spinner label="Loading quality profiles…" /></div>

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Quality Profiles</h1>
          <p className="mt-1 text-sm text-secondary">Copy a built-in profile to customize rules and severities, then assign to a project</p>
        </div>
      </header>
      <div className="flex flex-col gap-4 lg:flex-row">
        <nav className="w-full shrink-0 space-y-4 lg:sticky lg:top-4 lg:w-72 lg:self-start" aria-label="Quality profiles">
          {byLanguage.length === 0 && <EmptyState icon={ShieldTick} title="No profiles" hint="No languages are present in the rule catalog." />}
          {byLanguage.map(([language, list]) => (
            <div key={language}>
              <div className="mb-1 text-xs font-semibold uppercase tracking-[0.14em] text-quaternary">{language}</div>
              <ul className="space-y-1">
                {list.map((p) => (
                  <li key={p.key}>
                    <button
                      type="button"
                      onClick={() => setSelectedKey(p.key)}
                      aria-pressed={p.key === selectedKey}
                      className="flex w-full items-center justify-between gap-2 rounded-lg border border-secondary px-3 py-2 text-left text-sm transition-colors hover:bg-secondary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 aria-pressed:border-brand-solid aria-pressed:bg-brand-primary/15 aria-pressed:ring-1 aria-pressed:ring-brand-solid"
                    >
                      <span className={cn('truncate font-medium', p.key === selectedKey ? 'text-brand-secondary font-semibold' : 'text-primary')}>{p.name}</span>
                      <Pill className="tabular-nums">{p.builtIn ? 'Built-in' : 'Custom'}</Pill>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <div className="min-w-0 flex-1">
          {selected
            ? <ProfileDetail key={selected.key} profile={selected} onChanged={() => setRefresh((c) => c + 1)} />
            : <Card title="Select a profile"><EmptyState icon={ShieldTick} title="No profile selected" hint="Choose a profile on the left to view and edit its rules." /></Card>}
        </div>
      </div>
    </div>
  )
}

function ProfileDetail({ profile, onChanged }: { profile: QualityProfile; onChanged: () => void }) {
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [copyOpen, setCopyOpen] = useState(false)
  const [ruleQuery, setRuleQuery] = useState('')

  const { data: rules, error: rulesErr } = useFetch<RuleSummary[]>(
    () => api.listRules({ languages: [profile.language] }),
    { deps: [profile.language] },
  )

  const filtered = useMemo(() => {
    const q = ruleQuery.trim().toLowerCase()
    const all = rules ?? []
    if (!q) return all
    return all.filter((r) => r.key.toLowerCase().includes(q) || r.name.toLowerCase().includes(q))
  }, [rules, ruleQuery])
  const shown = filtered.slice(0, RULE_RENDER_CAP)

  async function run(action: () => Promise<unknown>) {
    setBusy(true)
    setErr(null)
    try { await action(); onChanged() } catch (e) { setErr(e instanceof ApiError ? e.message : 'Action failed') } finally { setBusy(false) }
  }

  return (
    <Card
      title={profile.name}
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <Pill>{profile.builtIn ? 'Built-in' : 'Custom'}</Pill>
          <AssignInlineForm profile={profile} onError={setErr} onDone={onChanged} />
          <Button variant="secondary" className="h-8 text-xs" disabled={busy} onClick={() => setCopyOpen((v) => !v)}>
            <Copy01 className="size-3.5" aria-hidden="true" /> Copy
          </Button>
          {!profile.builtIn && (
            <Button variant="secondary" className="h-8 text-xs" disabled={busy} onClick={() => run(() => api.deleteQualityProfile(profile.key))}>
              <Trash01 className="size-3.5" aria-hidden="true" /> Delete
            </Button>
          )}
        </div>
      }
    >
      {copyOpen && <CopyForm profile={profile} onDone={() => { setCopyOpen(false); onChanged() }} onError={setErr} />}
      {err && <div className="mt-3"><ErrorState message={err} /></div>}

      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-sm font-medium text-primary">
            Rules <span className="font-mono tabular-nums text-tertiary">({Object.keys(profile.activatedRules).length} active)</span>
          </div>
          <label className="w-full sm:w-64">
            <span className="sr-only">Filter rules</span>
            <Input
              value={ruleQuery}
              onChange={(e) => setRuleQuery(e.target.value)}
              placeholder="Filter rules by name or key…"
              className="h-8 py-1 text-xs"
            />
          </label>
        </div>
        {rulesErr ? (
          <div className="space-y-3"><ErrorState message={rulesErr} /></div>
        ) : !rules ? (
          <div className="flex h-24 items-center justify-center"><Spinner /></div>
        ) : rules.length === 0 ? (
          <EmptyState icon={ShieldTick} title="No rules" hint="The catalog has no rules for this language." />
        ) : filtered.length === 0 ? (
          <EmptyState icon={ShieldTick} title="No matching rules" hint="No rules match the filter." />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-secondary">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-secondary bg-secondary/50 text-[11px] font-semibold uppercase tracking-[0.14em] text-tertiary">
                <tr>
                  <th scope="col" className="w-10 px-3 py-2 font-semibold">Active</th>
                  <th scope="col" className="px-3 py-2 font-semibold">Rule</th>
                  <th scope="col" className="w-36 px-3 py-2 text-right font-semibold">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-secondary">
                {shown.map((r) => {
                  const active = profile.activatedRules[r.key] !== undefined
                  const override = profile.activatedRules[r.key]?.severity ?? ''
                  return (
                    <tr key={r.key} className="transition-colors hover:bg-secondary/30">
                      <td className="w-10 px-3 py-2">
                        <input
                          type="checkbox"
                          checked={active}
                          disabled={profile.builtIn || busy}
                          aria-label={`Activate ${r.name}`}
                          className="size-4 rounded accent-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                          onChange={(e) =>
                            run(() =>
                              e.target.checked
                                ? api.activateProfileRule(profile.key, r.key)
                                : api.deactivateProfileRule(profile.key, r.key),
                            )
                          }
                        />
                      </td>
                      <td className="px-3 py-2">
                        <span className="text-sm font-medium text-primary">{r.name}</span>
                        <span className="ml-2 font-mono text-xs text-tertiary">{r.key}</span>
                      </td>
                      <td className="w-36 px-3 py-2 text-right">
                        <Select
                          size="sm"
                          className="h-7 text-xs"
                          value={override || r.defaultSeverity}
                          ariaLabel={`Severity for ${r.name}`}
                          disabled={profile.builtIn || !active || busy}
                          onValueChange={(v) =>
                            run(() =>
                              api.setProfileRuleSeverity(profile.key, r.key, v === r.defaultSeverity ? '' : v),
                            )
                          }
                          options={SEVERITIES.map((s) => ({ value: s, label: s }))}
                        />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        {rules && filtered.length > shown.length && (
          <p className="mt-2 text-xs text-tertiary">
            Showing {shown.length} of <span className="font-mono tabular-nums">{filtered.length}</span> rules. Refine the filter to narrow the list.
          </p>
        )}
      </div>
    </Card>
  )
}

function CopyForm({ profile, onDone, onError }: { profile: QualityProfile; onDone: () => void; onError: (m: string) => void }) {
  const [key, setKey] = useState('')
  const [name, setName] = useState('')
  const [saving, setSaving] = useState(false)
  return (
    <form
      className="mb-4 rounded-xl border border-secondary bg-secondary/30 p-4"
      onSubmit={async (e) => {
        e.preventDefault()
        setSaving(true)
        try { await api.copyQualityProfile(profile.key, key.trim(), name.trim()); onDone() }
        catch (err) { onError(err instanceof ApiError ? err.message : 'Copy failed') }
        finally { setSaving(false) }
      }}
    >
      <div className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]">
        <label htmlFor="copy-key" className="block space-y-1.5">
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-tertiary">
            <span>New key</span>
            <span className="text-[10px] font-normal normal-case text-quaternary">lowercase-hyphenated</span>
          </div>
          <Input id="copy-key" value={key} onChange={(e) => setKey(e.target.value)} placeholder="team-go" className="h-10" />
        </label>

        <label htmlFor="copy-name" className="block space-y-1.5">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">
            <span>Name</span>
          </div>
          <Input id="copy-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Team Go" className="h-10" />
        </label>

        <div className="flex flex-col justify-end">
          <Button variant="brand" type="submit" loading={saving} className="h-10 whitespace-nowrap px-4">
            <Plus className="size-4" aria-hidden="true" /> Create copy
          </Button>
        </div>
      </div>
    </form>
  )
}

function AssignInlineForm({ profile, onError, onDone }: { profile: QualityProfile; onError: (m: string) => void; onDone: () => void }) {
  const [projectKey, setProjectKey] = useState('')
  const [saving, setSaving] = useState(false)
  return (
    <form
      className="flex items-center gap-1.5"
      onSubmit={async (e) => {
        e.preventDefault()
        if (!projectKey.trim()) return
        setSaving(true)
        try {
          await api.assignProjectProfile(projectKey.trim(), profile.language, profile.key)
          setProjectKey('')
          onDone()
        } catch (err) {
          onError(err instanceof ApiError ? err.message : 'Assign failed')
        } finally {
          setSaving(false)
        }
      }}
    >
      <input
        type="text"
        id="assign-project"
        value={projectKey}
        onChange={(e) => setProjectKey(e.target.value)}
        placeholder="project-key"
        aria-label={`Assign ${profile.name} to project`}
        className="h-8 w-44 rounded-md border border-secondary bg-primary px-2.5 text-xs text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 sm:w-56"
      />
      <Button variant="brand" className="h-8 px-3 text-xs" type="submit" loading={saving} disabled={!projectKey.trim() || saving}>
        Assign
      </Button>
    </form>
  )
}
