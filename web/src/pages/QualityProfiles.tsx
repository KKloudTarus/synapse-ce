import { useEffect, useMemo, useState } from 'react'
import { Copy, Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import type { QualityProfile, RuleSummary } from '../lib/types'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner } from '../components/ui'

const SEVERITIES = ['critical', 'high', 'medium', 'low'] // matches RuleSeverity
const RULE_RENDER_CAP = 100

// QualityProfiles is the management page for named, per-language rule sets: browse the built-in default
// per language, copy it into a custom profile, toggle rules + severities, assign it to a project.
export function QualityProfiles() {
  const [profiles, setProfiles] = useState<QualityProfile[] | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    let live = true
    setErr(null)
    api.listQualityProfiles()
      .then((list) => { if (live) setProfiles(list) })
      .catch((e) => { if (live) setErr(e instanceof ApiError ? e.message : 'Failed to load profiles') })
    return () => { live = false }
  }, [refresh])

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
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Quality Profiles</h1>
        <p className="mt-1 max-w-2xl text-sm text-mutedfg">Each language has a built-in “Synapse way” profile that activates every catalog rule. Copy it to a custom profile to activate or deactivate rules and override severities, then assign it to a project.</p>
      </div>
      <div className="flex flex-col gap-4 lg:flex-row">
        <nav className="w-full shrink-0 space-y-4 lg:w-72" aria-label="Quality profiles">
          {byLanguage.length === 0 && <EmptyState icon={ShieldCheck} title="No profiles" hint="No languages are present in the rule catalog." />}
          {byLanguage.map(([language, list]) => (
            <div key={language}>
              <div className="mb-1 text-xs font-semibold uppercase tracking-[0.14em] text-subtlefg">{language}</div>
              <ul className="space-y-1">
                {list.map((p) => (
                  <li key={p.key}>
                    <button
                      type="button"
                      onClick={() => setSelectedKey(p.key)}
                      aria-pressed={p.key === selectedKey}
                      className="flex w-full items-center justify-between gap-2 rounded-lg border border-border px-3 py-2 text-left text-sm transition-colors hover:bg-elevated/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 aria-pressed:border-brand/40 aria-pressed:bg-brand/5"
                    >
                      <span className="truncate">{p.name}</span>
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
            : <Card title="Select a profile"><EmptyState icon={ShieldCheck} title="No profile selected" hint="Choose a profile on the left to view and edit its rules." /></Card>}
        </div>
      </div>
    </div>
  )
}

function ProfileDetail({ profile, onChanged }: { profile: QualityProfile; onChanged: () => void }) {
  const [rules, setRules] = useState<RuleSummary[] | null>(null)
  const [rulesErr, setRulesErr] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [copyOpen, setCopyOpen] = useState(false)
  const [ruleQuery, setRuleQuery] = useState('')

  useEffect(() => {
    let live = true
    setRules(null)
    setRulesErr(null)
    api.listRules({ languages: [profile.language] })
      .then((list) => { if (live) setRules(list) })
      .catch((e) => { if (live) setRulesErr(e instanceof ApiError ? e.message : 'Failed to load rules') })
    return () => { live = false }
  }, [profile.language])

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
      actions={<div className="flex items-center gap-2">
        <Pill>{profile.builtIn ? 'Built-in' : 'Custom'}</Pill>
        <Button variant="secondary" disabled={busy} onClick={() => setCopyOpen((v) => !v)}><Copy className="size-4" aria-hidden="true" /> Copy</Button>
        {!profile.builtIn && <Button variant="secondary" disabled={busy} onClick={() => run(() => api.deleteQualityProfile(profile.key))}><Trash2 className="size-4" aria-hidden="true" /> Delete</Button>}
      </div>}
    >
      <p className="font-mono text-xs text-mutedfg">{profile.key} · {profile.language}{profile.parent ? ` · from ${profile.parent}` : ''}</p>
      {profile.builtIn && <p className="mt-3 text-xs text-mutedfg">Built-in profiles are immutable. Copy this profile to customize its rules, then assign the copy to a project.</p>}
      {copyOpen && <CopyForm profile={profile} onDone={() => { setCopyOpen(false); onChanged() }} onError={setErr} />}
      {err && <div className="mt-3"><ErrorState message={err} /></div>}

      <AssignForm profile={profile} onError={setErr} onDone={onChanged} />

      <div className="mt-5">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <div className="text-sm font-medium">Rules <span className="font-mono tabular-nums text-mutedfg">({Object.keys(profile.activatedRules).length} active)</span></div>
          <label className="w-full sm:w-64">
            <span className="sr-only">Filter rules</span>
            <Input value={ruleQuery} onChange={(e) => setRuleQuery(e.target.value)} placeholder="Filter rules by name or key…" />
          </label>
        </div>
        {rulesErr ? <div className="space-y-3"><ErrorState message={rulesErr} /></div>
          : !rules ? <div className="flex h-24 items-center justify-center"><Spinner /></div>
          : rules.length === 0 ? <EmptyState icon={ShieldCheck} title="No rules" hint="The catalog has no rules for this language." />
          : filtered.length === 0 ? <EmptyState icon={ShieldCheck} title="No matching rules" hint="No rules match the filter." />
          : (
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="min-w-full text-left text-sm">
                <thead className="bg-elevated/95 text-[11px] uppercase tracking-[0.14em] text-foreground">
                  <tr>
                    <th scope="col" className="px-3 py-2 font-semibold">Active</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Rule</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {shown.map((r) => {
                    const active = profile.activatedRules[r.key] !== undefined
                    const override = profile.activatedRules[r.key]?.severity ?? ''
                    return (
                      <tr key={r.key} className="hover:bg-elevated/30">
                        <td className="px-3 py-2">
                          <input
                            type="checkbox"
                            checked={active}
                            disabled={profile.builtIn || busy}
                            aria-label={`Activate ${r.name}`}
                            className="size-4 accent-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                            onChange={(e) => run(() => e.target.checked ? api.activateProfileRule(profile.key, r.key) : api.deactivateProfileRule(profile.key, r.key))}
                          />
                        </td>
                        <td className="px-3 py-2"><div className="font-medium">{r.name}</div><div className="font-mono text-xs text-mutedfg">{r.key}</div></td>
                        <td className="px-3 py-2">
                          <Select
                            value={override || r.defaultSeverity}
                            ariaLabel={`Severity for ${r.name}`}
                            disabled={profile.builtIn || !active || busy}
                            onValueChange={(v) => run(() => api.setProfileRuleSeverity(profile.key, r.key, v === r.defaultSeverity ? '' : v))}
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
          <p className="mt-2 text-xs text-mutedfg">Showing {shown.length} of <span className="font-mono tabular-nums">{filtered.length}</span> rules. Refine the filter to narrow the list.</p>
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
      className="mt-4 grid gap-3 rounded-lg border border-border bg-bg p-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
      onSubmit={async (e) => {
        e.preventDefault()
        setSaving(true)
        try { await api.copyQualityProfile(profile.key, key.trim(), name.trim()); onDone() }
        catch (err) { onError(err instanceof ApiError ? err.message : 'Copy failed') }
        finally { setSaving(false) }
      }}
    >
      <Field label="New key" hint="lowercase-hyphenated" htmlFor="copy-key"><Input id="copy-key" value={key} onChange={(e) => setKey(e.target.value)} placeholder="team-go" /></Field>
      <Field label="Name" htmlFor="copy-name"><Input id="copy-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Team Go" /></Field>
      <Button variant="brand" type="submit" loading={saving}><Plus className="size-4" aria-hidden="true" /> Create copy</Button>
    </form>
  )
}

function AssignForm({ profile, onError, onDone }: { profile: QualityProfile; onError: (m: string) => void; onDone: () => void }) {
  const [projectKey, setProjectKey] = useState('')
  const [saving, setSaving] = useState(false)
  return (
    <form
      className="mt-4 grid gap-3 rounded-lg border border-dashed border-border bg-bg p-3 sm:grid-cols-[1fr_auto] sm:items-end"
      onSubmit={async (e) => {
        e.preventDefault()
        if (!projectKey.trim()) return
        setSaving(true)
        try { await api.assignProjectProfile(projectKey.trim(), profile.language, profile.key); setProjectKey(''); onDone() }
        catch (err) { onError(err instanceof ApiError ? err.message : 'Assign failed') }
        finally { setSaving(false) }
      }}
    >
      <Field label={`Assign to a project (${profile.language})`} htmlFor="assign-project"><Input id="assign-project" value={projectKey} onChange={(e) => setProjectKey(e.target.value)} placeholder="project-key" /></Field>
      <Button variant="secondary" type="submit" loading={saving}>Assign</Button>
    </form>
  )
}
