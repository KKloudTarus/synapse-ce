import { useEffect, useState } from 'react'
import { Button, Card, ErrorState, Field, Input, Pill, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import { newIdempotencyKey } from '../../lib/api/client'
import type { OwnershipAssetMapping, OwnershipCapability, OwnershipMapping, OwnershipPolicyInput, OwnershipRule, OwnershipRun, OwnershipRunItem, OwnershipSnapshot } from '../../lib/api/ownership'
import { Choice, ownershipError, ResolutionEvidence, TeamChoice, useOwnershipTeams } from './shared'

const jsonClass = 'min-h-40 w-full rounded-lg border border-secondary bg-primary p-3 font-mono text-xs text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40'
const emptyRules = JSON.stringify([{ id: 'critical-findings', priority: 10, when: { severities: ['critical'] }, team_id: '' }], null, 2)

export function RoutingPolicies({ capability }: { capability: OwnershipCapability }) {
  const engagements = useFetch(() => api.listEngagements())
  const [engagement, setEngagement] = useState('')
  useEffect(() => { if (!engagement && engagements.data?.[0]) setEngagement(engagements.data[0].id) }, [engagement, engagements.data])
  const policies = useFetch(() => engagement ? api.ownershipPolicies(engagement) : Promise.resolve({ items: [] }), { enabled: !!engagement, deps: [engagement] })
  const snapshots = useFetch(() => engagement ? api.ownershipSnapshots(engagement) : Promise.resolve({ items: [] }), { enabled: !!engagement, deps: [engagement] })
  const teams = useOwnershipTeams()
  const assets = useFetch((signal) => api.listBusinessAssets('limit=200', signal))
  const [selected, setSelected] = useState('')
  const [repository, setRepository] = useState('')
  const [snapshot, setSnapshot] = useState('')
  const [rules, setRules] = useState(emptyRules)
  const [mappingRepository, setMappingRepository] = useState('')
  const [mappingOwner, setMappingOwner] = useState('')
  const [mappingTeam, setMappingTeam] = useState('')
  const [asset, setAsset] = useState('')
  const [assetTeam, setAssetTeam] = useState('')
  const ownerMappings = useFetch(
    () => engagement && repository ? api.ownershipMappings(engagement, repository) : Promise.resolve({ items: [] }),
    { enabled: !!engagement && !!repository, deps: [engagement, repository] },
  )
  const assetMappings = useFetch(() => api.ownershipAssetMappings())
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [run, setRun] = useState<OwnershipRun>()
  const selectedPolicy = policies.data?.items.find((policy) => policy.id === selected)
  const version = useFetch(() => selectedPolicy?.latest_version ? api.ownershipVersion(selectedPolicy.id, selectedPolicy.latest_version) : Promise.resolve(null), { enabled: !!selectedPolicy?.latest_version, deps: [selectedPolicy?.id, selectedPolicy?.latest_version] })
  useEffect(() => {
    const policy = version.data?.policy
    if (!policy) return
    setRepository(policy.repository); setSnapshot(policy.snapshot_id ?? ''); setRules(JSON.stringify(policy.rules ?? [], null, 2))
  }, [version.data])
  useEffect(() => { setMappingRepository(repository) }, [repository])
  useEffect(() => { setSelected(''); setRepository(''); setSnapshot(''); setRules(emptyRules); setRun(undefined) }, [engagement])
  const routingError = error || policies.error || snapshots.error || teams.error || engagements.error || assets.error || version.error || ownerMappings.error || assetMappings.error
  function parseRules(): OwnershipRule[] {
    const value: unknown = JSON.parse(rules)
    if (!Array.isArray(value)) throw new Error('Rules must be a JSON array.')
    return value as OwnershipRule[]
  }
  async function savePolicy() {
    if (!engagement) return
    setBusy(true); setError(''); setNotice('')
    try {
      const current = selectedPolicy
      const currentVersion = version.data?.policy
      const input: OwnershipPolicyInput = {
        engagement_id: engagement, repository, snapshot_id: snapshot,
        version: current ? current.latest_version + 1 : 1, rules: parseRules(),
        mappings: ownerMappings.data?.items.map((item) => item.mapping) ?? currentVersion?.mappings ?? [],
        assets: assetMappings.data?.items.map((item) => item.mapping) ?? currentVersion?.assets ?? [],
      }
      const result = await api.saveOwnershipPolicy(input, current?.id)
      setNotice(`Policy version ${result.policy.version} saved. Preview it before activation.`)
      await policies.refetch()
      if (!current) setSelected(result.policy.policy_id)
    } catch (error) { setError(ownershipError(error)) }
    finally { setBusy(false) }
  }
  async function activate() {
    if (!selectedPolicy || !version.data) return
    setBusy(true); setError(''); setNotice('')
    try { await api.activateOwnershipPolicy(selectedPolicy.id, selectedPolicy.latest_version, selectedPolicy.revision, version.data.content_hash); setRun(undefined); setNotice(`Version ${selectedPolicy.latest_version} activated. Run a fresh preview before any historical reroute.`); await policies.refetch() }
    catch (error) { setError(ownershipError(error)) } finally { setBusy(false) }
  }
  async function start(mode: 'preview' | 'reroute') {
    if (!selectedPolicy || !version.data) return
    setBusy(true); setError(''); setNotice('')
    try {
      const input = { version: selectedPolicy.latest_version, policy_revision: selectedPolicy.revision, policy_hash: version.data.content_hash, ...(mode === 'reroute' ? { preview_id: run?.id } : {}), filter: { engagement_id: engagement } }
      const started = await api.startOwnershipRun(selectedPolicy.id, mode, input, newIdempotencyKey())
      setRun(started); setNotice(mode === 'preview' ? 'Preview queued.' : 'Historical reroute queued from the completed preview.')
    } catch (error) { setError(ownershipError(error)) } finally { setBusy(false) }
  }
  async function saveMapping() {
    if (!engagement || !mappingRepository || !mappingOwner || !mappingTeam) return
    setBusy(true); setError('')
    try { await api.saveOwnershipMapping(engagement, { mapping: { repository: mappingRepository, owner: mappingOwner, team_id: mappingTeam }, revision: 1 }); setMappingOwner(''); await ownerMappings.refetch(); setNotice('Owner token mapping saved and ready for the next immutable policy version.'); }
    catch (error) { setError(ownershipError(error)) } finally { setBusy(false) }
  }
  async function saveAssetMapping() {
    if (!asset || !assetTeam) return
    setBusy(true); setError('')
    try { await api.saveOwnershipAssetMapping({ mapping: { asset_id: asset, team_id: assetTeam }, revision: 1 }); setAsset(''); await assetMappings.refetch(); setNotice('Business asset mapping saved and ready for the next immutable policy version.'); }
    catch (error) { setError(ownershipError(error)) } finally { setBusy(false) }
  }
  async function removeMapping(item: NonNullable<typeof ownerMappings.data>['items'][number]) {
    setBusy(true); setError('')
    try { await api.saveOwnershipMapping(engagement, item, true); await ownerMappings.refetch(); setNotice('Owner token mapping removed.') }
    catch (error) { setError(ownershipError(error)) } finally { setBusy(false) }
  }
  async function removeAssetMapping(item: NonNullable<typeof assetMappings.data>['items'][number]) {
    setBusy(true); setError('')
    try { await api.saveOwnershipAssetMapping(item, true); await assetMappings.refetch(); setNotice('Business asset mapping removed.') }
    catch (error) { setError(ownershipError(error)) } finally { setBusy(false) }
  }
  return <div className="space-y-4">
    {routingError && <ErrorState message={routingError} />}{notice && <p role="status" className="text-sm text-success-primary">{notice}</p>}
    <Card title="Policy scope"><div className="grid items-end gap-3 md:grid-cols-3">
      <Field label="Engagement"><Choice value={engagement} onChange={(event) => setEngagement(event.target.value)} disabled={busy || engagements.loading}><option value="">Choose engagement</option>{engagements.data?.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Choice></Field>
      <Field label="Policy"><Choice value={selected} onChange={(event) => { setSelected(event.target.value); setRun(undefined) }} disabled={busy || policies.loading}><option value="">Create new policy</option>{policies.data?.items.map((item) => <option key={item.id} value={item.id}>{item.repository || 'Engagement fallback'} · v{item.latest_version}{item.active_version ? ` (active v${item.active_version})` : ''}</option>)}</Choice></Field>
      <Button variant="secondary" onClick={policies.refetch} disabled={!engagement || busy}>Reload policies</Button>
    </div></Card>
    <Card title="Immutable policy version"><div className="space-y-4">
      {version.loading && <Spinner label="Loading policy…" />}
      <div className="grid gap-3 md:grid-cols-2"><Field label="Repository identity" hint="Leave empty for an engagement fallback policy."><Input value={repository} onChange={(event) => setRepository(event.target.value)} disabled={busy || !!selectedPolicy} maxLength={2048} /></Field><Field label="Trusted CODEOWNERS snapshot"><Choice value={snapshot} onChange={(event) => setSnapshot(event.target.value)} disabled={busy}><option value="">No CODEOWNERS snapshot</option>{snapshots.data?.items.map((item) => <option key={item.id} value={item.id} disabled={item.trust === 'untrusted'}>{item.file_path} · {item.trust} · {item.source_revision}</option>)}</Choice></Field></div>
      <Field label="Ordered routing rules" hint="Conditions are AND across fields and OR within each list. Lower priority wins. Use { exclude: true } instead of team_id for an exclusion."><textarea aria-label="Ordered routing rules" className={jsonClass} value={rules} onChange={(event) => setRules(event.target.value)} spellCheck={false} disabled={busy} /></Field>
      <div className="flex flex-wrap gap-2"><Button onClick={() => void savePolicy()} loading={busy} disabled={!engagement}>Save new version</Button>{selectedPolicy && version.data && <><Button variant="secondary" onClick={() => void start('preview')} disabled={busy || !capability.routing_available}>Preview</Button><Button variant="secondary" onClick={() => void activate()} disabled={busy || selectedPolicy.active_version === selectedPolicy.latest_version}>Activate version</Button><Button variant="secondary" onClick={() => void start('reroute')} disabled={busy || capability.mode !== 'enforce' || !capability.routing_available || run?.mode !== 'preview' || run.state !== 'completed'}>Reroute previewed findings</Button></>}</div>
      <p className="text-xs text-secondary">Activation applies to future or changed findings. Historical findings require an explicit completed preview followed by reroute.</p>
    </div></Card>
    <SnapshotManager engagement={engagement} snapshots={snapshots.data?.items ?? []} reload={snapshots.refetch} disabled={busy} />
    <Card title="Reusable evidence mappings"><div className="grid gap-5 xl:grid-cols-2">
      <section className="space-y-3"><h3 className="font-semibold">CODEOWNERS token</h3><Field label="Repository"><Input value={mappingRepository} onChange={(event) => setMappingRepository(event.target.value)} maxLength={2048} /></Field><Field label="Exact owner token"><Input value={mappingOwner} onChange={(event) => setMappingOwner(event.target.value)} placeholder="@company/payments" /></Field><Field label="Synapse team"><TeamChoice teams={teams.teams} value={mappingTeam} onChange={setMappingTeam} /></Field><Button disabled={busy || !engagement || !mappingRepository || !mappingOwner || !mappingTeam} onClick={() => void saveMapping()}>Save owner mapping</Button><MappingList items={ownerMappings.data?.items ?? []} teams={teams.teams} remove={removeMapping} disabled={busy} /></section>
      <section className="space-y-3"><h3 className="font-semibold">Business asset fallback</h3><Field label="Business asset"><Choice value={asset} onChange={(event) => setAsset(event.target.value)}><option value="">Choose asset</option>{assets.data?.items.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Choice></Field><Field label="Synapse team"><TeamChoice teams={teams.teams} value={assetTeam} onChange={setAssetTeam} /></Field><Button disabled={busy || !asset || !assetTeam} onClick={() => void saveAssetMapping()}>Save asset mapping</Button><p className="text-xs text-secondary">Free-text asset owners are never treated as user or team IDs.</p><AssetMappingList items={assetMappings.data?.items ?? []} assets={assets.data?.items ?? []} teams={teams.teams} remove={removeAssetMapping} disabled={busy} /></section>
    </div></Card>
    {run && <RunViewer key={run.id} run={run} teams={teams.teams} capability={capability} onRun={setRun} />}
  </div>
}

function MappingList({ items, teams, remove, disabled }: { items: OwnershipMapping[]; teams: ReturnType<typeof useOwnershipTeams>['teams']; remove: (item: OwnershipMapping) => Promise<void>; disabled: boolean }) {
  if (!items.length) return <p className="text-xs text-secondary">No mappings for the policy repository.</p>
  return <ul className="divide-y divide-secondary">{items.map((item) => <li key={`${item.mapping.repository}:${item.mapping.owner}`} className="flex items-center justify-between gap-3 py-2 text-sm"><span><code>{item.mapping.owner}</code> → {teams.find((team) => team.id === item.mapping.team_id)?.name ?? item.mapping.team_id}</span><Button variant="secondary" disabled={disabled} onClick={() => void remove(item)}>Remove</Button></li>)}</ul>
}

function AssetMappingList({ items, assets, teams, remove, disabled }: { items: OwnershipAssetMapping[]; assets: Array<{ id: string; name: string }>; teams: ReturnType<typeof useOwnershipTeams>['teams']; remove: (item: OwnershipAssetMapping) => Promise<void>; disabled: boolean }) {
  if (!items.length) return <p className="text-xs text-secondary">No explicit asset mappings.</p>
  return <ul className="divide-y divide-secondary">{items.map((item) => <li key={item.mapping.asset_id} className="flex items-center justify-between gap-3 py-2 text-sm"><span>{assets.find((asset) => asset.id === item.mapping.asset_id)?.name ?? item.mapping.asset_id} → {teams.find((team) => team.id === item.mapping.team_id)?.name ?? item.mapping.team_id}</span><Button variant="secondary" disabled={disabled} onClick={() => void remove(item)}>Remove</Button></li>)}</ul>
}

export function SnapshotManager({ engagement, snapshots, reload, disabled }: { engagement: string; snapshots: OwnershipSnapshot[]; reload: () => void; disabled: boolean }) {
  const [repository, setRepository] = useState('')
  const [revision, setRevision] = useState('')
  const [path, setPath] = useState('.github/CODEOWNERS')
  const [content, setContent] = useState('')
  const [accept, setAccept] = useState(false)
  const [reviewID, setReviewID] = useState('')
  const [reviewAccept, setReviewAccept] = useState(false)
  const [error, setError] = useState('')
  const review = useFetch(() => reviewID ? api.ownershipSnapshot(reviewID) : Promise.resolve(null), { enabled: !!reviewID, deps: [reviewID] })
  async function importFile() { try { setError(''); await api.importOwnershipSnapshot({ engagement_id: engagement, repository, source_revision: revision, file_path: path, content, approve: true, accept_diagnostics: accept }); setContent(''); reload() } catch (error) { setError(ownershipError(error)) } }
  async function approve() { const item = review.data; if (!item) return; try { setError(''); await api.approveOwnershipSnapshot(item.id, item.content_hash, reviewAccept); setReviewID(''); reload() } catch (error) { setError(ownershipError(error)) } }
  return <Card title="CODEOWNERS snapshots"><div className="space-y-4">{error && <ErrorState message={error} />}
    <p className="text-sm text-secondary">Scan-captured head/base files remain untrusted until an administrator verifies their repository and immutable revision. Approval creates a new immutable copy.</p>
    <div className="grid gap-3 md:grid-cols-3"><Field label="Repository"><Input value={repository} onChange={(event) => setRepository(event.target.value)} /></Field><Field label="Pinned revision"><Input value={revision} onChange={(event) => setRevision(event.target.value)} placeholder="git:40-hex commit or sha256:64-hex" /></Field><Field label="CODEOWNERS path"><Choice value={path} onChange={(event) => setPath(event.target.value)}><option>.github/CODEOWNERS</option><option>CODEOWNERS</option><option>docs/CODEOWNERS</option></Choice></Field></div>
    <Field label="CODEOWNERS content"><textarea className={jsonClass} value={content} onChange={(event) => setContent(event.target.value)} spellCheck={false} maxLength={3_000_000} /></Field>
    <label className="flex gap-2 text-sm"><input type="checkbox" checked={accept} onChange={(event) => setAccept(event.target.checked)} />Accept parser diagnostics after reviewing the content</label><Button disabled={disabled || !engagement || !repository || !revision || !content} onClick={() => void importFile()}>Import and approve snapshot</Button>
    <ul className="divide-y divide-secondary">{snapshots.map((item) => <li key={item.id} className="flex flex-wrap items-center justify-between gap-3 py-3"><div><p className="font-mono text-xs">{item.file_path} · {item.source_revision}</p><div className="mt-1 flex gap-2"><Pill>{item.trust}</Pill></div></div>{item.trust === 'untrusted' && <Button variant="secondary" onClick={() => { setReviewID(item.id); setReviewAccept(false) }}>Review exact content</Button>}</li>)}</ul>
    {review.loading && <Spinner label="Loading exact snapshot…" />}{review.error && <ErrorState message={review.error} />}{review.data && <section className="space-y-3 rounded-lg border border-secondary bg-secondary/30 p-4"><div><h3 className="font-semibold">Approve immutable snapshot</h3><p className="break-all font-mono text-xs text-secondary">SHA-256 {review.data.content_hash}</p></div><pre className={`${jsonClass} max-h-80 overflow-auto whitespace-pre-wrap`}>{review.data.content}</pre>{review.data.diagnostics?.length ? <div className="space-y-1 text-sm"><p className="font-semibold">Parser diagnostics</p>{review.data.diagnostics.map((diagnostic, index) => <p key={`${diagnostic.line}:${diagnostic.code}:${index}`}>Line {diagnostic.line}: {diagnostic.code}{diagnostic.message ? ` — ${diagnostic.message}` : ''}</p>)}</div> : <p className="text-sm text-success-primary">No parser diagnostics.</p>}<label className="flex gap-2 text-sm"><input type="checkbox" checked={reviewAccept} onChange={(event) => setReviewAccept(event.target.checked)} />I verified the repository, pinned revision, exact content, and any diagnostics</label><div className="flex gap-2"><Button onClick={() => void approve()} disabled={!reviewAccept}>Approve exact hash</Button><Button variant="secondary" onClick={() => setReviewID('')}>Cancel review</Button></div></section>}
  </div></Card>
}

function RunViewer({ run: initial, teams, capability, onRun }: { run: OwnershipRun; teams: ReturnType<typeof useOwnershipTeams>['teams']; capability: OwnershipCapability; onRun: (run: OwnershipRun) => void }) {
  const [run, setRun] = useState(initial)
  const [cursor, setCursor] = useState<string>()
  const [error, setError] = useState('')
  const status = useFetch((signal) => api.ownershipRun(run.id, signal), { deps: [run.id, run.revision] })
  const items = useFetch((signal) => api.ownershipRunItems(run.id, cursor, signal), { deps: [run.id, cursor, status.data?.processed] })
  useEffect(() => { if (status.data) { setRun(status.data); onRun(status.data) } }, [status.data, onRun])
  async function control(action: 'cancel' | 'retry') { try { setError(''); await api.controlOwnershipRun(run.id, run.revision, action); status.refetch() } catch (error) { setError(ownershipError(error)) } }
  return <Card title={`${run.mode === 'preview' ? 'Preview' : 'Reroute'} ${run.processed}/${run.total}`} actions={<Pill>{run.state}</Pill>}><div className="space-y-4">{error && <ErrorState message={error} />}
    <div className="flex flex-wrap gap-2"><Button variant="secondary" onClick={status.refetch} disabled={status.loading}>Refresh run</Button>{['queued', 'running'].includes(run.state) && <Button variant="secondary" onClick={() => void control('cancel')}>Cancel</Button>}{run.state === 'failed' && <Button onClick={() => void control('retry')} disabled={!capability.routing_available}>Replay dead-lettered run</Button>}</div>
    {items.loading && <Spinner label="Loading results…" />}{items.error && <ErrorState message={items.error} />}
    <div className="space-y-3">{items.data?.items.map((item: OwnershipRunItem) => <article key={item.finding_id} className="rounded-lg border border-secondary p-3"><div className="mb-2 flex justify-between gap-3"><code>{item.finding_id}</code><Pill>{item.outcome}</Pill></div><ResolutionEvidence result={item.result} teams={teams} /></article>)}</div>
    <div className="flex gap-2">{cursor && <Button variant="secondary" onClick={() => setCursor(undefined)}>First results</Button>}{items.data?.next && <Button variant="secondary" onClick={() => setCursor(items.data?.next)} disabled={items.loading}>More results</Button>}</div>
  </div></Card>
}
