import { req } from './client'

export interface OwnershipPage<T> { items: T[]; next?: string }
export interface OwnershipCapability { enabled: boolean; mode: 'off' | 'observe' | 'enforce'; routing_available: boolean; reason?: string }
export interface OwnershipTeam { id: string; slug: string; name: string; archived: boolean; revision: number; created_at: string; updated_at: string }
export interface OwnershipMember { team_id: string; user_id: string; created_at: string }
export interface OwnerMapping { repository: string; owner: string; team_id: string; suggested_user_id?: string }
export interface OwnershipMapping { mapping: OwnerMapping; revision: number }
export interface OwnerAsset { asset_id: string; team_id: string }
export interface OwnershipAssetMapping { mapping: OwnerAsset; revision: number }
export interface OwnershipDiagnostic { line: number; code: string; message?: string }
export interface OwnershipSnapshot { id: string; engagement_id: string; repository: string; source_revision: string; file_path: string; content_hash: string; content?: string; parser_version: string; trust: 'untrusted' | 'base_ref' | 'admin_import'; approved_by?: string; accept_diagnostics: boolean; created_at: string; diagnostics?: OwnershipDiagnostic[] }
export interface OwnershipSnapshotInput { engagement_id: string; repository: string; source_revision: string; file_path: string; content: string; approve: boolean; accept_diagnostics: boolean }
export interface OwnershipRule { id: string; priority: number; when: { engagement_ids?: string[]; repositories?: string[]; project_ids?: string[]; paths?: string[]; kinds?: string[]; severities?: string[]; asset_ids?: string[] }; team_id?: string; exclude?: boolean }
export interface OwnershipPolicy { id: string; engagement_id: string; repository: string; revision: number; active_version: number; latest_version: number }
export interface OwnershipPolicyInput { engagement_id: string; repository: string; version: number; snapshot_id: string; rules: OwnershipRule[]; mappings: OwnerMapping[]; assets: OwnerAsset[] }
export interface OwnershipPolicyVersion extends OwnershipPolicyInput { policy_id: string; created_at: string; created_by: string }
export interface OwnershipVersionView { policy: OwnershipPolicyVersion; content_hash: string }
export interface OwnershipAssignment { team_id?: string; assignee_id?: string; legacy_assignee?: string; mode: 'auto' | 'manual'; revision: number; manual_generation: number }
export type OwnershipResolution = 'resolved' | 'unresolved' | 'ambiguous' | 'excluded' | 'unsupported'
export interface OwnershipEvidence { path: string; line?: number; pattern?: string; owners?: string[]; reason: string }
export interface OwnershipResult { resolution: OwnershipResolution; reason: string; team_id?: string; candidates: string[]; evidence: OwnershipEvidence[]; rule_id?: string; policy_hash: string; snapshot_hash?: string; input_hash: string }
export interface OwnershipCurrent { assignment: OwnershipAssignment; finding_version: number; finding_assignee: string; resolution: OwnershipResolution; reason: string; updated_at: string }
export interface OwnershipDecision { id: string; engagement_id: string; finding_id: string; actor: string; before: OwnershipAssignment; after: OwnershipAssignment; result: OwnershipResult; created_at: string; transition_key: string }
export interface OwnershipFinding { id: string; engagement_id: string; title: string; severity: string; status: string; kind: string; version: number; assignment: OwnershipAssignment; resolution: OwnershipResolution; reason: string; sla_status?: string; remediate_by?: string }
export interface OwnershipFilter { engagement_id?: string; team_id?: string; assignee_id?: string; my_teams?: boolean; mine?: boolean; unresolved?: boolean; severity?: string; status?: string; kind?: string; sla_status?: string; due_before?: string }
export type OwnershipAction = 'assign' | 'transfer' | 'claim' | 'clear' | 'release'
export interface OwnershipAssignmentInput { action: OwnershipAction; team_id?: string; assignee_id?: string; clear_assignee?: boolean; finding_version: number; ownership_revision: number; manual_generation: number }
export interface OwnershipBulkItem extends OwnershipAssignmentInput { engagement_id: string; finding_id: string }
export interface OwnershipBulkResult { engagement_id: string; finding_id: string; status: number; error?: string; decision?: OwnershipDecision }
export interface OwnershipRunInput { version: number; policy_revision: number; policy_hash: string; preview_id?: string; filter?: OwnershipFilter }
export interface OwnershipRun { id: string; engagement_id: string; policy_id: string; policy_version: number; policy_revision: number; policy_hash: string; mode: 'preview' | 'reroute'; state: 'queued' | 'running' | 'completed' | 'cancelled' | 'failed'; revision: number; cutoff: string; total: number; processed: number; filter: OwnershipFilter; created_at: string }
export interface OwnershipRunItem { run_id: string; engagement_id: string; finding_id: string; finding_version: number; ownership_revision: number; manual_generation: number; result: OwnershipResult; outcome: 'evaluated' | 'manual_protected' | 'conflict' }

type Query = Record<string, string | number | boolean | undefined>
function query(values: Query) {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(values)) if (value !== undefined && value !== '') params.set(key, String(value))
  return params.toString() ? `?${params}` : ''
}
const id = encodeURIComponent
const mutate = (method: string, body: unknown, key?: string): RequestInit => ({ method, body: JSON.stringify(body), ...(key ? { headers: { 'Idempotency-Key': key } } : {}) })
const findingPath = (eng: string, fid: string) => `/engagements/${id(eng)}/findings/${id(fid)}/ownership`

export const ownershipApi = {
  ownershipCapability: (signal?: AbortSignal): Promise<OwnershipCapability> => req('/ownership/capabilities', { signal }),
  ownershipTeams: (cursor?: string, signal?: AbortSignal): Promise<OwnershipPage<OwnershipTeam>> => req(`/ownership/teams${query({ cursor, limit: 200 })}`, { signal }),
  ownershipTeam: (team: string): Promise<OwnershipTeam> => req(`/ownership/teams/${id(team)}`),
  saveOwnershipTeam: (input: Pick<OwnershipTeam, 'slug' | 'name' | 'archived' | 'revision'>, team?: string): Promise<OwnershipTeam> => req(`/ownership/teams${team ? `/${id(team)}` : ''}`, mutate(team ? 'PATCH' : 'POST', input)),
  ownershipMembers: (team: string, cursor?: string): Promise<OwnershipPage<OwnershipMember>> => req(`/ownership/teams/${id(team)}/members${query({ cursor, limit: 200 })}`),
  setOwnershipMember: (team: string, user: string, revision: number, remove = false): Promise<void> => req(`/ownership/teams/${id(team)}/members/${id(user)}`, mutate(remove ? 'DELETE' : 'PUT', { revision })),
  ownershipMappings: (engagement_id: string, repository: string, cursor?: string): Promise<OwnershipPage<OwnershipMapping>> => req(`/ownership/mappings${query({ engagement_id, repository, cursor, limit: 200 })}`),
  saveOwnershipMapping: (engagement_id: string, item: OwnershipMapping, remove = false): Promise<void> => req('/ownership/mappings', mutate(remove ? 'DELETE' : 'PUT', { engagement_id, ...item })),
  ownershipAssetMappings: (cursor?: string): Promise<OwnershipPage<OwnershipAssetMapping>> => req(`/ownership/asset-mappings${query({ cursor, limit: 200 })}`),
  saveOwnershipAssetMapping: (item: OwnershipAssetMapping, remove = false): Promise<void> => req('/ownership/asset-mappings', mutate(remove ? 'DELETE' : 'PUT', item)),
  ownershipSnapshots: (engagement_id: string, cursor?: string): Promise<OwnershipPage<OwnershipSnapshot>> => req(`/ownership/snapshots${query({ engagement_id, cursor, limit: 100 })}`),
  ownershipSnapshot: (snapshot: string): Promise<OwnershipSnapshot> => req(`/ownership/snapshots/${id(snapshot)}`),
  importOwnershipSnapshot: (input: OwnershipSnapshotInput): Promise<OwnershipSnapshot> => req('/ownership/snapshots', mutate('POST', input)),
  approveOwnershipSnapshot: (snapshot: string, content_hash: string, accept_diagnostics: boolean): Promise<OwnershipSnapshot> => req(`/ownership/snapshots/${id(snapshot)}/approve`, mutate('POST', { content_hash, accept_diagnostics })),
  ownershipPolicies: (engagement_id: string, cursor?: string): Promise<OwnershipPage<OwnershipPolicy>> => req(`/ownership/policies${query({ engagement_id, cursor, limit: 100 })}`),
  ownershipPolicy: (policy: string): Promise<OwnershipPolicy> => req(`/ownership/policies/${id(policy)}`),
  ownershipVersion: (policy: string, version: number): Promise<OwnershipVersionView> => req(`/ownership/policies/${id(policy)}/versions/${version}`),
  saveOwnershipPolicy: (input: OwnershipPolicyInput, policy?: string): Promise<OwnershipVersionView> => req(`/ownership/policies${policy ? `/${id(policy)}/versions` : ''}`, mutate('POST', input)),
  activateOwnershipPolicy: (policy: string, version: number, revision: number, content_hash: string): Promise<void> => req(`/ownership/policies/${id(policy)}/activate`, mutate('POST', { version, revision, content_hash })),
  startOwnershipRun: (policy: string, mode: 'preview' | 'reroute', input: OwnershipRunInput, key: string): Promise<OwnershipRun> => req(`/ownership/policies/${id(policy)}/${mode}`, mutate('POST', input, key)),
  ownershipRun: (run: string, signal?: AbortSignal): Promise<OwnershipRun> => req(`/ownership/runs/${id(run)}`, { signal }),
  ownershipRunItems: (run: string, cursor?: string, signal?: AbortSignal): Promise<OwnershipPage<OwnershipRunItem>> => req(`/ownership/runs/${id(run)}/items${query({ cursor, limit: 100 })}`, { signal }),
  controlOwnershipRun: (run: string, revision: number, action: 'cancel' | 'retry'): Promise<void> => req(`/ownership/runs/${id(run)}/${action}`, mutate('POST', { revision })),
  ownershipInbox: (filter: OwnershipFilter, cursor?: string, signal?: AbortSignal): Promise<OwnershipPage<OwnershipFinding> & { total: number }> => req(`/ownership/findings${query({ ...filter, cursor, limit: 100 })}`, { signal }),
  findingOwnership: (eng: string, fid: string, signal?: AbortSignal): Promise<OwnershipCurrent> => req(findingPath(eng, fid), { signal }),
  findingOwnershipHistory: (eng: string, fid: string, cursor?: string): Promise<OwnershipPage<OwnershipDecision>> => req(`${findingPath(eng, fid)}/history${query({ cursor, limit: 50 })}`),
  assignOwnership: (eng: string, fid: string, input: OwnershipAssignmentInput, key: string): Promise<OwnershipDecision> => req(findingPath(eng, fid), mutate('POST', input, key)),
  bulkOwnership: async (items: OwnershipBulkItem[], key: string): Promise<OwnershipBulkResult[]> => (await req('/ownership/bulk', mutate('POST', { items }, key))).items,
}
