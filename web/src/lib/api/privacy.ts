import { ApiError, req } from './client'

/**
 * Tenant source-privacy policy governance (#413 privacy plane). A policy decides how the fleet agent
 * redacts each telemetry field category at the source before it ever leaves the host. An admitted policy
 * is identified by its content digest; activating a digest makes it the one agents fetch. The hash salt
 * is never returned on this human plane (only the agent plane receives it), so it is not modelled here.
 */
export type PrivacyDisposition = 'allow' | 'redact' | 'hash' | 'drop'

// The field categories a policy reasons about, in a stable display order (domain: internal/domain/privacy).
export const PRIVACY_CATEGORIES: { id: string; label: string }[] = [
  { id: 'process.comm', label: 'Process name' },
  { id: 'process.arg', label: 'Process arguments' },
  { id: 'process.path', label: 'Process path' },
  { id: 'process.env', label: 'Process environment' },
  { id: 'file.path', label: 'File path' },
  { id: 'file.comm', label: 'File process name' },
  { id: 'network.comm', label: 'Network process name' },
  { id: 'privilege.comm', label: 'Privilege process name' },
]

export interface PrivacyPolicy {
  dispositions: Record<string, PrivacyDisposition>
  redactSecrets: boolean
  maxArgLen: number
  maxArgCount: number
  maxPathLen: number
  version: string
}

export interface PrivacyAssignment {
  tenantId: string
  policy: PrivacyPolicy
  digest: string
  createdBy: string
  createdAt: string
}

function mapPolicy(p: any): PrivacyPolicy {
  const dispositions: Record<string, PrivacyDisposition> = {}
  const raw = p?.dispositions ?? {}
  for (const k of Object.keys(raw)) dispositions[k] = raw[k] as PrivacyDisposition
  return {
    dispositions,
    redactSecrets: p?.redact_secrets === true,
    maxArgLen: p?.max_arg_len ?? 0,
    maxArgCount: p?.max_arg_count ?? 0,
    maxPathLen: p?.max_path_len ?? 0,
    version: p?.version ?? '',
  }
}

function mapAssignment(a: any): PrivacyAssignment {
  return {
    tenantId: a?.tenant_id ?? '',
    policy: mapPolicy(a?.policy),
    digest: a?.digest ?? '',
    createdBy: a?.created_by ?? '',
    createdAt: a?.created_at ?? '',
  }
}

function policyWire(p: PrivacyPolicy) {
  return {
    dispositions: p.dispositions,
    redact_secrets: p.redactSecrets,
    max_arg_len: p.maxArgLen,
    max_arg_count: p.maxArgCount,
    max_path_len: p.maxPathLen,
    version: p.version,
  }
}

export const privacyApi = {
  // The currently active policy, or null when none has been activated yet.
  activePrivacyPolicy: async (): Promise<PrivacyAssignment | null> => {
    try {
      const r = await req('/fleet/privacy-policies/active')
      return r?.assignment ? mapAssignment(r.assignment) : null
    } catch (e) {
      if (e instanceof ApiError && (e.status === 404 || e.status === 400)) return null
      throw e
    }
  },
  privacyPolicyHistory: async (): Promise<PrivacyAssignment[]> => {
    const r = await req('/fleet/privacy-policies')
    return Array.isArray(r?.assignments) ? r.assignments.map(mapAssignment) : []
  },
  admitPrivacyPolicy: async (policy: PrivacyPolicy): Promise<{ assignment: PrivacyAssignment; created: boolean }> => {
    const r = await req('/fleet/privacy-policies', { method: 'POST', body: JSON.stringify({ policy: policyWire(policy) }) })
    return { assignment: mapAssignment(r?.assignment), created: r?.created === true }
  },
  activatePrivacyPolicy: async (digest: string, operationId: string): Promise<PrivacyAssignment> => {
    const r = await req('/fleet/privacy-policies/activate', {
      method: 'POST',
      body: JSON.stringify({ digest, operation_id: operationId }),
    })
    return mapAssignment(r?.assignment)
  },
}
