import { req, snapshotAuth } from './client'
import { errorFromResponse } from './errors'

export type EnterprisePurpose = 'login' | 'link' | 'test' | 'step_up'
export type SSORequirement = 'optional' | 'required'

export interface EnterpriseConnection {
  id: string
  displayName: string
  issuer: string
  enabled: boolean
  revision: number
  draftRevision: number
  version: number
  testPassed: boolean
}

export interface EnterpriseContext {
  enabled: boolean
  tenantId: string
  requirement: SSORequirement
  connections: EnterpriseConnection[]
  bootstrapEligible: boolean
}

export interface IdentityPolicy {
  requirement: SSORequirement
  version: number
  rehearsedAt: string | null
  alertConfigured: boolean
  graceCutoff: string | null
}

export interface ConnectionDraft {
  displayName: string
  issuer: string
  clientId: string
  clientSecret: string
}

export interface RecoveryCodeRequest {
  membershipId: string
  personId: string
}

export interface RecoveryAlert {
  id: string
  membershipId: string
  sessionId: string
  state: string
  attempts: number
  maxAttempts: number
  nextAttemptAt: string
  createdAt: string
}

type RecordValue = Record<string, unknown>

function asRecord(value: unknown): RecordValue {
  return value !== null && typeof value === 'object' ? value as RecordValue : {}
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function numberValue(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

function requirement(value: unknown): SSORequirement {
  return value === 'required' ? 'required' : 'optional'
}

function nullableString(value: unknown): string | null {
  return typeof value === 'string' && value !== '' ? value : null
}

function connectionFromWire(value: unknown): EnterpriseConnection {
  const connection = asRecord(value)
  return {
    id: stringValue(connection.id),
    displayName: stringValue(connection.display_name) || stringValue(connection.name) || stringValue(connection.id),
    issuer: stringValue(connection.issuer),
    enabled: connection.enabled === true,
    revision: numberValue(connection.revision),
    draftRevision: numberValue(connection.draft_revision),
    version: numberValue(connection.version),
    testPassed: connection.test_passed === true,
  }
}

function policyFromWire(value: unknown): IdentityPolicy {
  const policy = asRecord(value)
  return {
    requirement: requirement(policy.requirement),
    version: numberValue(policy.version),
    rehearsedAt: nullableString(policy.rehearsed_at),
    alertConfigured: policy.alert_configured === true,
    graceCutoff: nullableString(policy.grace_cutoff),
  }
}

function alertFromWire(value: unknown): RecoveryAlert {
  const alert = asRecord(value)
  return {
    id: stringValue(alert.id) || stringValue(alert.ID),
    membershipId: stringValue(alert.membership_id) || stringValue(alert.MembershipID),
    sessionId: stringValue(alert.session_id) || stringValue(alert.SessionID),
    state: stringValue(alert.state) || stringValue(alert.State),
    attempts: numberValue(alert.attempts) || numberValue(alert.Attempts),
    maxAttempts: numberValue(alert.max_attempts) || numberValue(alert.MaxAttempts),
    nextAttemptAt: stringValue(alert.next_attempt_at) || stringValue(alert.NextAttemptAt),
    createdAt: stringValue(alert.created_at) || stringValue(alert.CreatedAt),
  }
}

function withProof(proof: string | undefined): RecordValue {
  return proof ? { bootstrap_eligibility: proof } : {}
}

function request(path: string, init?: RequestInit): Promise<unknown> {
  return req(path, init) as Promise<unknown>
}

async function authRequest(path: string, init?: RequestInit): Promise<unknown> {
  const auth = snapshotAuth()
  let response: Response
  try {
    response = await fetch(path, auth.requestInit(init))
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new Error('Cannot reach the API. Is the server running on :8080?')
  }
  if (!response.ok) {
    const error = await errorFromResponse(response)
    auth.notifyUnauthorized(error)
    throw error
  }
  return response.status === 204 ? null : response.json()
}

export const identityApi = {
  async context(signal?: AbortSignal): Promise<EnterpriseContext> {
    const response = asRecord(await authRequest('/api/auth/enterprise/context', { signal }))
    const connections = Array.isArray(response.connections) ? response.connections.map(connectionFromWire) : []
    return {
      enabled: response.enabled === true,
      tenantId: stringValue(response.tenant_id),
      requirement: requirement(response.requirement),
      connections,
      bootstrapEligible: response.bootstrap_eligible === true,
    }
  },

  begin(connectionId: string, purpose: EnterprisePurpose, bootstrapEligibility?: string): Promise<unknown> {
    return authRequest('/api/auth/enterprise/begin', {
      method: 'POST',
      body: JSON.stringify({ connection_id: connectionId, purpose, ...withProof(bootstrapEligibility) }),
    })
  },

  async connections(signal?: AbortSignal): Promise<EnterpriseConnection[]> {
    const response = asRecord(await request('/identity/connections', { signal }))
    return Array.isArray(response.connections) ? response.connections.map(connectionFromWire) : []
  },

  async bootstrap(): Promise<string> {
    const response = asRecord(await request('/identity/bootstrap', { method: 'POST' }))
    const proof = stringValue(response.bootstrap_eligibility)
    if (!proof) throw new Error('The server did not return an administrator verification proof.')
    return proof
  },

  draftConnection(draft: ConnectionDraft, bootstrapEligibility?: string): Promise<unknown> {
    return request('/identity/connections/draft', {
      method: 'POST',
      body: JSON.stringify({
        display_name: draft.displayName,
        issuer: draft.issuer,
        client_id: draft.clientId,
        client_secret: draft.clientSecret,
        ...withProof(bootstrapEligibility),
      }),
    })
  },

  async testConnection(id: string, bootstrapEligibility?: string): Promise<{ authorizationURL: string }> {
    const response = asRecord(await request('/identity/connections/test', {
      method: 'POST',
      body: JSON.stringify({ id, ...withProof(bootstrapEligibility) }),
    }))
    const authorizationURL = stringValue(response.authorization_url)
    if (!authorizationURL) throw new Error('The server did not return an authorization destination.')
    const destination = new URL(authorizationURL)
    if (destination.protocol !== 'https:') throw new Error('The server returned an unsafe authorization destination.')
    return { authorizationURL }
  },

  activateConnection(id: string, revision: number, version: number, bootstrapEligibility?: string): Promise<unknown> {
    return request('/identity/connections/activate', {
      method: 'POST',
      body: JSON.stringify({ id, revision, version, ...withProof(bootstrapEligibility) }),
    })
  },

  disableConnection(id: string, version: number, bootstrapEligibility?: string): Promise<unknown> {
    return request('/identity/connections/disable', {
      method: 'POST',
      body: JSON.stringify({ id, version, ...withProof(bootstrapEligibility) }),
    })
  },

  async policy(signal?: AbortSignal): Promise<IdentityPolicy> {
    return policyFromWire(await request('/identity/policy', { signal }))
  },

  savePolicy(policy: Pick<IdentityPolicy, 'requirement' | 'version'>, bootstrapEligibility?: string): Promise<unknown> {
    return request('/identity/policy', {
      method: 'PUT',
      body: JSON.stringify({ requirement: policy.requirement, version: policy.version, ...withProof(bootstrapEligibility) }),
    })
  },

  rehearse(bootstrapEligibility?: string): Promise<unknown> {
    return request('/identity/policy/rehearse', { method: 'POST', body: JSON.stringify(withProof(bootstrapEligibility)) })
  },

  testAlert(bootstrapEligibility?: string): Promise<unknown> {
    return request('/identity/policy/test-alert', { method: 'POST', body: JSON.stringify(withProof(bootstrapEligibility)) })
  },

  async createRecoveryCode(input: RecoveryCodeRequest, bootstrapEligibility?: string): Promise<string> {
    const response = asRecord(await request('/identity/policy/recovery-code', {
      method: 'POST',
      body: JSON.stringify({ membership_id: input.membershipId, person_id: input.personId, ...withProof(bootstrapEligibility) }),
    }))
    const code = stringValue(response.recovery_code)
    if (!code) throw new Error('The server did not return a recovery code.')
    return code
  },

  async alerts(signal?: AbortSignal): Promise<RecoveryAlert[]> {
    const response = asRecord(await request('/identity/recovery/alerts', { signal }))
    return Array.isArray(response.alerts) ? response.alerts.map(alertFromWire) : []
  },
}
