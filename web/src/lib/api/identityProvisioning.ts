import { entraMode, identityAuthRequest, type ConnectionDraft, type EnterpriseConnection } from './identity'

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

export interface ProvisioningConnection extends EnterpriseConnection {
  clientId: string
  auth0OrganizationId: string
}

export interface InitialOrganizationInvitation {
  id: string
  recipient: string
  role: string
  state: string
  version: number
  expiresAt: string
}

export interface InitialOrganizationProvisioning {
  id: string
  tenantId: string
  recipient: string
  state: string
  version: number
  connection: ProvisioningConnection | null
  invitation: InitialOrganizationInvitation | null
}

export interface ProvisioningDraft extends ConnectionDraft {
  capability: string
  auth0OrganizationId: string
  version: number
}

export interface BeginProvisioningResult {
  provisioning: InitialOrganizationProvisioning
  capability: string
}

export interface InvitationResult {
  provisioning: InitialOrganizationProvisioning
  code: string
}

function connectionFromWire(value: unknown): ProvisioningConnection {
  const connection = asRecord(value)
  return {
    id: stringValue(connection.id),
    displayName: stringValue(connection.display_name) || stringValue(connection.name) || stringValue(connection.id),
    issuer: stringValue(connection.issuer),
    clientId: stringValue(connection.client_id),
    enabled: connection.enabled === true,
    revision: numberValue(connection.revision),
    draftRevision: numberValue(connection.draft_revision),
    version: numberValue(connection.version),
    testPassed: connection.test_passed === true,
    auth0OrganizationId: stringValue(connection.auth0_organization_id),
    ...(typeof connection.entra_discovery_mode === 'string' ? { entraDiscoveryMode: entraMode(connection.entra_discovery_mode) } : {}),
    ...(typeof connection.draft_entra_discovery_mode === 'string' ? { draftEntraDiscoveryMode: entraMode(connection.draft_entra_discovery_mode) } : {}),
  }
}

function invitationFromWire(value: unknown): InitialOrganizationInvitation | null {
  if (value === null || value === undefined) return null
  const invitation = asRecord(value)
  return {
    id: stringValue(invitation.id),
    recipient: stringValue(invitation.recipient),
    role: stringValue(invitation.role),
    state: stringValue(invitation.state),
    version: numberValue(invitation.version),
    expiresAt: stringValue(invitation.expires_at),
  }
}

export function initialOrganizationProvisioningFromWire(value: unknown): InitialOrganizationProvisioning {
  const provisioning = asRecord(value)
  return {
    id: stringValue(provisioning.id),
    tenantId: stringValue(provisioning.tenant_id),
    recipient: stringValue(provisioning.recipient),
    state: stringValue(provisioning.state),
    version: numberValue(provisioning.version),
    connection: provisioning.connection === null || provisioning.connection === undefined ? null : connectionFromWire(provisioning.connection),
    invitation: invitationFromWire(provisioning.invitation),
  }
}

async function post(path: string, body: RecordValue): Promise<RecordValue> {
  return asRecord(await identityAuthRequest(`/api/v1${path}`, { method: 'POST', body: JSON.stringify(body) }))
}

function providerDestination(value: unknown): string {
  const authorizationURL = stringValue(asRecord(value).authorization_url)
  if (!authorizationURL) throw new Error('The server did not return an authorization destination.')
  let destination: URL
  try {
    destination = new URL(authorizationURL)
  } catch {
    throw new Error('The server returned an unsafe authorization destination.')
  }
  if (destination.protocol !== 'https:' || destination.username !== '' || destination.password !== '') {
    throw new Error('The server returned an unsafe authorization destination.')
  }
  return authorizationURL
}

function provisioningFromResult(value: RecordValue): InitialOrganizationProvisioning {
  return initialOrganizationProvisioningFromWire(value.provisioning ?? value)
}

export const identityProvisioningApi = {
  async begin(tenantId: string, recipient: string): Promise<BeginProvisioningResult> {
    const response = await post('/identity/provisioning/begin', { tenant_id: tenantId, recipient })
    const provisioning = provisioningFromResult(response)
    const capability = stringValue(response.capability)
    if (!capability && provisioning.state !== 'closed') throw new Error('The server did not return a provisioning capability.')
    return { provisioning, capability }
  },

  async status(capability: string): Promise<InitialOrganizationProvisioning> {
    return provisioningFromResult(await post('/identity/provisioning/status', { capability }))
  },

  async draft(input: ProvisioningDraft): Promise<InitialOrganizationProvisioning> {
    return provisioningFromResult(await post('/identity/provisioning/draft', {
      capability: input.capability,
      display_name: input.displayName,
      issuer: input.issuer,
      client_id: input.clientId,
      client_secret: input.clientSecret,
      auth0_organization_id: input.auth0OrganizationId,
      ...(input.entraDiscoveryMode ? { entra_discovery_mode: input.entraDiscoveryMode } : {}),
      version: input.version,
    }))
  },

  async test(capability: string): Promise<{ authorizationURL: string }> {
    const response = await post('/identity/provisioning/test', { capability })
    return { authorizationURL: providerDestination(response) }
  },

  async activate(capability: string, revision: number, version: number): Promise<InitialOrganizationProvisioning> {
    return provisioningFromResult(await post('/identity/provisioning/activate', { capability, revision, version }))
  },

  async invitation(capability: string): Promise<InvitationResult> {
    const response = await post('/identity/provisioning/invitation', { capability })
    const code = stringValue(response.code)
    if (!code) throw new Error('The server did not return the administrator invitation code.')
    return { provisioning: provisioningFromResult(response), code }
  },
}
