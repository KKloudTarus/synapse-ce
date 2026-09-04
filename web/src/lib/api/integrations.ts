import type {
  Integration,
  IntegrationBinding,
  IntegrationExternalRun,
  IntegrationInput,
  IntegrationOperation,
  IntegrationOperationType,
  IntegrationProviderDescriptor,
} from '../types'
import { req } from './client'

const id = encodeURIComponent

function mapDescriptor(value: any): IntegrationProviderDescriptor {
  const fields = (items: any[] = []) => items.map((field) => ({
    name: field.name ?? '',
    label: field.label ?? '',
    kind: field.kind ?? 'text',
    required: field.required ?? false,
    description: field.description ?? '',
  }))
  return {
    provider: value.provider ?? '',
    name: value.name ?? '',
    description: value.description ?? '',
    capabilities: value.capabilities ?? [],
    configFields: fields(value.config_fields),
    secretFields: fields(value.secret_fields),
  }
}

function mapIntegration(value: any): Integration {
  return {
    id: value.id ?? '',
    provider: value.provider ?? '',
    name: value.name ?? '',
    endpoint: value.endpoint ?? '',
    config: value.config ?? {},
    allowPrivateNetwork: value.allow_private_network ?? false,
    pollIntervalSeconds: value.poll_interval_seconds ?? 300,
    enabled: value.enabled ?? false,
    archived: value.archived ?? false,
    version: value.version ?? 1,
    connectionRevision: value.connection_revision ?? 1,
    credentialRevision: value.credential_revision ?? 0,
    credentialConfigured: value.credential_configured ?? false,
    createdAt: value.created_at ?? '',
    updatedAt: value.updated_at ?? '',
  }
}

function mapPipeline(value: any) {
  return {
    externalKey: value.external_key ?? '',
    name: value.name ?? '',
    fullName: value.full_name ?? '',
    kind: value.kind ?? '',
    url: value.url ?? '',
  }
}

function mapOperation(value: any): IntegrationOperation {
  return {
    id: value.id ?? '',
    integrationId: value.integration_id ?? '',
    type: value.type ?? 'test',
    state: value.state ?? 'queued',
    checkpoint: value.checkpoint ?? '',
    counts: {
      pipelines: value.counts?.pipelines ?? 0,
      runs: value.counts?.runs ?? 0,
      linked: value.counts?.linked ?? 0,
      unlinked: value.counts?.unlinked ?? 0,
      errors: value.counts?.errors ?? 0,
    },
    errors: value.errors ?? [],
    pipelines: (value.pipelines ?? []).map(mapPipeline),
    jobId: value.job_id ?? '',
    actor: value.actor ?? '',
    startedAt: value.started_at ?? null,
    finishedAt: value.finished_at ?? null,
    createdAt: value.created_at ?? '',
    updatedAt: value.updated_at ?? '',
  }
}

function mapBinding(value: any): IntegrationBinding {
  return {
    id: value.id ?? '',
    integrationId: value.integration_id ?? '',
    projectId: value.project_id ?? '',
    externalKey: value.external_key ?? '',
    externalName: value.external_name ?? '',
    version: value.version ?? 1,
    createdAt: value.created_at ?? '',
    updatedAt: value.updated_at ?? '',
  }
}

function mapRun(value: any): IntegrationExternalRun {
  return {
    id: value.id ?? '',
    integrationId: value.integration_id ?? '',
    bindingId: value.binding_id ?? '',
    providerKey: value.provider_key ?? '',
    pipelineKey: value.pipeline_key ?? '',
    number: value.number ?? '',
    url: value.url ?? '',
    lifecycle: value.lifecycle ?? 'queued',
    result: value.result ?? 'unknown',
    revision: value.revision ?? '',
    branch: value.branch ?? '',
    analysisId: value.analysis_id ?? '',
    correlation: value.correlation ?? 'missing',
    queuedAt: value.queued_at ?? null,
    startedAt: value.started_at ?? null,
    finishedAt: value.finished_at ?? null,
    providerUpdatedAt: value.provider_updated_at ?? '',
    createdAt: value.created_at ?? '',
    updatedAt: value.updated_at ?? '',
  }
}

function integrationBody(input: IntegrationInput) {
  return {
    provider: input.provider,
    name: input.name,
    endpoint: input.endpoint,
    config: input.config,
    allow_private_network: input.allowPrivateNetwork,
    poll_interval_seconds: input.pollIntervalSeconds,
  }
}

export const integrationsApi = {
  listIntegrationProviders: async (): Promise<IntegrationProviderDescriptor[]> =>
    ((await req('/integration-providers')) ?? []).map(mapDescriptor),

  listIntegrations: async (): Promise<Integration[]> =>
    ((await req('/integrations')) ?? []).map(mapIntegration),

  getIntegration: async (integrationId: string): Promise<Integration> =>
    mapIntegration(await req(`/integrations/${id(integrationId)}`)),

  createIntegration: async (input: IntegrationInput): Promise<Integration> =>
    mapIntegration(await req('/integrations', { method: 'POST', body: JSON.stringify(integrationBody(input)) })),

  updateIntegration: async (integration: Integration, input: IntegrationInput): Promise<Integration> =>
    mapIntegration(await req(`/integrations/${id(integration.id)}`, {
      method: 'PUT',
      body: JSON.stringify({ ...integrationBody(input), provider: undefined, version: integration.version }),
    })),

  setIntegrationEnabled: async (integration: Integration, enabled: boolean): Promise<Integration> =>
    mapIntegration(await req(`/integrations/${id(integration.id)}/${enabled ? 'enable' : 'disable'}`, {
      method: 'POST', body: JSON.stringify({ version: integration.version }),
    })),

  archiveIntegration: async (integration: Integration): Promise<void> => {
    await req(`/integrations/${id(integration.id)}/archive`, { method: 'POST', body: JSON.stringify({ version: integration.version }) })
  },

  setIntegrationCredential: async (integration: Integration, secrets: Record<string, string>): Promise<void> => {
    await req(`/integrations/${id(integration.id)}/credentials`, {
      method: 'PUT',
      body: JSON.stringify({ secrets, version: integration.version, connection_revision: integration.connectionRevision }),
    })
  },

  deleteIntegrationCredential: async (integration: Integration): Promise<void> => {
    await req(`/integrations/${id(integration.id)}/credentials`, {
      method: 'DELETE',
      body: JSON.stringify({ version: integration.version, connection_revision: integration.connectionRevision }),
    })
  },

  startIntegrationOperation: async (integrationId: string, type: IntegrationOperationType): Promise<IntegrationOperation> =>
    mapOperation(await req(`/integrations/${id(integrationId)}/operations`, { method: 'POST', body: JSON.stringify({ type }) })),

  listIntegrationOperations: async (integrationId: string): Promise<IntegrationOperation[]> =>
    ((await req(`/integrations/${id(integrationId)}/operations?limit=50`)) ?? []).map(mapOperation),

  getIntegrationOperation: async (operationId: string): Promise<IntegrationOperation> =>
    mapOperation(await req(`/integration-operations/${id(operationId)}`)),

  cancelIntegrationOperation: async (operationId: string): Promise<IntegrationOperation> =>
    mapOperation(await req(`/integration-operations/${id(operationId)}/cancel`, { method: 'POST', body: '{}' })),

  listIntegrationBindings: async (integrationId: string): Promise<IntegrationBinding[]> =>
    ((await req(`/integrations/${id(integrationId)}/bindings`)) ?? []).map(mapBinding),

  createIntegrationBinding: async (integrationId: string, projectId: string, externalKey: string, externalName: string): Promise<IntegrationBinding> =>
    mapBinding(await req(`/integrations/${id(integrationId)}/bindings`, {
      method: 'POST', body: JSON.stringify({ project_id: projectId, external_key: externalKey, external_name: externalName }),
    })),

  deleteIntegrationBinding: async (integrationId: string, bindingId: string): Promise<void> => {
    await req(`/integrations/${id(integrationId)}/bindings/${id(bindingId)}`, { method: 'DELETE' })
  },

  listIntegrationExternalRuns: async (integrationId: string): Promise<IntegrationExternalRun[]> =>
    ((await req(`/integrations/${id(integrationId)}/external-runs?limit=100`)) ?? []).map(mapRun),
}
