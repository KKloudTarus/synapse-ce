import { req } from './client'

/**
 * Source-control connectors: tenant-scoped git-host + personal-access-token bindings that let a
 * server-initiated scan clone a PRIVATE repository. Wire shape: `connectorDTO` in
 * internal/adapter/httpapi/scm_connector_handler.go. The token is write-only — it is sent on create
 * and never returned, so a Connector carries only metadata.
 */
export type ConnectorProvider = 'github' | 'gitlab' | 'bitbucket' | 'generic'

export interface Connector {
  id: string
  name: string
  provider: ConnectorProvider
  host: string
  username: string
  authKind: string
  createdAt: string
  updatedAt: string
}

export interface ConnectorCreate {
  name: string
  provider: ConnectorProvider
  host: string
  username?: string
  token: string
}

function mapConnector(raw: any): Connector {
  return {
    id: raw?.id ?? '',
    name: raw?.name ?? '',
    provider: (raw?.provider ?? 'generic') as ConnectorProvider,
    host: raw?.host ?? '',
    username: raw?.username ?? '',
    authKind: raw?.auth_kind ?? '',
    createdAt: raw?.created_at ?? '',
    updatedAt: raw?.updated_at ?? '',
  }
}

export const connectorsApi = {
  /** Returns null when the deployment does not expose connectors (route 404), so the page can say so. */
  listConnectors: async (): Promise<Connector[] | null> => {
    try {
      const res = await req('/connectors')
      const list = res?.connectors
      return Array.isArray(list) ? list.map(mapConnector) : []
    } catch (e: any) {
      if (e?.status === 404) return null
      throw e
    }
  },
  createConnector: async (body: ConnectorCreate): Promise<Connector> =>
    mapConnector(await req('/connectors', { method: 'POST', body: JSON.stringify(body) })),
  deleteConnector: async (id: string): Promise<void> => {
    await req(`/connectors/${encodeURIComponent(id)}`, { method: 'DELETE' })
  },
}
