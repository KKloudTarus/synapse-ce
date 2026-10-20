import type { TicketMapping } from './api/ticketing'
import type { Integration, IntegrationProviderDescriptor } from './types'

export type TicketDestination = Readonly<{
  provider: string
  connection: string
  endpoint: string
  mapping: string
}>

/**
 * Maps an administrator-selected mapping to its configured connection.  A missing
 * connection, provider descriptor, or endpoint is deliberately unresolved: callers
 * must not display a plausible destination for an outbound ticket request.
 */
export function ticketDestination(mapping: TicketMapping, integrations: Integration[], providers: IntegrationProviderDescriptor[]): TicketDestination | null {
  const integration = integrations.find((item) => item.id === mapping.integrationId)
  const connection = typeof integration?.name === 'string' ? integration.name.trim() : ''
  const endpoint = typeof integration?.endpoint === 'string' ? integration.endpoint.trim() : ''
  if (!integration || !connection || !endpoint) return null
  const provider = providers.find((item) => item.provider === integration.provider)
  const providerName = typeof provider?.name === 'string' ? provider.name.trim() : ''
  if (!provider || !providerName) return null
  return {
    provider: providerName,
    connection,
    endpoint,
    mapping: `${mapping.projectKey || 'Unspecified project'} · ${mapping.issueType || 'Unspecified type'} (${mapping.locale})`,
  }
}

export function ticketDestinationLabel(mapping: TicketMapping, integrations: Integration[], providers: IntegrationProviderDescriptor[]): string {
  const destination = ticketDestination(mapping, integrations, providers)
  return destination ? `${destination.provider} · ${destination.connection} · ${destination.endpoint} · ${destination.mapping}` : 'Unresolved ticket destination'
}
