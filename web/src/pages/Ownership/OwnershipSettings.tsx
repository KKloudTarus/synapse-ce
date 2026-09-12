import { useState } from 'react'
import { OwnershipBoundary } from './shared'
import { OwnershipTeams } from './OwnershipTeams'
import { RoutingPolicies } from './RoutingPolicies'

export function OwnershipSettings() {
  const [section, setSection] = useState<'teams' | 'routing'>('teams')
  return <OwnershipBoundary admin>{(capability) => <div className="space-y-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-xl font-bold text-primary">Finding ownership</h2><p className="text-sm text-secondary">Map trusted ownership evidence to Synapse teams and route canonical findings.</p></div><span className="rounded-full bg-secondary px-3 py-1 text-xs font-semibold text-secondary">{capability.mode} mode</span></div>
    <nav aria-label="Ownership settings" className="flex gap-2 border-b border-secondary"><button className={`px-3 py-2 text-sm font-semibold ${section === 'teams' ? 'border-b-2 border-brand-solid text-brand-secondary' : 'text-tertiary'}`} onClick={() => setSection('teams')}>Teams & members</button><button className={`px-3 py-2 text-sm font-semibold ${section === 'routing' ? 'border-b-2 border-brand-solid text-brand-secondary' : 'text-tertiary'}`} onClick={() => setSection('routing')}>Routing policies</button></nav>
    {section === 'teams' ? <OwnershipTeams /> : <RoutingPolicies capability={capability} />}
  </div>}</OwnershipBoundary>
}
