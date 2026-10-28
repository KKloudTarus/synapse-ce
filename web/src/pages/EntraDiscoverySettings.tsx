import { useId } from 'react'
import type { EntraDiscoveryMode } from '../lib/api/identity'

export function entraDirectory(issuer: string): string | null {
  return /^https:\/\/login\.microsoftonline\.com\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/v2\.0$/.exec(issuer)?.[1] ?? null
}

export function entraModeLabel(mode: EntraDiscoveryMode | undefined): string {
  return mode === 'common' ? 'Common' : mode === 'organizations' ? 'Organizations' : 'Tenant-specific'
}

export function EntraDiscoverySettings({ issuer, mode, onChange, disabled = false }: { issuer: string; mode: EntraDiscoveryMode; onChange: (mode: EntraDiscoveryMode) => void; disabled?: boolean }) {
  const modeID = useId()
  const helpID = `${modeID}-help`
  const directory = entraDirectory(issuer)
  if (!directory) return null
  return <div className="grid gap-1 text-sm text-primary">
    <label htmlFor={modeID}>Entra metadata discovery</label>
    <select id={modeID} value={mode} disabled={disabled} onChange={(event) => onChange(event.target.value as EntraDiscoveryMode)} aria-describedby={helpID} className="rounded border border-secondary px-3 py-2 disabled:opacity-70">
      <option value="">Tenant-specific</option><option value="common">Common</option><option value="organizations">Organizations</option>
    </select>
    <p id={helpID} className="text-secondary">Metadata discovery uses the selected endpoint. Sign-in remains pinned to approved directory <code>{directory}</code>.</p>
  </div>
}
