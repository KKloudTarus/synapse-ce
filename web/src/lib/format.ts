// Display helpers (presentation only – never mutate the stored value).

const ACRONYMS = new Set(['url', 'cidr', 'api', 'cve', 'ip', 'dns'])

// kindLabel renders a scope/target kind for display: acronyms uppercased,
// everything else capitalized (repo → Repo, url → URL, cidr → CIDR).
export function kindLabel(kind: string): string {
  const k = kind.toLowerCase()
  if (ACRONYMS.has(k)) return k.toUpperCase()
  return k.charAt(0).toUpperCase() + k.slice(1)
}

// statusLabel renders a finding triage status (false_positive → "False positive").
export function statusLabel(status: string): string {
  const s = status.replace(/_/g, ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}

const FINDING_KIND_ACRONYMS = new Set(['sca', 'sast', 'dast'])

// findingKindLabel renders a finding Kind for display: the scanner acronyms uppercased (sca → SCA,
// sast → SAST), everything else capitalized (exploitation → Exploitation, hypothesis → Hypothesis).
export function findingKindLabel(kind: string): string {
  const k = kind.toLowerCase()
  if (FINDING_KIND_ACRONYMS.has(k)) return k.toUpperCase()
  return k.charAt(0).toUpperCase() + k.slice(1)
}
