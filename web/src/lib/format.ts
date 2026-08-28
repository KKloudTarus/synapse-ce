// Display helpers (presentation only – never mutate the stored value).

const ACRONYMS = new Set(['url', 'cidr', 'api', 'cve', 'ip', 'dns', 'sca', 'sast', 'dast', 'iac'])

function toTitleCase(str: string): string {
  if (!str) return ''
  return str
    .split(/[-_.* ]+/)
    .filter(Boolean)
    .map((word) => {
      const lower = word.toLowerCase()
      if (ACRONYMS.has(lower)) return lower.toUpperCase()
      return lower.charAt(0).toUpperCase() + lower.slice(1)
    })
    .join(' ')
}

// kindLabel renders a scope/target kind for display: acronyms uppercased,
// each word capitalized (repo → Repo, url → URL, cidr → CIDR).
export function kindLabel(kind: string): string {
  return toTitleCase(kind)
}

// statusLabel renders a finding triage status (false_positive → "False Positive").
export function statusLabel(status: string): string {
  return toTitleCase(status)
}

// findingKindLabel renders a finding Kind for display: scanner acronyms uppercased (sca → SCA,
// sast → SAST), each word capitalized (code_quality → Code Quality).
export function findingKindLabel(kind: string): string {
  return toTitleCase(kind)
}
