export const projectAnalysisFocusValues = [
  'security',
  'reliability',
  'maintainability',
  'coverage',
  'duplications',
  'new-code',
] as const

export type ProjectAnalysisFocus = (typeof projectAnalysisFocusValues)[number]

const projectAnalysisFocusSet = new Set<string>(projectAnalysisFocusValues)

export function parseProjectAnalysisFocus(value: string | null): ProjectAnalysisFocus | null {
  return value !== null && projectAnalysisFocusSet.has(value) ? value as ProjectAnalysisFocus : null
}

export function serializeProjectAnalysisFocus(value: ProjectAnalysisFocus): string {
  return value
}
