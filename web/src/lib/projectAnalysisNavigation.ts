export const projectAnalysisFocusValues = [
  'security',
  'reliability',
  'maintainability',
  'coverage',
  'duplications',
  'new-code',
] as const

export type ProjectAnalysisFocus = (typeof projectAnalysisFocusValues)[number]
export type ProjectCodeLens = CodeLens

export interface ProjectAnalysisNavigation {
  focus: ProjectAnalysisFocus | null
  lens: ProjectCodeLens
}

export interface NormalizedProjectAnalysisSearch extends ProjectAnalysisNavigation {
  params: URLSearchParams
  changed: boolean
}

export const projectAnalysisLandmarks = {
  newCode: 'project-analysis-new-code',
  qualityRatings: 'project-analysis-quality-ratings',
  coverage: 'project-analysis-coverage',
  duplications: 'project-analysis-duplications',
  findings: 'project-analysis-findings',
} as const

const projectAnalysisFocusSet = new Set<string>(projectAnalysisFocusValues)

export function parseProjectAnalysisFocus(value: string | null): ProjectAnalysisFocus | null {
  return value !== null && projectAnalysisFocusSet.has(value) ? value as ProjectAnalysisFocus : null
}

export function serializeProjectAnalysisFocus(value: ProjectAnalysisFocus): string {
  return value
}

export function normalizeProjectAnalysisSearch(searchParams: URLSearchParams): NormalizedProjectAnalysisSearch {
  const params = new URLSearchParams(searchParams)
  const rawFocus = searchParams.get('focus')
  const focus = parseProjectAnalysisFocus(rawFocus)
  let changed = false

  if (rawFocus !== null && focus === null) {
    params.delete('focus')
    changed = true
  }

  const rawLens = searchParams.get('lens')
  let lens = parseCodeLens(rawLens)
  if (rawLens !== null && !isValidCodeLens(rawLens)) {
    params.set('lens', 'overall')
    changed = true
  }
  if (focus === 'new-code' && lens !== 'new-code') {
    lens = 'new-code'
    params.set('lens', 'new-code')
    changed = true
  }

  return { focus, lens, params, changed }
}

export function projectAnalysisPath(
  projectKey: string,
  focus: ProjectAnalysisFocus | null = null,
  lens: ProjectCodeLens | null = null,
): string {
  const path = `/code-quality/projects/${encodeURIComponent(projectKey)}/analysis`
  const params = new URLSearchParams()
  if (focus !== null) params.set('focus', serializeProjectAnalysisFocus(focus))
  if (lens !== null) params.set('lens', serializeCodeLens(lens))
  const query = params.toString()
  return query ? `${path}?${query}` : path
}

export function projectOverviewPath(projectKey: string, lens: ProjectCodeLens): string {
  return `/code-quality/projects/${encodeURIComponent(projectKey)}?lens=${serializeCodeLens(lens)}`
}

export function projectAnalysisLandmarkFor(
  focus: ProjectAnalysisFocus,
  lens: ProjectCodeLens,
): string {
  if (lens === 'new-code' || focus === 'new-code') return projectAnalysisLandmarks.newCode
  switch (focus) {
    case 'security':
    case 'reliability':
    case 'maintainability':
      return projectAnalysisLandmarks.findings
    case 'coverage':
      return projectAnalysisLandmarks.coverage
    case 'duplications':
      return projectAnalysisLandmarks.duplications
  }
}
import {
  isValidCodeLens,
  parseCodeLens,
  serializeCodeLens,
  type CodeLens,
} from './projectOverviewPresentation'
