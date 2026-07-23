import type { ProjectCodeView } from './types'

export interface ProjectCodeSelection {
  analysisId: string | null
  path: string | null
  view: ProjectCodeView
  line: number | null
  findingId: string | null
}

export interface NormalizedProjectCodeSearch extends ProjectCodeSelection {
  params: URLSearchParams
  changed: boolean
}

export const PROJECT_CODE_SOURCE_WINDOW = 1000

const views = new Set<ProjectCodeView>(['source', 'unified', 'split'])

function text(value: string | null): string | null {
  const trimmed = value?.trim() ?? ''
  return trimmed || null
}

function positiveInteger(value: string | null): number | null {
  if (!value || !/^[1-9]\d*$/.test(value)) return null
  const number = Number(value)
  return Number.isSafeInteger(number) ? number : null
}

export function normalizeProjectCodeSearch(searchParams: URLSearchParams): NormalizedProjectCodeSearch {
  const params = new URLSearchParams(searchParams)
  const analysisId = text(searchParams.get('analysis'))
  const path = text(searchParams.get('path'))
  const rawView = searchParams.get('view')
  const view = rawView && views.has(rawView as ProjectCodeView) ? rawView as ProjectCodeView : 'source'
  const line = positiveInteger(searchParams.get('line'))
  const findingId = text(searchParams.get('finding'))
  let changed = false

  const normalizeText = (key: string, value: string | null) => {
    const raw = searchParams.get(key)
    if (value) {
      if (raw !== value) {
        params.set(key, value)
        changed = true
      }
    } else if (raw !== null) {
      params.delete(key)
      changed = true
    }
  }
  normalizeText('analysis', analysisId)
  normalizeText('path', path)
  if (rawView !== null && rawView !== view) {
    if (view === 'source') params.delete('view')
    else params.set('view', view)
    changed = true
  }
  if (!path) {
    const hadDependentState = searchParams.has('line') || searchParams.has('finding')
    params.delete('line')
    params.delete('finding')
    changed ||= hadDependentState
    return { analysisId, path: null, view, line: null, findingId: null, params, changed }
  }
  if (line === null && searchParams.has('line')) {
    params.delete('line')
    changed = true
  }
  normalizeText('finding', findingId)
  return { analysisId, path, view, line, findingId, params, changed }
}

export function projectCodePath(projectKey: string, selection: ProjectCodeSelection): string {
  const params = new URLSearchParams()
  if (selection.analysisId) params.set('analysis', selection.analysisId)
  if (selection.path) params.set('path', selection.path)
  if (selection.view !== 'source') params.set('view', selection.view)
  if (selection.path && selection.line) params.set('line', String(selection.line))
  if (selection.path && selection.findingId) params.set('finding', selection.findingId)
  const query = params.toString()
  return `/code-quality/projects/${encodeURIComponent(projectKey)}/code${query ? `?${query}` : ''}`
}
