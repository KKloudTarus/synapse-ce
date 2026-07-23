import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { FileCode2 } from 'lucide-react'
import { ProjectCodeWorkspace } from '../components/codequality/ProjectCodeWorkspace'
import { Button, EmptyState, ErrorState, Spinner } from '../components/ui'
import { api, ApiError } from '../lib/api'
import { normalizeProjectCodeSearch, PROJECT_CODE_SOURCE_WINDOW } from '../lib/projectCodeNavigation'
import type { ProjectCodeDiffResponse, ProjectCodeFileIndex, ProjectCodeFileView, ProjectCodeFinding, ProjectCodeView } from '../lib/types'
import { ProjectRouteEmpty, useProjectRouteContext } from './CodeQualityProject'

const windowStart = (line: number | null) => line ? Math.floor((line - 1) / PROJECT_CODE_SOURCE_WINDOW) * PROJECT_CODE_SOURCE_WINDOW + 1 : 1

export function ProjectCodePage() {
  const { projectKey, analysisRevision, isRunning } = useProjectRouteContext()
  const [params, setParams] = useSearchParams()
  const selection = normalizeProjectCodeSearch(params)
  const [latestAnalysisId, setLatestAnalysisId] = useState<string | null>(null)
  const analysisId = selection.analysisId ?? latestAnalysisId
  const [index, setIndex] = useState<ProjectCodeFileIndex | null>(null)
  const [source, setSource] = useState<ProjectCodeFileView | null>(null)
  const [diff, setDiff] = useState<ProjectCodeDiffResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [sourceError, setSourceError] = useState<string | null>(null)
  const [diffError, setDiffError] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)
  const indexAbort = useRef<AbortController | null>(null)
  const contentAbort = useRef<AbortController | null>(null)
  const selectedFile = index?.files.find((file) => file.path === selection.path) ?? null
  const diffAvailable = selection.view === 'unified' ? index?.capabilities.unifiedDiff : index?.capabilities.splitDiff
  const view = selectedFile && selection.view !== 'source' && (selectedFile.status === 'unchanged' || !diffAvailable) ? 'source' : selection.view

  useEffect(() => {
    if (selection.changed) setParams(selection.params, { replace: true })
  }, [selection.changed, selection.params, setParams])

  useEffect(() => {
    if (selection.analysisId) {
      setLatestAnalysisId(null)
      return
    }
    let live = true
    setLatestAnalysisId(null)
    api.projectAnalyses(projectKey)
      .then((page) => {
        if (live && !selection.analysisId) setLatestAnalysisId(page.items[0]?.id ?? null)
      })
      .catch((err) => live && setError(message(err)))
    return () => { live = false }
  }, [analysisRevision, projectKey, selection.analysisId])

  useEffect(() => {
    if (!analysisId) return
    indexAbort.current?.abort()
    const abort = new AbortController()
    indexAbort.current = abort
    setLoading(true)
    setError(null)
    setIndex(null)
    api.listProjectCodeFiles(projectKey, analysisId, abort.signal)
      .then((next) => { if (!abort.signal.aborted) setIndex(next) })
      .catch((err) => { if (!abort.signal.aborted) setError(message(err)) })
      .finally(() => { if (!abort.signal.aborted) setLoading(false) })
    return () => abort.abort()
  }, [analysisId, projectKey, refresh])

  useEffect(() => {
    if (!index || selection.path || !index.files.length) return
    const file = index.files.find((candidate) => candidate.sourceAvailable) ?? index.files[0]
    patch({ path: file.path, line: 1, finding: null }, true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [index, selection.path])

  useEffect(() => {
    if (!index || !selectedFile || selection.view === 'source' || view !== 'source') return
    patch({ view: 'source' }, true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [index, selectedFile, selection.view, view])

  useEffect(() => {
    if (!index || !analysisId || !selection.path) {
      setSource(null)
      setDiff(null)
      return
    }
    contentAbort.current?.abort()
    const abort = new AbortController()
    contentAbort.current = abort
    setSource(null)
    setDiff(null)
    setSourceError(null)
    setDiffError(null)
    api.projectCodeFile(projectKey, analysisId, selection.path, windowStart(selection.line), abort.signal)
      .then((next) => { if (!abort.signal.aborted) setSource(next) })
      .catch((err) => { if (!abort.signal.aborted) setSourceError(message(err)) })
    if (view !== 'source') {
      api.projectCodeDiff(projectKey, analysisId, selection.path, view, abort.signal)
        .then((next) => { if (!abort.signal.aborted) setDiff(next) })
        .catch((err) => { if (!abort.signal.aborted) setDiffError(message(err)) })
    }
    return () => abort.abort()
  }, [analysisId, index, projectKey, refresh, selection.line, selection.path, view])

  function patch(values: Partial<{ path: string | null; line: number | null; finding: string | null; view: ProjectCodeView }>, replace = false) {
    const next = new URLSearchParams(params)
    if ('path' in values) values.path ? next.set('path', values.path) : next.delete('path')
    if ('line' in values) values.line ? next.set('line', String(values.line)) : next.delete('line')
    if ('finding' in values) values.finding ? next.set('finding', values.finding) : next.delete('finding')
    if ('view' in values) values.view === 'source' ? next.delete('view') : next.set('view', values.view!)
    setParams(next, { replace })
  }

  function selectFile(path: string) {
    const file = index?.files.find((candidate) => candidate.path === path)
    const nextView = selection.view !== 'source' && (file?.status === 'unchanged' || !diffCapability(index, selection.view)) ? 'source' : selection.view
    patch({ path, line: 1, finding: null, view: nextView })
  }
  function selectFinding(finding: ProjectCodeFinding | null) { patch({ finding: finding?.id ?? null, line: finding?.location.startLine ?? selection.line }) }

  if (error && !index) return <div className="space-y-3"><ErrorState message={error} /><Button variant="secondary" onClick={() => setRefresh((value) => value + 1)}>Retry</Button></div>
  if (!analysisId) return loading ? <Spinner label="Loading analyses…" /> : <ProjectRouteEmpty running={isRunning} />
  if (loading || !index) return <Spinner label="Loading Code workspace…" />
  if (!index.files.length) return <EmptyState icon={FileCode2} title="No captured files" hint="This immutable analysis has no source files available for Code review." />

  return <div className="space-y-3">
    {isRunning && <div className="rounded-lg border border-brand/30 bg-brand/10 px-4 py-3 text-sm text-mutedfg">A new analysis is running. This workspace remains {selection.analysisId ? 'pinned to immutable analysis ' : 'on the latest completed analysis '}<span className="font-mono">{analysisId}</span>.</div>}
    <ProjectCodeWorkspace index={index} source={source} diff={diff} selectedPath={selection.path} selectedFindingId={selection.findingId} view={view} onSelectFile={selectFile} onSelectFinding={selectFinding} onView={(nextView) => { if (nextView === 'source' || (selectedFile?.status !== 'unchanged' && diffCapability(index, nextView))) patch({ view: nextView }) }} onNavigateLine={(line) => patch({ line, finding: null })} onRetrySource={() => setRefresh((value) => value + 1)} sourceError={sourceError} diffError={diffError} />
  </div>
}

function diffCapability(index: ProjectCodeFileIndex | null, view: ProjectCodeView): boolean {
  if (view === 'source') return true
  return view === 'unified' ? index?.capabilities.unifiedDiff === true : index?.capabilities.splitDiff === true
}

function message(error: unknown): string {
  if (error instanceof ApiError) return error.message
  return error instanceof Error ? error.message : 'Failed to load immutable Code data'
}
