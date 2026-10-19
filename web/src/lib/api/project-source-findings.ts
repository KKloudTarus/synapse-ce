import type { Finding, ScanJob } from '../types'
import { req } from './client'
import { mapFinding } from './findings'

/** A finding resolved through a Project's private source-scan context. It deliberately has no engagement identity. */
export type ProjectSourceFinding = Omit<Finding, 'engagementId'>
export type ProjectSourceFindingPage = { items: ProjectSourceFinding[]; nextCursor: string }
/** A source-scan job carries the public job state but never exposes the internal engagement context. */
export type ProjectSourceScanJob = Omit<ScanJob, 'engagementId'>

function mapProjectSourceFinding(value: unknown): ProjectSourceFinding {
  const { engagementId: _hiddenEngagementID, ...finding } = mapFinding(value as Record<string, unknown>)
  return finding
}

function mapScanJob(value: any): ProjectSourceScanJob {
  return {
    id: value?.id ?? '',
    target: value?.target ?? '',
    kind: value?.kind ?? '',
    status: value?.status === 'succeeded' || value?.status === 'failed' ? value.status : 'running',
    stage: value?.stage ?? '',
    progress: value?.progress ?? 0,
    error: value?.error ?? '',
    startedAt: value?.started_at ?? null,
    finishedAt: value?.finished_at ?? null,
    debugEvents: Array.isArray(value?.debug_events) ? value.debug_events : [],
    engineOutcomes: Array.isArray(value?.engine_outcomes) ? value.engine_outcomes : [],
    engineCoverage: value?.engine_coverage,
  }
}

const projectPath = (key: string) => `/projects/${encodeURIComponent(key)}`
const sourceFindingPath = (key: string, findingID: string) => `${projectPath(key)}/source-findings/${encodeURIComponent(findingID)}`

export const projectSourceFindingsApi = {
  listProjectSourceFindings: async (projectKey: string, after = '', limit = 50): Promise<ProjectSourceFindingPage> => {
    const query = new URLSearchParams({ limit: String(limit) })
    if (after) query.set('after', after)
    const value = await req(`${projectPath(projectKey)}/source-findings?${query}`)
    return {
      items: Array.isArray(value?.items) ? value.items.map(mapProjectSourceFinding) : [],
      nextCursor: typeof value?.next_cursor === 'string' ? value.next_cursor : '',
    }
  },
  getProjectSourceFinding: async (projectKey: string, findingID: string): Promise<ProjectSourceFinding> =>
    mapProjectSourceFinding(await req(sourceFindingPath(projectKey, findingID))),
  updateProjectSourceFindingStatus: async (
    projectKey: string,
    findingID: string,
    status: string,
    version: number,
    note?: string,
  ): Promise<ProjectSourceFinding> => mapProjectSourceFinding(await req(sourceFindingPath(projectKey, findingID), {
    method: 'PATCH',
    body: JSON.stringify({ status, note, version }),
  })),
  startProjectSourceScan: async (projectKey: string, subdirectory: string): Promise<ProjectSourceScanJob> =>
    mapScanJob(await req(`${projectPath(projectKey)}/source-scans`, {
      method: 'POST',
      body: JSON.stringify({ subdirectory }),
    })),
  projectSourceScan: async (projectKey: string, jobID: string): Promise<ProjectSourceScanJob> =>
    mapScanJob(await req(`${projectPath(projectKey)}/source-scans/${encodeURIComponent(jobID)}`)),
}
