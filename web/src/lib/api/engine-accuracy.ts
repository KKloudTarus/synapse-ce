import { req } from './client'

// Detection-accuracy trend for the owned scanner engine (EPIC #860 D8.6). Deployment-global engine
// data served by GET /api/v1/engine/accuracy (snake_case wire shape from accuracy_handler.go).

export interface AccuracyMetrics {
  truePositives: number
  falsePositives: number
  falseNegatives: number
  precision: number
  recall: number
  f1: number
  falseDiscoveryRate: number
  falseNegativeRate: number
}

export interface AccuracyGroup {
  group: string
  cases: number
  metrics: AccuracyMetrics
}

export interface AccuracyRun {
  id: string
  ranAt: string
  corpusVersion: string
  schemaVersion: string
  cases: number
  overall: AccuracyMetrics
  groups: AccuracyGroup[]
}

function mapMetrics(r: any): AccuracyMetrics {
  return {
    truePositives: r?.true_positives ?? 0,
    falsePositives: r?.false_positives ?? 0,
    falseNegatives: r?.false_negatives ?? 0,
    precision: r?.precision ?? 0,
    recall: r?.recall ?? 0,
    f1: r?.f1 ?? 0,
    falseDiscoveryRate: r?.false_discovery_rate ?? 0,
    falseNegativeRate: r?.false_negative_rate ?? 0,
  }
}

function mapRun(r: any): AccuracyRun {
  return {
    id: r?.id ?? '',
    ranAt: r?.ran_at ?? '',
    corpusVersion: r?.corpus_version ?? '',
    schemaVersion: r?.schema_version ?? '',
    cases: r?.cases ?? 0,
    overall: mapMetrics(r?.overall),
    groups: Array.isArray(r?.groups)
      ? r.groups.map((g: any) => ({ group: g?.group ?? '', cases: g?.cases ?? 0, metrics: mapMetrics(g?.metrics) }))
      : [],
  }
}

export const engineAccuracyApi = {
  // Recent detection-accuracy regression runs, newest first. Returns [] when the nightly job is not
  // enabled (the route is always registered and answers with an empty list).
  engineAccuracy: async (limit = 50, signal?: AbortSignal): Promise<AccuracyRun[]> => {
    const res = await req(`/engine/accuracy?limit=${limit}`, { signal })
    return Array.isArray(res?.runs) ? res.runs.map(mapRun) : []
  },
}
