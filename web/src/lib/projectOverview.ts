export type ProjectOverviewState = 'not_analyzed' | 'analyzed'

export type MetricAvailability =
  | 'available'
  | 'unavailable'
  | 'not_supplied'
  | 'not_applicable'

export type UnavailableReason =
  | 'no_analysis'
  | 'rating_not_available'
  | 'issue_lifecycle_not_available'
  | 'security_hotspots_not_available'
  | 'changed_line_metrics_not_available'
  | 'coverage_not_supplied'
  | 'no_executable_lines'
  | 'duplication_not_available'

export type OverviewGrade = 'A' | 'B' | 'C' | 'D' | 'E'
export type OverviewGateStatus = 'passed' | 'failed'

export interface RatingMetric {
  availability: MetricAvailability
  grade: OverviewGrade | null
  unavailableReason: UnavailableReason | null
}

export interface PercentageMetric {
  availability: MetricAvailability
  value: number | null
  unavailableReason: UnavailableReason | null
}

export interface CountMetric {
  availability: MetricAvailability
  value: number | null
  unavailableReason: UnavailableReason | null
}

export interface ProjectOverviewAnalysis {
  id: string
  createdAt: string
  sourceRef: string
  sourceCommit: string
  newCode: {
    firstAnalysis: boolean
    hasBaseline: boolean
    baselineAnalysisId: string | null
  }
}

export interface ProjectOverviewGate {
  status: OverviewGateStatus
  key: string | null
  name: string | null
  source: string | null
  failedConditions: ProjectOverviewGateCondition[]
}

export interface ProjectOverviewGateCondition {
  metric: string
  operator: string
  threshold: number
  actual: number
}

export interface ProjectOverviewIssueSummary {
  new: CountMetric
  accepted: CountMetric
}

export interface ProjectOverviewLens {
  security: RatingMetric
  reliability: RatingMetric
  maintainability: RatingMetric
  securityHotspotsReviewed: PercentageMetric
  coverage: PercentageMetric
  duplications: PercentageMetric
}

export interface ProjectOverview {
  state: ProjectOverviewState
  project: {
    key: string
    name: string
  }
  latestAnalysis: ProjectOverviewAnalysis | null
  gate: ProjectOverviewGate | null
  issues: ProjectOverviewIssueSummary
  lenses: {
    overall: ProjectOverviewLens
    newCode: ProjectOverviewLens
  }
}

const STATES = new Set<ProjectOverviewState>(['not_analyzed', 'analyzed'])
const AVAILABILITIES = new Set<MetricAvailability>(['available', 'unavailable', 'not_supplied', 'not_applicable'])
const REASONS = new Set<UnavailableReason>([
  'no_analysis',
  'rating_not_available',
  'issue_lifecycle_not_available',
  'security_hotspots_not_available',
  'changed_line_metrics_not_available',
  'coverage_not_supplied',
  'no_executable_lines',
  'duplication_not_available',
])
const GRADES = new Set<OverviewGrade>(['A', 'B', 'C', 'D', 'E'])
const GATE_STATUSES = new Set<OverviewGateStatus>(['passed', 'failed'])

const INVALID_PROJECT_OVERVIEW_RESPONSE = 'Invalid project overview response'

function invalid(): never {
  throw new Error(INVALID_PROJECT_OVERVIEW_RESPONSE)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function record(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) invalid()
  return value
}

function stringValue(value: unknown): string {
  if (typeof value !== 'string') invalid()
  return value
}

function nullableString(value: unknown): string | null {
  if (value === null) return null
  return stringValue(value)
}

function booleanValue(value: unknown): boolean {
  if (typeof value !== 'boolean') invalid()
  return value
}

function finiteNumber(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) invalid()
  return value
}

function stringEnum<T extends string>(value: unknown, allowed: Set<T>): T {
  const v = stringValue(value)
  if (!allowed.has(v as T)) invalid()
  return v as T
}

function unavailableReason(value: unknown): UnavailableReason | null {
  if (value === null) return null
  return stringEnum(value, REASONS)
}

function ratingMetric(value: unknown): RatingMetric {
  const raw = record(value)
  const availability = stringEnum(raw.availability, AVAILABILITIES)
  const reason = unavailableReason(raw.unavailable_reason)
  if (availability === 'available') {
    const grade = stringEnum(raw.grade, GRADES)
    if (reason !== null) invalid()
    return { availability, grade, unavailableReason: null }
  }
  if (raw.grade !== null || reason === null) invalid()
  return { availability, grade: null, unavailableReason: reason }
}

function percentageMetric(value: unknown): PercentageMetric {
  const raw = record(value)
  const availability = stringEnum(raw.availability, AVAILABILITIES)
  const reason = unavailableReason(raw.unavailable_reason)
  if (availability === 'available') {
    const pct = finiteNumber(raw.value)
    if (pct < 0 || pct > 100 || reason !== null) invalid()
    return { availability, value: pct, unavailableReason: null }
  }
  if (raw.value !== null || reason === null) invalid()
  return { availability, value: null, unavailableReason: reason }
}

function countMetric(value: unknown): CountMetric {
  const raw = record(value)
  const availability = stringEnum(raw.availability, AVAILABILITIES)
  const reason = unavailableReason(raw.unavailable_reason)
  if (availability === 'available') {
    const count = finiteNumber(raw.value)
    if (!Number.isInteger(count) || count < 0 || reason !== null) invalid()
    return { availability, value: count, unavailableReason: null }
  }
  if (raw.value !== null || reason === null) invalid()
  return { availability, value: null, unavailableReason: reason }
}

function parseTimestamp(value: unknown): string {
  const s = stringValue(value)
  if (Number.isNaN(Date.parse(s))) invalid()
  return s
}

function projectAnalysis(value: unknown): ProjectOverviewAnalysis {
  const raw = record(value)
  const newCode = record(raw.new_code)
  const baselineAnalysisId = nullableString(newCode.baseline_analysis_id)
  const firstAnalysis = booleanValue(newCode.first_analysis)
  const hasBaseline = booleanValue(newCode.has_baseline)
  if (firstAnalysis && hasBaseline) invalid()
  if (!hasBaseline && baselineAnalysisId !== null) invalid()
  if (hasBaseline && (!baselineAnalysisId || baselineAnalysisId.trim() === '')) invalid()
  return {
    id: stringValue(raw.id),
    createdAt: parseTimestamp(raw.created_at),
    sourceRef: stringValue(raw.source_ref),
    sourceCommit: stringValue(raw.source_commit),
    newCode: { firstAnalysis, hasBaseline, baselineAnalysisId },
  }
}

function projectGate(value: unknown): ProjectOverviewGate {
  const raw = record(value)
  if (!Array.isArray(raw.failed_conditions)) invalid()
  return {
    status: stringEnum(raw.status, GATE_STATUSES),
    key: nullableString(raw.key),
    name: nullableString(raw.name),
    source: nullableString(raw.source),
    failedConditions: raw.failed_conditions.map((item) => {
      const condition = record(item)
      return {
        metric: stringValue(condition.metric),
        operator: stringValue(condition.operator),
        threshold: finiteNumber(condition.threshold),
        actual: finiteNumber(condition.actual),
      }
    }),
  }
}

function overviewLens(value: unknown): ProjectOverviewLens {
  const raw = record(value)
  return {
    security: ratingMetric(raw.security),
    reliability: ratingMetric(raw.reliability),
    maintainability: ratingMetric(raw.maintainability),
    securityHotspotsReviewed: percentageMetric(raw.security_hotspots_reviewed),
    coverage: percentageMetric(raw.coverage),
    duplications: percentageMetric(raw.duplications),
  }
}

export function mapProjectOverviewResponse(raw: unknown): ProjectOverview {
  const root = record(raw)
  const state = stringEnum(root.state, STATES)
  const project = record(root.project)
  const issues = record(root.issues)
  const lenses = record(root.lenses)
  const latestAnalysis = root.latest_analysis === null ? null : projectAnalysis(root.latest_analysis)
  const gate = root.gate === null ? null : projectGate(root.gate)
  if (state === 'not_analyzed' && (latestAnalysis !== null || gate !== null)) invalid()
  if (state === 'analyzed' && (latestAnalysis === null || gate === null)) invalid()
  return {
    state,
    project: {
      key: stringValue(project.key),
      name: stringValue(project.name),
    },
    latestAnalysis,
    gate,
    issues: {
      new: countMetric(issues.new),
      accepted: countMetric(issues.accepted),
    },
    lenses: {
      overall: overviewLens(lenses.overall),
      newCode: overviewLens(lenses.new_code),
    },
  }
}
