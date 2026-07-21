export type MeasureAvailability = 'available' | 'unavailable' | 'not_applicable'

export interface MeasureCountMetric {
  availability: MeasureAvailability
  value: number | null
  reason: string | null
}

export interface MeasureDecimalMetric {
  availability: MeasureAvailability
  value: number | null
  reason: string | null
}

export interface MeasureGradeMetric {
  availability: MeasureAvailability
  grade: string | null
  reason: string | null
}

export interface SizeMeasures {
  files: MeasureCountMetric
  ncloc: MeasureCountMetric
  commentLines: MeasureCountMetric
  blankLines: MeasureCountMetric
  functions: MeasureCountMetric
  commentDensity: MeasureDecimalMetric
}

export interface ComplexityMeasures {
  cyclomatic: MeasureCountMetric
  cognitive: MeasureCountMetric
}

export interface CoverageMeasures {
  coveredLines: MeasureCountMetric
  coverableLines: MeasureCountMetric
  coverage: MeasureDecimalMetric
  newCodeCoverage: MeasureDecimalMetric
}

export interface DuplicationMeasures {
  duplicatedLines: MeasureCountMetric
  duplicationBlocks: MeasureCountMetric
  duplicationDensity: MeasureDecimalMetric
}

export interface IssueMeasures {
  byType: Record<string, MeasureCountMetric>
  bySeverity: Record<string, MeasureCountMetric>
}

export interface DebtMeasures {
  remediationEffortMinutes: MeasureCountMetric
}

export interface RatingsMeasures {
  security: MeasureGradeMetric
  reliability: MeasureGradeMetric
  maintainability: MeasureGradeMetric
}

export interface ProjectNodeInfo {
  key: string
  name: string
}

export interface AnalysisMetadata {
  id: string
  createdAt: string
  sourceRef: string
  sourceCommit: string
}

export interface MeasureNode {
  path: string
  name: string
  kind: 'project' | 'directory' | 'file'
  language: string
  size: SizeMeasures | null
  complexity: ComplexityMeasures | null
  coverage: CoverageMeasures | null
  duplication: DuplicationMeasures | null
  issues: IssueMeasures | null
  debt: DebtMeasures | null
  ratings: RatingsMeasures | null
}

export interface ChildCollection {
  items: MeasureNode[]
  nextCursor: string | null
}

export interface ProjectMeasureResponse {
  state: 'analyzed' | 'not_analyzed'
  project: ProjectNodeInfo
  analysis: AnalysisMetadata | null
  path: string
  includedDomains: string[]
  node: MeasureNode | null
  children: ChildCollection
}

export interface MeasuresQuery {
  path?: string
  domain?: string[]
  limit?: number
  cursor?: string
}

function mapCountMetric(raw: any): MeasureCountMetric {
  if (!raw) return { availability: 'unavailable', value: null, reason: null }
  return {
    availability: raw.availability ?? 'unavailable',
    value: raw.availability === 'available' && typeof raw.value === 'number' ? raw.value : null,
    reason: raw.unavailable_reason ?? null,
  }
}

function mapDecimalMetric(raw: any): MeasureDecimalMetric {
  if (!raw) return { availability: 'unavailable', value: null, reason: null }
  return {
    availability: raw.availability ?? 'unavailable',
    value: raw.availability === 'available' && typeof raw.value === 'number' ? raw.value : null,
    reason: raw.unavailable_reason ?? null,
  }
}

function mapGradeMetric(raw: any): MeasureGradeMetric {
  if (!raw) return { availability: 'unavailable', grade: null, reason: null }
  return {
    availability: raw.availability ?? 'unavailable',
    grade: raw.availability === 'available' && typeof raw.grade === 'string' ? raw.grade : null,
    reason: raw.unavailable_reason ?? null,
  }
}

function mapSizeMeasures(raw: any): SizeMeasures | null {
  if (!raw) return null
  return {
    files: mapCountMetric(raw.files),
    ncloc: mapCountMetric(raw.ncloc),
    commentLines: mapCountMetric(raw.comment_lines),
    blankLines: mapCountMetric(raw.blank_lines),
    functions: mapCountMetric(raw.functions),
    commentDensity: mapDecimalMetric(raw.comment_density),
  }
}

function mapComplexityMeasures(raw: any): ComplexityMeasures | null {
  if (!raw) return null
  return {
    cyclomatic: mapCountMetric(raw.cyclomatic),
    cognitive: mapCountMetric(raw.cognitive),
  }
}

function mapCoverageMeasures(raw: any): CoverageMeasures | null {
  if (!raw) return null
  return {
    coveredLines: mapCountMetric(raw.covered_lines),
    coverableLines: mapCountMetric(raw.coverable_lines),
    coverage: mapDecimalMetric(raw.coverage),
    newCodeCoverage: mapDecimalMetric(raw.new_code_coverage),
  }
}

function mapDuplicationMeasures(raw: any): DuplicationMeasures | null {
  if (!raw) return null
  return {
    duplicatedLines: mapCountMetric(raw.duplicated_lines),
    duplicationBlocks: mapCountMetric(raw.duplication_blocks),
    duplicationDensity: mapDecimalMetric(raw.duplication_density),
  }
}

function mapIssueMeasures(raw: any): IssueMeasures | null {
  if (!raw) return null
  
  const byType: Record<string, MeasureCountMetric> = {}
  if (raw.by_type) {
    for (const [k, v] of Object.entries(raw.by_type)) {
      byType[k] = mapCountMetric(v)
    }
  }

  const bySeverity: Record<string, MeasureCountMetric> = {}
  if (raw.by_severity) {
    for (const [k, v] of Object.entries(raw.by_severity)) {
      bySeverity[k] = mapCountMetric(v)
    }
  }

  return { byType, bySeverity }
}

function mapDebtMeasures(raw: any): DebtMeasures | null {
  if (!raw) return null
  return {
    remediationEffortMinutes: mapCountMetric(raw.remediation_effort_minutes),
  }
}

function mapRatingsMeasures(raw: any): RatingsMeasures | null {
  if (!raw) return null
  return {
    security: mapGradeMetric(raw.security),
    reliability: mapGradeMetric(raw.reliability),
    maintainability: mapGradeMetric(raw.maintainability),
  }
}

export function mapMeasureNode(raw: any): MeasureNode | null {
  if (!raw) return null
  return {
    path: raw.path ?? '',
    name: raw.name ?? '',
    kind: raw.kind ?? 'file',
    language: raw.language ?? '',
    size: mapSizeMeasures(raw.size),
    complexity: mapComplexityMeasures(raw.complexity),
    coverage: mapCoverageMeasures(raw.coverage),
    duplication: mapDuplicationMeasures(raw.duplication),
    issues: mapIssueMeasures(raw.issues),
    debt: mapDebtMeasures(raw.debt),
    ratings: mapRatingsMeasures(raw.ratings),
  }
}

export function mapProjectMeasureResponse(raw: any): ProjectMeasureResponse {
  const childrenItems = Array.isArray(raw?.children?.items) 
    ? raw.children.items.map(mapMeasureNode).filter(Boolean) as MeasureNode[]
    : []

  return {
    state: raw?.state ?? 'not_analyzed',
    project: {
      key: raw?.project?.key ?? '',
      name: raw?.project?.name ?? '',
    },
    analysis: raw?.analysis ? {
      id: raw.analysis.id ?? '',
      createdAt: raw.analysis.created_at ?? '',
      sourceRef: raw.analysis.source_ref ?? '',
      sourceCommit: raw.analysis.source_commit ?? '',
    } : null,
    path: raw?.path ?? '',
    includedDomains: Array.isArray(raw?.included_domains) ? raw.included_domains : [],
    node: mapMeasureNode(raw?.node),
    children: {
      items: childrenItems,
      nextCursor: raw?.children?.next_cursor ?? null,
    }
  }
}
