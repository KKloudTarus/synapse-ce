// Barrel re-export — preserves all existing import paths from '../lib/api'
// All consumers use: import { api, ApiError, setToken, ... } from '../lib/api'

export { ApiError, setToken, setCSRFToken, setUnauthorizedHandler, discoverSession, logoutSession, type BFFSession } from './client'
export { type ReportType, type ReportBuildOptions } from './evidence'
export { type ReconLogEvent, streamReconLogs } from './recon'
export { type AgentStreamEvent, streamAgentSession } from './agent'
export { type Connector, type ConnectorCreate, type ConnectorProvider } from './connectors'
export { type ResponseRecord, type ResponsePlan, type ResponseKind, type ResponseState, type HaltResult, type PurpleVerdict, type PurpleCoverageRow, type PurpleWorkItem, type EmulationRunSummary } from './blueteam'
export { type RiskStory, type RiskFinding, type RiskExposure, type RiskPath, type RiskDetection, type RiskAssetFacts } from './riskstory'
export { type ReconcileRun, type ReconcileCounts, type ReconcileState, type ReconcileDiff, type ReconcileDiffClass, type ReconcileDiffCursor, type ReconcileDiffPage } from './vulnerability'

import { authApi, teamApi } from './auth'
import { auditApi } from './audit'
import { engagementsApi } from './engagements'
import { findingsApi } from './findings'
import { scanApi } from './scan'
import { evidenceApi } from './evidence'
import { reconApi } from './recon'
import { agentApi } from './agent'
import { codeQualityApi } from './code-quality'
import { rulesApi } from './rules'
import { fleetApi } from './fleet'
import { incidentsApi } from './incidents'
import { governanceApi } from './governance'
import { assetsApi } from './assets'
import { vulnerabilityApi } from './vulnerability'
import { aiTriageApi } from './ai-triage'
import { dashboardApi } from './dashboard'
import { capabilitiesApi } from './capabilities'
import { connectorsApi } from './connectors'
import { blueteamApi } from './blueteam'
import { riskStoryApi } from './riskstory'
import { slaApi } from './sla'

// projectMeasures was a standalone export in the old api.ts
export const projectMeasures = codeQualityApi.projectMeasures

// downloadExport/downloadReport/downloadBundle/downloadReportDoc were standalone exports
export const downloadExport = evidenceApi.downloadExport
export const downloadReport = evidenceApi.downloadReport
export const downloadBundle = evidenceApi.downloadBundle
export const downloadReportDoc = evidenceApi.downloadReportDoc

// Unified api object — same shape as before
export const api = {
  ...authApi,
  ...teamApi,
  ...auditApi,
  ...engagementsApi,
  ...findingsApi,
  ...scanApi,
  ...evidenceApi,
  ...reconApi,
  ...agentApi,
  ...codeQualityApi,
  ...rulesApi,
  ...fleetApi,
  ...incidentsApi,
  ...governanceApi,
  ...assetsApi,
  ...vulnerabilityApi,
  ...aiTriageApi,
  ...dashboardApi,
  ...capabilitiesApi,
  ...connectorsApi,
  ...blueteamApi,
  ...riskStoryApi,
  ...slaApi,
}
export {
  type SlaConfig,
  type SlaPolicy,
  type SlaWeights,
  type SlaThresholds,
  type SlaDueRange,
  type SlaDueRanges,
  type SlaTier,
  SLA_TIERS,
} from './sla'
export {
  type CoverageWindow,
  type CoverageWindowFilters,
  type CoverageClass,
  type CoverageClassState,
  type CoverageVector,
} from './fleet'
