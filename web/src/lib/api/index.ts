// Barrel re-export — preserves all existing import paths from '../lib/api'
// All consumers use: import { api, ApiError, setToken, ... } from '../lib/api'

export { ApiError, setToken, setCSRFToken, setUnauthorizedHandler, discoverSession, logoutSession, type BFFSession } from './client'
export { type ReportType, type ReportBuildOptions } from './evidence'
export { type ReconLogEvent, streamReconLogs } from './recon'
export { type AgentStreamEvent, streamAgentSession } from './agent'

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
import { assetsApi } from './assets'
import { vulnerabilityApi } from './vulnerability'
import { aiTriageApi } from './ai-triage'
import { dashboardApi } from './dashboard'

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
  ...assetsApi,
  ...vulnerabilityApi,
  ...aiTriageApi,
  ...dashboardApi,
}
