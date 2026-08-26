import type { AuditEntry, AuditReport } from '../types'
import { req } from './client'

export const auditApi = {
  recentAudit: async (limit = 200): Promise<AuditEntry[]> => (await req(`/audit?limit=${limit}`)) ?? [],

  verifyAudit: async (): Promise<AuditReport> => await req('/audit/verify'),
}
