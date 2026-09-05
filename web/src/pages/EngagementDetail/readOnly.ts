import type { Engagement } from '../../lib/types'

/** Shown wherever a write control is disabled because the engagement is archived. */
export const ARCHIVED_REASON = 'This engagement is archived. Archived engagements are read-only.'

/** Archived is the terminal lifecycle state; it accepts no scans, findings or triage writes. */
export function isReadOnly(engagement: Pick<Engagement, 'status'>): boolean {
  return engagement.status === 'archived'
}
