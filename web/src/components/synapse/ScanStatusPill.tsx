import { Pill, cn } from '../ui'

/** Every scan state a host or engagement row can be in. Workflow, not risk. */
export type ScanState = 'none' | 'unrecorded' | 'pending' | 'running' | 'succeeded' | 'failed'

export const SCAN_STATE_LABEL: Record<ScanState, string> = {
  none: 'No package inventory',
  unrecorded: 'Packages not recorded',
  pending: 'Scan pending',
  running: 'Scanning',
  succeeded: 'Scanned',
  failed: 'Scan failed',
}

// Scan state is workflow, not risk: neutral, brand and success tones; only a failure borrows the error tone.
const SCAN_STATE_CLASS: Record<ScanState, string> = {
  none: 'bg-secondary text-tertiary',
  unrecorded: 'bg-warning-primary text-warning-primary',
  pending: 'bg-secondary text-secondary',
  running: 'bg-brand-primary text-brand-secondary',
  succeeded: 'bg-success-primary text-success-primary',
  failed: 'bg-error-primary text-error-primary',
}

/** Normalises a job status string from the API to a ScanState; unknown strings read as pending. */
export function scanStateOf(status: string | null | undefined): ScanState {
  switch (status) {
    case 'succeeded':
    case 'failed':
    case 'running':
    case 'pending':
      return status
    default:
      return 'pending'
  }
}

/** The one pill every table uses for a scan's state, so "Scanned" looks the same on Hosts and Engagements. */
export function ScanStatusPill({ state, title, className }: { state: ScanState; title?: string; className?: string }) {
  return (
    <Pill className={cn(SCAN_STATE_CLASS[state], className)}>
      <span title={title}>{SCAN_STATE_LABEL[state]}</span>
    </Pill>
  )
}
