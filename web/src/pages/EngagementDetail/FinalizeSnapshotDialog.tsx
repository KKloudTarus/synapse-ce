import { useState } from 'react'
import { Camera01, XClose } from '@untitledui/icons'
import { Dialog, Modal, ModalOverlay } from '../../components/application/modals/modal'
import { Button, ErrorState, Pill, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { ApiError, api } from '../../lib/api'
import type { ScanRun } from '../../lib/types'

function runTime(value: string | null): string {
  if (!value) return 'Not sealed'
  const at = new Date(value)
  return Number.isNaN(at.getTime()) ? 'Unknown time' : at.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

/**
 * Finalizes an immutable assessment snapshot from selected scan runs.
 *
 * The server expands a run with no explicit lane keys to all of that run's provenance lanes, so the
 * operator chooses runs and the lane set stays server-authoritative. `expectedDefaultVersion` is
 * sent as If-Match: if another operator finalized a snapshot first, the request is rejected as a
 * conflict rather than overwriting the default pointer they just set.
 */
export function FinalizeSnapshotDialog({
  assessmentId,
  expectedDefaultVersion,
  onClose,
  onFinalized,
}: {
  assessmentId: string
  expectedDefaultVersion: number
  onClose: () => void
  onFinalized: () => void
}) {
  const runs = useFetch<ScanRun[]>(() => api.scanRuns(assessmentId), { deps: [assessmentId] })
  const [selected, setSelected] = useState<string[]>([])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const items = runs.data ?? []
  // A run with no provenance lane cannot contribute to a snapshot; the server rejects it, so it is
  // not offered here.
  const selectable = items.filter((run) => run.laneCount > 0)

  function toggle(runId: string) {
    setSelected((current) => (current.includes(runId) ? current.filter((id) => id !== runId) : [...current, runId]))
  }

  async function finalize() {
    if (selected.length === 0) return
    setSaving(true)
    setError('')
    try {
      await api.finalizeAssessmentSnapshot(assessmentId, {
        selectedRuns: selected.map((runId) => ({ runId })),
        expectedDefaultVersion,
      })
      onFinalized()
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 409) {
        setError('Another operator finalized a snapshot for this Assessment. Refresh and review the current snapshots before finalizing again.')
      } else if (cause instanceof ApiError && cause.status === 400) {
        setError('The server rejected this selection. Snapshots require an open Assessment Cycle and runs that belong to this Assessment.')
      } else {
        setError(cause instanceof Error ? cause.message : 'Finalize failed.')
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <ModalOverlay isOpen isDismissable={!saving} onOpenChange={(open) => { if (!open && !saving) onClose() }}>
      <Modal className="w-full max-w-3xl">
        <Dialog aria-label="Finalize assessment snapshot">
          <div className="flex items-start justify-between gap-3 border-b border-secondary px-6 py-4">
            <div>
              <h2 className="text-lg font-semibold text-primary">Finalize a snapshot</h2>
              <p className="mt-1 text-sm text-tertiary">A finalized snapshot is immutable and becomes the Assessment default.</p>
            </div>
            <button
              type="button"
              aria-label="Close dialog"
              disabled={saving}
              onClick={onClose}
              className="rounded-lg p-2 text-tertiary hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand disabled:opacity-50"
            >
              <XClose className="size-5" />
            </button>
          </div>

          <div className="space-y-5 p-6">
            {runs.loading && !runs.data ? <Spinner label="Loading scan runs…" /> : null}
            {runs.error ? <ErrorState message={runs.error} /> : null}
            {!runs.loading && !runs.error && selectable.length === 0 ? (
              <p className="rounded-lg border border-secondary bg-primary px-4 py-3 text-sm text-tertiary">
                No scan run with provenance lanes is available for this Assessment. Run a scan before finalizing a snapshot.
              </p>
            ) : null}

            {selectable.length > 0 ? (
              <fieldset className="space-y-2">
                <legend className="text-sm font-semibold text-primary">Scan runs to include</legend>
                <p className="text-xs text-tertiary">All provenance lanes of a selected run are included.</p>
                <ul className="mt-2 space-y-2">
                  {selectable.map((run) => (
                    <li key={run.id} className="rounded-lg border border-secondary p-3">
                      <label className="flex items-start gap-3 text-sm">
                        <input
                          type="checkbox"
                          className="mt-1"
                          checked={selected.includes(run.id)}
                          disabled={saving}
                          onChange={() => toggle(run.id)}
                          aria-label={`Include scan run ${run.id}`}
                        />
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-2">
                            <strong className="font-mono text-xs text-primary">{run.id}</strong>
                            <Pill>{run.laneCount} lane{run.laneCount === 1 ? '' : 's'}</Pill>
                            {run.completeCoverage ? <Pill className="text-success">Complete coverage</Pill> : <Pill className="text-warning">Partial coverage</Pill>}
                          </span>
                          <span className="mt-1 block text-xs text-tertiary">
                            {run.terminalStatus || 'unknown status'} · sealed {runTime(run.sealedAt)}
                          </span>
                        </span>
                      </label>
                    </li>
                  ))}
                </ul>
              </fieldset>
            ) : null}

            {error ? <ErrorState message={error} /> : null}

            <div className="flex justify-end gap-2">
              <Button variant="ghost" disabled={saving} onClick={onClose}>Cancel</Button>
              <Button loading={saving} disabled={selected.length === 0} onClick={() => void finalize()}>
                <Camera01 className="size-4" />
                Finalize snapshot
              </Button>
            </div>
          </div>
        </Dialog>
      </Modal>
    </ModalOverlay>
  )
}
