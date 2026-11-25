import { useState } from 'react'
import { XClose } from '@untitledui/icons'
import { Dialog, Modal, ModalOverlay } from '../../components/application/modals/modal'
import { Button, ErrorState, Field, Input, Select, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { ApiError, api } from '../../lib/api'
import type { Finding, ImportedFinding } from '../../lib/types'

/**
 * Records the decision that an imported observation and a canonical finding describe one issue.
 *
 * The decision is the point, so the dialog refuses to submit without a reason: a binding with no reason
 * is indistinguishable from the automatic merge this whole surface exists to prevent. When the row is
 * already approved, the current version is sent back as expected_version, which is what makes a stale
 * view fail loudly instead of overwriting whatever was decided in between.
 */
export function ApproveBindingDialog({
  engagementId,
  observation,
  onClose,
  onDecided,
}: {
  engagementId: string
  observation: ImportedFinding
  onClose: () => void
  onDecided: () => void
}) {
  const findings = useFetch<Finding[]>(() => api.findings(engagementId), { deps: [engagementId] })
  const rebinding = observation.binding === 'approved'
  const [findingId, setFindingId] = useState(rebinding ? observation.approvedFindingId : observation.findingId)
  const [reason, setReason] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const items = findings.data ?? []

  async function submit() {
    if (!findingId || reason.trim() === '') return
    setSaving(true)
    setError('')
    try {
      await api.bindObservation(engagementId, observation.id, {
        findingId,
        reason: reason.trim(),
        ...(rebinding ? { expectedVersion: observation.bindingVersion } : {}),
      })
      onDecided()
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 409) {
        setError(
          'This observation was decided by someone else while this dialog was open. Close it, refresh the tab, and read their reason before deciding again.',
        )
      } else if (cause instanceof ApiError && cause.status === 403) {
        setError('Recording a binding requires the operate capability, which this account does not hold.')
      } else if (cause instanceof ApiError && cause.status === 404) {
        setError('The finding or the observation is no longer in this engagement.')
      } else if (cause instanceof ApiError && cause.status === 400) {
        setError(
          cause.message ||
            'The server refused this decision. An observation needs a rule and a location, or a fingerprint from its tool, before it can be bound.',
        )
      } else {
        setError(cause instanceof Error ? cause.message : 'Recording the decision failed.')
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <ModalOverlay isOpen isDismissable={!saving} onOpenChange={(open) => { if (!open && !saving) onClose() }}>
      <Modal className="w-full max-w-2xl">
        <Dialog aria-label="Approve this observation onto a finding">
          <div className="flex items-start justify-between gap-3 border-b border-secondary px-6 py-4">
            <div>
              <h2 className="text-lg font-semibold text-primary">
                {rebinding ? 'Change the approved finding' : 'Approve onto a finding'}
              </h2>
              <p className="mt-1 text-sm text-tertiary">
                {rebinding
                  ? 'The version this replaces is kept, so the decision you are changing stays readable.'
                  : 'A match on file and line is evidence. This records that you decided the two are one issue.'}
              </p>
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
            <div className="rounded-lg border border-secondary bg-primary px-4 py-3 text-sm">
              <div className="font-medium text-primary">{observation.title || observation.rule}</div>
              <div className="mt-1 font-mono text-[12px] text-tertiary">
                {observation.tool} · {observation.rule}
                {observation.path ? ` · ${observation.path}:${observation.startLine}` : ''}
              </div>
            </div>

            {findings.loading && !findings.data ? <Spinner label="Loading findings" /> : null}
            {findings.error ? <ErrorState message={findings.error} /> : null}

            {!findings.loading && items.length === 0 ? (
              <p className="rounded-lg border border-secondary bg-primary px-4 py-3 text-sm text-tertiary">
                This engagement has no first-party finding yet. Run a scan, or author a finding, before deciding that an
                imported result belongs to one.
              </p>
            ) : null}

            {items.length > 0 ? (
              <Field label="Canonical finding" htmlFor="binding-finding">
                <Select
                  id="binding-finding"
                  value={findingId}
                  onValueChange={setFindingId}
                  disabled={saving}
                  placeholder="Choose a finding"
                  ariaLabel="Canonical finding"
                  options={items.map((item) => ({ value: item.id, label: item.title }))}
                />
              </Field>
            ) : null}

            <Field
              label="Reason"
              htmlFor="binding-reason"
              hint="Stored with your name and kept when the decision is later replaced. It cannot be edited afterwards."
            >
              <Input
                id="binding-reason"
                value={reason}
                maxLength={2000}
                placeholder="Why these two describe one issue"
                onChange={(event) => setReason(event.target.value)}
                disabled={saving}
              />
            </Field>

            {error ? <ErrorState message={error} /> : null}
          </div>

          <div className="flex justify-end gap-2 border-t border-secondary px-6 py-4">
            <Button variant="secondary" onClick={onClose} disabled={saving}>
              Cancel
            </Button>
            <Button onClick={submit} loading={saving} disabled={saving || !findingId || reason.trim() === ''}>
              {rebinding ? 'Replace the decision' : 'Record the decision'}
            </Button>
          </div>
        </Dialog>
      </Modal>
    </ModalOverlay>
  )
}
