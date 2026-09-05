import type { ReactNode } from 'react'
import { AlertTriangle } from '@untitledui/icons'
import { Dialog, Modal, ModalOverlay } from '@/components/application/modals/modal'
import { Button } from '@/components/base/buttons/button'
import { ErrorState } from '../ui'

export interface ConfirmDialogProps {
  open: boolean
  title: string
  /** Body copy: say what changes and what cannot be undone. */
  description: ReactNode
  confirmLabel: string
  cancelLabel?: string
  /** `destructive` for terminal or irreversible transitions. */
  tone?: 'destructive' | 'brand'
  busy?: boolean
  error?: string | null
  onConfirm: () => void
  onCancel: () => void
}

/**
 * Confirmation for an irreversible action, on the shared React Aria `Modal` so
 * focus containment, `Escape`, and the labelled dialog role come for free.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  cancelLabel = 'Cancel',
  tone = 'destructive',
  busy = false,
  error = null,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  return (
    <ModalOverlay
      isOpen={open}
      onOpenChange={(next) => {
        if (!next && !busy) onCancel()
      }}
      isDismissable={!busy}
    >
      <Modal className="w-full max-w-md">
        <Dialog aria-label={title} className="p-5 sm:p-6">
          <div className="flex items-start gap-3">
            <span
              className={
                tone === 'destructive'
                  ? 'flex size-10 shrink-0 items-center justify-center rounded-full bg-error-primary text-fg-error-primary'
                  : 'flex size-10 shrink-0 items-center justify-center rounded-full bg-brand-primary text-brand-secondary'
              }
            >
              <AlertTriangle className="size-5" aria-hidden="true" />
            </span>
            <div className="min-w-0 space-y-1.5">
              <h2 className="text-md font-semibold text-primary">{title}</h2>
              <div className="text-sm text-tertiary">{description}</div>
            </div>
          </div>

          {error && (
            <div className="mt-4">
              <ErrorState message={error} />
            </div>
          )}

          <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button color="secondary" size="md" isDisabled={busy} onClick={onCancel}>
              {cancelLabel}
            </Button>
            <Button
              color={tone === 'destructive' ? 'primary-destructive' : 'primary'}
              size="md"
              isLoading={busy}
              isDisabled={busy}
              showTextWhileLoading
              onClick={onConfirm}
            >
              {confirmLabel}
            </Button>
          </div>
        </Dialog>
      </Modal>
    </ModalOverlay>
  )
}
