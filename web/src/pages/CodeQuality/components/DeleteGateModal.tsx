import { Trash01, XClose } from '@untitledui/icons'
import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { Button, ErrorState } from '../../../components/ui'
import { api } from '../../../lib/api'
import type { QualityGate } from '../../../lib/types'

export function DeleteGateModal({
  gate,
  onClose,
  onDeleted,
}: {
  gate: QualityGate
  onClose: () => void
  onDeleted: () => void
}) {
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  async function handleDelete() {
    setDeleting(true)
    setError(null)
    try {
      await api.deleteQualityGate(gate.key)
      onDeleted()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete quality gate')
      setDeleting(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity" onClick={onClose} aria-hidden="true" />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="delete-gate-title"
        className="relative z-10 w-full max-w-md flex flex-col rounded-2xl border border-secondary bg-primary p-6 shadow-2xl overflow-hidden animate-scale-in text-left"
      >
        <div className="flex items-start gap-3.5">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-xl border border-utility-red-200 bg-utility-red-50 text-utility-red-600 dark:border-utility-red-800 dark:bg-utility-red-950/40 dark:text-utility-red-400 shadow-sm">
            <Trash01 className="size-5" aria-hidden="true" />
          </div>
          <div className="flex-1 min-w-0">
            <h2 id="delete-gate-title" className="text-base font-bold text-primary">
              Delete “{gate.name}”?
            </h2>
            <p className="mt-1 text-xs text-secondary leading-relaxed">
              Are you sure you want to delete this quality gate? Assigned quality gates cannot be deleted.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-lg p-1 text-tertiary transition hover:bg-secondary hover:text-primary shrink-0"
          >
            <XClose className="size-5" />
          </button>
        </div>

        {error && <div className="mt-4"><ErrorState message={error} /></div>}

        <div className="mt-6 flex items-center justify-end">
          <Button
            type="button"
            onClick={handleDelete}
            loading={deleting}
            className="h-9 px-5 text-xs font-semibold !bg-utility-red-600 !text-white hover:!bg-utility-red-700 shadow-xs"
          >
            Delete
          </Button>
        </div>
      </div>
    </div>,
    document.body
  )
}
