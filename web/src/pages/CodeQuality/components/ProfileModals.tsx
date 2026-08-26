import { Copy01, Link01, Plus, Trash01, XClose } from '@untitledui/icons'
import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { Button, ErrorState, Input } from '../../../components/ui'
import { api, ApiError } from '../../../lib/api'
import type { QualityProfile } from '../../../lib/types'

export function CopyProfileModal({
  profile,
  onClose,
  onDone,
  onError,
}: {
  profile: QualityProfile
  onClose: () => void
  onDone: () => void
  onError: (m: string) => void
}) {
  const [key, setKey] = useState('')
  const [name, setName] = useState('')
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    const cleanKey = key.trim()
    const cleanName = name.trim()

    if (!cleanKey || !cleanName) {
      setFormError('Both key and name are required.')
      return
    }

    setSaving(true)
    setFormError(null)
    try {
      await api.copyQualityProfile(profile.key, cleanKey, cleanName)
      onDone()
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to copy quality profile'
      setFormError(msg)
      onError(msg)
    } finally {
      setSaving(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="copy-modal-title"
        className="relative z-10 w-full max-w-lg rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden animate-scale-in text-left"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4 bg-secondary/30">
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-xl border border-brand/30 bg-brand-primary/10 text-brand-secondary shadow-sm">
              <Copy01 className="size-5" aria-hidden="true" />
            </div>
            <div>
              <h2 id="copy-modal-title" className="text-base font-bold text-primary">
                Copy Quality Profile
              </h2>
              <p className="text-xs text-secondary">
                Duplicate rules from &quot;{profile.name}&quot; ({profile.language})
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-lg p-1.5 text-tertiary transition hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
          >
            <XClose className="size-4" />
          </button>
        </div>

        {/* Modal Body */}
        <form onSubmit={submit} className="p-6 space-y-4">
          {formError && <ErrorState message={formError} />}

          <label htmlFor="copy-key" className="block space-y-1.5">
            <div className="flex items-center justify-between text-xs font-semibold text-secondary">
              <span>New Profile Key</span>
              <span className="font-mono text-[11px] font-normal text-tertiary">lowercase-hyphenated</span>
            </div>
            <Input
              id="copy-key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder={`custom-${profile.language.toLowerCase()}`}
              className="h-9 text-xs"
              autoFocus
            />
          </label>

          <label htmlFor="copy-name" className="block space-y-1.5">
            <span className="text-xs font-semibold text-secondary">Profile Display Name</span>
            <Input
              id="copy-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={`Custom ${profile.language.toUpperCase()}`}
              className="h-9 text-xs"
            />
          </label>

          {/* Modal Footer */}
          <div className="mt-6 flex items-center justify-end gap-3 pt-2">
            <Button
              variant="primary"
              type="submit"
              loading={saving}
              className="!bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs"
            >
              <Plus className="size-4" aria-hidden="true" /> Create copy
            </Button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  )
}

export function AssignProfileModal({
  profile,
  onClose,
  onDone,
  onError,
}: {
  profile: QualityProfile
  onClose: () => void
  onDone: () => void
  onError: (m: string) => void
}) {
  const [projectKey, setProjectKey] = useState('')
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    const cleanProject = projectKey.trim()

    if (!cleanProject) {
      setFormError('Project key is required.')
      return
    }

    setSaving(true)
    setFormError(null)
    try {
      await api.assignProjectProfile(cleanProject, profile.language, profile.key)
      onDone()
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to assign profile to project'
      setFormError(msg)
      onError(msg)
    } finally {
      setSaving(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="assign-modal-title"
        className="relative z-10 w-full max-w-lg rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden animate-scale-in text-left"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4 bg-secondary/30">
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-xl border border-brand/30 bg-brand-primary/10 text-brand-secondary shadow-sm">
              <Link01 className="size-5" aria-hidden="true" />
            </div>
            <div>
              <h2 id="assign-modal-title" className="text-base font-bold text-primary">
                Assign Profile to Project
              </h2>
              <p className="text-xs text-secondary">
                Set &quot;{profile.name}&quot; for language <strong>{profile.language}</strong>
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-lg p-1.5 text-tertiary transition hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
          >
            <XClose className="size-4" />
          </button>
        </div>

        {/* Modal Body */}
        <form onSubmit={submit} className="p-6 space-y-4">
          {formError && <ErrorState message={formError} />}

          <label htmlFor="assign-project-key" className="block space-y-1.5">
            <div className="flex items-center justify-between text-xs font-semibold text-secondary">
              <span>Target Project Key</span>
              <span className="font-mono text-[11px] font-normal text-tertiary">e.g. backend-service</span>
            </div>
            <Input
              id="assign-project-key"
              value={projectKey}
              onChange={(e) => setProjectKey(e.target.value)}
              placeholder="my-project-key"
              className="h-9 text-xs"
              autoFocus
            />
          </label>

          {/* Modal Footer */}
          <div className="mt-6 flex items-center justify-end gap-3 pt-2">
            <Button
              variant="primary"
              type="submit"
              loading={saving}
              className="!bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs"
            >
              <Link01 className="size-4" aria-hidden="true" /> Assign profile
            </Button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  )
}

export function DeleteProfileModal({
  profile,
  onClose,
  onDeleted,
  onError,
}: {
  profile: QualityProfile
  onClose: () => void
  onDeleted: () => void
  onError: (m: string) => void
}) {
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  async function handleDelete() {
    setSaving(true)
    setFormError(null)
    try {
      await api.deleteQualityProfile(profile.key)
      onDeleted()
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to delete quality profile'
      setFormError(msg)
      onError(msg)
    } finally {
      setSaving(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="delete-profile-title"
        className="relative z-10 w-full max-w-md rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden animate-scale-in text-left"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4 bg-secondary/30">
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-xl border border-error bg-error-primary/10 text-error-primary shadow-sm">
              <Trash01 className="size-5 text-fg-error-primary" aria-hidden="true" />
            </div>
            <div>
              <h2 id="delete-profile-title" className="text-base font-bold text-primary">
                Delete Quality Profile
              </h2>
              <p className="text-xs text-secondary">This action cannot be undone.</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-lg p-1.5 text-tertiary transition hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
          >
            <XClose className="size-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4">
          {formError && <ErrorState message={formError} />}

          <p className="text-xs text-secondary leading-relaxed">
            Are you sure you want to permanently delete custom profile{' '}
            <strong className="text-primary font-semibold">&quot;{profile.name}&quot;</strong> (
            <span className="font-mono text-xs">{profile.key}</span>)?
          </p>
          <p className="text-xs text-tertiary">
            Any projects previously assigned to this profile will fall back to the built-in default for {profile.language}.
          </p>

          {/* Modal Footer */}
          <div className="mt-6 flex items-center justify-end gap-3 pt-2">
            <Button
              variant="danger"
              type="button"
              loading={saving}
              onClick={handleDelete}
              className="bg-error-solid text-white hover:bg-error-solid/90 shadow-xs"
            >
              <Trash01 className="size-4" aria-hidden="true" /> Delete profile
            </Button>
          </div>
        </div>
      </div>
    </div>,
    document.body,
  )
}
