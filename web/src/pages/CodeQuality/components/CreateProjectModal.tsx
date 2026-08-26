import { Folder, GitBranch01, Upload01, XClose } from '@untitledui/icons'
import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { api } from '../../../lib/api'
import type { ProjectSourceKind } from '../../../lib/types'
import { Button, ErrorState, Field, Input, Select, cn } from '../../../components/ui'
import { slugify } from './projectCardHelpers'

const allowLocalSource = import.meta.env.DEV

export function CreateProjectModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated?: () => void
}) {
  const [name, setName] = useState('')
  const [key, setKey] = useState('')
  const [keyEdited, setKeyEdited] = useState(false)
  const [kind, setKind] = useState<ProjectSourceKind>('git')
  const [value, setValue] = useState('')
  const [ref, setRef] = useState('')
  const [archive, setArchive] = useState<File | null>(null)
  const [gateId, setGateId] = useState('')
  const [gates, setGates] = useState<{ key: string; name: string }[]>([])
  const [dragging, setDragging] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()
  const archiveInput = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  useEffect(() => {
    api.listQualityGates().then(setGates).catch(() => setGates([]))
  }, [])

  function chooseArchive(file: File | undefined) {
    if (!file) return
    if (!/\.(zip|tgz|tar\.gz)$/i.test(file.name)) {
      setError('Choose a .zip, .tar.gz, or .tgz archive.')
      return
    }
    if (file.size > 512 * 1024 * 1024) {
      setError('Archive must be 512 MiB or smaller.')
      return
    }
    setArchive(file)
    setError(null)
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!name.trim() || !key.trim() || (kind === 'archive' ? !archive : !value.trim())) {
      setError('Name, key, and source are required.')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      const project = kind === 'archive'
        ? await api.createProjectFromArchive(name.trim(), key.trim(), archive!, gateId)
        : await api.createProject({ name: name.trim(), key: key.trim(), sourceBinding: { kind, value: value.trim(), ref: kind === 'git' ? ref.trim() : '' }, gateId })
      onClose()
      onCreated?.()
      try {
        await api.startProjectAnalysis(project.key)
        navigate(`/code-quality/projects/${encodeURIComponent(project.key)}`)
      } catch (e) {
        navigate(`/code-quality/projects/${encodeURIComponent(project.key)}`, { state: { analysisStartError: e instanceof Error ? e.message : 'Failed to start analysis' } })
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create project')
    } finally {
      setSubmitting(false)
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
        aria-labelledby="create-project-title"
        className="relative z-10 w-full max-w-xl rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden animate-scale-in text-left"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4 bg-secondary/30">
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-xl border border-brand/30 bg-brand-primary/10 text-brand-secondary shadow-sm">
              <Folder className="size-5" aria-hidden="true" />
            </div>
            <div>
              <h2 id="create-project-title" className="text-base font-bold text-primary">
                New code quality project
              </h2>
              <p className="text-xs text-secondary">
                Create a project from Git{allowLocalSource ? ', local path,' : ''} or archive
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
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="Name" htmlFor="project-name">
              <Input
                id="project-name"
                value={name}
                onChange={(e) => {
                  setName(e.target.value)
                  if (!keyEdited) setKey(slugify(e.target.value))
                }}
                placeholder="Synapse CE"
                autoFocus
              />
            </Field>
            <Field label="Key" hint="Lowercase letters, numbers, hyphens" htmlFor="project-key">
              <Input
                id="project-key"
                className="font-mono text-xs"
                value={key}
                onChange={(e) => {
                  setKeyEdited(true)
                  setKey(e.target.value)
                }}
                placeholder="synapse-ce"
              />
            </Field>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-[10rem_1fr]">
            <Field label="Source kind" htmlFor="project-source-kind">
              <Select
                id="project-source-kind"
                value={kind}
                onValueChange={(next) => {
                  setKind(next as ProjectSourceKind)
                  setArchive(null)
                  setError(null)
                }}
                ariaLabel="Source kind"
                className="w-full"
                options={[
                  { value: 'git', label: 'Git URL' },
                  ...(allowLocalSource ? [{ value: 'local', label: 'Local path' }] : []),
                  { value: 'archive', label: 'Upload archive' },
                ]}
              />
            </Field>
            {kind === 'archive' ? (
              <Field label="Source archive" htmlFor="project-archive" hint=".zip, .tar.gz, or .tgz · max 512 MiB">
                <input
                  ref={archiveInput}
                  id="project-archive"
                  type="file"
                  accept=".zip,.tar.gz,.tgz"
                  className="sr-only"
                  onChange={(e) => {
                    chooseArchive(e.target.files?.[0])
                    e.target.value = ''
                  }}
                />
                <button
                  type="button"
                  onClick={() => archiveInput.current?.click()}
                  onDragEnter={(e) => {
                    e.preventDefault()
                    setDragging(true)
                  }}
                  onDragOver={(e) => e.preventDefault()}
                  onDragLeave={() => setDragging(false)}
                  onDrop={(e) => {
                    e.preventDefault()
                    setDragging(false)
                    chooseArchive(e.dataTransfer.files[0])
                  }}
                  className={cn(
                    'flex min-h-16 w-full items-center justify-center gap-2 rounded-lg border border-dashed px-4 text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
                    dragging
                      ? 'border-brand bg-brand-primary/10 text-primary'
                      : 'border-secondary bg-secondary/30 text-tertiary hover:border-brand/50',
                  )}
                >
                  <Upload01 className="size-4" aria-hidden="true" />
                  {archive ? `${archive.name} (${(archive.size / 1024 / 1024).toFixed(1)} MiB)` : 'Drop an archive here or choose a file'}
                </button>
              </Field>
            ) : (
              <Field label="Source" htmlFor="project-source">
                <Input
                  id="project-source"
                  className="font-mono text-xs"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder={kind === 'git' ? 'https://github.com/acme/app.git' : '/path/to/source'}
                />
              </Field>
            )}
          </div>

          {kind === 'git' && (
            <Field label="Branch or tag" hint="Optional; uses default branch when empty" htmlFor="project-ref">
              <Input
                id="project-ref"
                className="font-mono text-xs"
                value={ref}
                onChange={(e) => setRef(e.target.value)}
                placeholder="main"
              />
            </Field>
          )}

          <Field label="Quality policy" hint="Leave unassigned to allow repository .synapse-gate.yaml; otherwise Synapse way is used." htmlFor="project-gate">
            <select
              id="project-gate"
              value={gateId}
              onChange={(e) => setGateId(e.target.value)}
              className="h-9 w-full rounded-lg border border-secondary bg-primary px-3 text-xs text-primary focus:outline-none focus:ring-2 focus:ring-brand/60"
            >
              <option value="">Default / repository gate</option>
              {gates.map((gate) => (
                <option key={gate.key} value={gate.key}>
                  {gate.name}
                </option>
              ))}
            </select>
          </Field>

          {error && <ErrorState message={error} />}

          {/* Modal Footer: NO Cancel button, only Primary CTA */}
          <div className="mt-6 flex items-center justify-end pt-2">
            <Button
              variant="primary"
              type="submit"
              loading={submitting}
              className="!bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs"
            >
              <GitBranch01 className="size-4" aria-hidden="true" /> Create and analyze
            </Button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  )
}
