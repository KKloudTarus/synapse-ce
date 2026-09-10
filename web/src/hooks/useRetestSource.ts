import { useEffect, useState } from 'react'
import { api, ApiError } from '../lib/api'
import type { CreateAssessmentRetestInput, UploadedSourcePackage } from '../lib/types'

export const MAX_SOURCE_BYTES = 512 * 1024 * 1024
export function sourceArchiveError(file?: File): string {
  if (!file) return 'Choose a source archive to upload.'
  return /\.(zip|tar|tar\.gz|tgz)$/i.test(file.name) && file.size > 0 && file.size <= MAX_SOURCE_BYTES
    ? '' : 'Choose a non-empty ZIP or TAR source archive up to 512 MiB.'
}

type SourceStrategy = 'reuse_current' | 'upload_new'
type Lookup = { assessmentId: string; loading: boolean; source: UploadedSourcePackage | null; uploaded: boolean; error: string }
type Selection = { assessmentId: string; strategy: SourceStrategy; file?: File }

export function useRetestSource(assessmentId: string) {
  const [lookup, setLookup] = useState<Lookup>({ assessmentId: '', loading: false, source: null, uploaded: false, error: '' })
  const [selection, setSelection] = useState<Selection>({ assessmentId: '', strategy: 'reuse_current' })
  const [retry, setRetry] = useState(0)
  useEffect(() => { setSelection({ assessmentId, strategy: 'reuse_current' }) }, [assessmentId])
  useEffect(() => {
    if (!assessmentId) return
    let live = true
    setLookup({ assessmentId, loading: true, source: null, uploaded: false, error: '' })
    api.uploadedSource(assessmentId).then((source) => {
      if (live) setLookup({ assessmentId, loading: false, source, uploaded: Boolean(source), error: '' })
    }).catch(async (cause) => {
      if (!live) return
      if (cause instanceof ApiError && cause.status === 404) {
        try {
          // A legacy upload may have lost its archive metadata. Its frozen
          // scope still distinguishes it from a genuine linked/git/image source.
          const engagement = await api.getEngagement(assessmentId)
          const uploaded = engagement.inScope.some((target) => target.kind === 'repo' && /^uploaded-source\/sha256\/[0-9a-f]{64}$/.test(target.value.trim()))
          if (live) setLookup({ assessmentId, loading: false, source: null, uploaded, error: '' })
          return
        } catch (failure) { cause = failure }
      }
      if (live) setLookup({ assessmentId, loading: false, source: null, uploaded: false,
        error: cause instanceof Error ? cause.message : 'Could not load the predecessor source.',
      })
    })
    return () => { live = false }
  }, [assessmentId, retry])

  // Never expose the previous predecessor's archive during the render before
  // the next lookup starts or when an earlier request resolves out of order.
  const current = lookup.assessmentId === assessmentId ? lookup : null
  const chosen = selection.assessmentId === assessmentId ? selection : { assessmentId, strategy: 'reuse_current' as const, file: undefined }
  const loading = Boolean(assessmentId) && (!current || current.loading)
  const source = current?.source ?? null
  const hasUploadedSource = Boolean(source) || current?.uploaded === true
  const strategy: SourceStrategy = hasUploadedSource && !source ? 'upload_new' : chosen.strategy
  const error = current?.error ?? ''
  const changeStrategy = (strategy: SourceStrategy) => setSelection({ assessmentId, strategy })
  const chooseFile = (file?: File) => setSelection({ assessmentId, strategy: 'upload_new', file })
  const validationError = (scopeStrategy: 'copy' | 'empty') => {
    if (loading) return 'Wait for the predecessor source to load.'
    if (error) return 'Retry loading the predecessor source before creating a Re-test.'
    if (!hasUploadedSource) return ''
    if (scopeStrategy !== 'copy') return 'An uploaded-source Re-test must copy the frozen scope.'
    return strategy === 'upload_new' ? sourceArchiveError(chosen.file) : ''
  }
  const input: Pick<CreateAssessmentRetestInput, 'source' | 'sourceStrategy' | 'sourceVersionId'> = hasUploadedSource ? {
    sourceStrategy: strategy,
    sourceVersionId: strategy === 'reuse_current' ? source?.versionId : undefined,
    source: strategy === 'upload_new' ? chosen.file : undefined,
  } : {}
  return { assessmentId, source, hasUploadedSource, loading, error, strategy, file: chosen.file, input, validationError, changeStrategy, chooseFile, refetch: () => setRetry((value) => value + 1) }
}
