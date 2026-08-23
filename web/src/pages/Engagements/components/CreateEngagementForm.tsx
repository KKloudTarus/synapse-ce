import { useEffect, useMemo, useState, type FC, type FormEvent } from 'react'
import { Plus, Trash01, Check } from '@untitledui/icons'
import { api } from '../../../lib/api'
import { kindLabel } from '../../../lib/format'
import type { BusinessAsset, ScopeTarget } from '../../../lib/types'
import { Select } from '../../../components/ui'

const KINDS = ['repo', 'domain', 'host', 'url', 'image', 'cidr']

export interface CreateEngagementFormProps {
  initialAssetId?: string
  onCreated: () => void
}

export const CreateEngagementForm: FC<CreateEngagementFormProps> = ({
  initialAssetId,
  onCreated,
}) => {
  const [name, setName] = useState('')
  const [client, setClient] = useState('')
  const [scope, setScope] = useState<ScopeTarget[]>([{ kind: 'repo', value: '' }])
  const [authFrom, setAuthFrom] = useState('')
  const [authTo, setAuthTo] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [assets, setAssets] = useState<BusinessAsset[]>([])
  const [assetId, setAssetId] = useState(initialAssetId ?? '')

  useEffect(() => {
    let live = true
    api.listBusinessAssets('limit=200')
      .then((result) => {
        if (!live) return
        const assignable = result.items.filter((asset) => asset.lifecycle !== 'retired')
        setAssets(assignable)
        if (initialAssetId && !assignable.some((asset) => asset.id === initialAssetId)) {
          setAssetId('')
        }
      })
      .catch(() => {
        if (!live) return
        setAssets([])
        setAssetId('')
      })
    return () => {
      live = false
    }
  }, [initialAssetId])

  const assetOptions = useMemo(() => [
    { value: '__unassigned__', label: 'Unassigned' },
    ...assets.map((asset) => ({
      value: asset.id,
      label: `${asset.name} (${asset.key})`,
    })),
  ], [assets])

  const kindOptions = useMemo(() => KINDS.map((kind) => ({
    value: kind,
    label: kindLabel(kind),
  })), [])

  function setRow(index: number, patch: Partial<ScopeTarget>) {
    setScope((rows) => rows.map((row, rowIndex) => (rowIndex === index ? { ...row, ...patch } : row)))
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    const inScope = scope.filter((row) => row.value.trim() !== '')
    if (!name.trim()) {
      setError('Name is required.')
      return
    }
    if (inScope.length === 0) {
      setError('Add at least one in-scope target.')
      return
    }
    if (assetId && !assets.some((asset) => asset.id === assetId)) {
      setError('Select a valid Asset.')
      return
    }
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone
    const from = authFrom ? new Date(authFrom).toISOString() : undefined
    const to = authTo ? new Date(authTo).toISOString() : undefined
    if (from && to && new Date(from) >= new Date(to)) {
      setError('Authorization start must be before end.')
      return
    }

    setSubmitting(true)
    setError(null)
    try {
      await api.createEngagement({
        name: name.trim(),
        client: client.trim(),
        inScope,
        outOfScope: [],
        authorizedFrom: from,
        authorizedTo: to,
        timezone: from || to ? timezone : undefined,
        assetId,
      })
      onCreated()
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : 'Failed to create engagement')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="rounded-xl border border-secondary bg-primary p-6 shadow-xs sm:p-8">
      <header className="mb-6 border-b border-secondary pb-4">
        <h2 className="text-lg font-bold text-primary sm:text-xl">Engagement details</h2>
        <p className="mt-1 text-xs text-tertiary">
          Configure testing parameters, target scopes, and asset linkage.
        </p>
      </header>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Step 1: Assessment Context */}
        <div>
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-primary">
            <span className="flex size-6 items-center justify-center rounded-full bg-brand-solid text-xs font-bold text-white">
              1
            </span>
            Assessment context
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
            <div>
              <label htmlFor="engagement-name-input" className="block text-xs font-medium text-secondary">
                Name <span className="text-utility-red-600">*</span>
              </label>
              <input
                id="engagement-name-input"
                type="text"
                disabled={submitting}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="acme-q3-2026"
                autoFocus
                required
                className="mt-1.5 h-10 w-full rounded-lg border border-primary bg-primary px-3.5 py-2 text-sm text-primary shadow-xs outline-none focus:border-brand focus:ring-2 focus:ring-brand/20 disabled:cursor-not-allowed disabled:opacity-50"
              />
            </div>

            <div>
              <label htmlFor="engagement-client-input" className="block text-xs font-medium text-secondary">
                Client <span className="text-tertiary">(Optional)</span>
              </label>
              <input
                id="engagement-client-input"
                type="text"
                disabled={submitting}
                value={client}
                onChange={(e) => setClient(e.target.value)}
                placeholder="Acme Corp"
                className="mt-1.5 h-10 w-full rounded-lg border border-primary bg-primary px-3.5 py-2 text-sm text-primary shadow-xs outline-none focus:border-brand focus:ring-2 focus:ring-brand/20 disabled:cursor-not-allowed disabled:opacity-50"
              />
            </div>

            <div>
              <label htmlFor="engagement-asset-select" className="block text-xs font-medium text-secondary">
                Asset <span className="text-tertiary">(Optional)</span>
              </label>
              <Select
                id="engagement-asset-select"
                disabled={submitting}
                value={assetId || '__unassigned__'}
                onValueChange={(val) => setAssetId(val === '__unassigned__' ? '' : val)}
                options={assetOptions}
                className="mt-1.5 h-10 w-full border-primary bg-primary shadow-xs"
              />
            </div>
          </div>
        </div>

        {/* Step 2: In-Scope Targets */}
        <div className="border-t border-secondary pt-6">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-primary">
            <span className="flex size-6 items-center justify-center rounded-full bg-brand-solid text-xs font-bold text-white">
              2
            </span>
            In-scope targets
          </div>

          <div className="space-y-2.5">
            {scope.map((row, index) => (
              <div key={index} className="flex items-center gap-2">
                <Select
                  disabled={submitting}
                  value={row.kind}
                  onValueChange={(val) => setRow(index, { kind: val })}
                  ariaLabel={`Target kind for row ${index + 1}`}
                  options={kindOptions}
                  className="h-10 w-32 shrink-0 border-primary bg-primary shadow-xs"
                />

                <input
                  type="text"
                  disabled={submitting}
                  value={row.value}
                  onChange={(e) => setRow(index, { value: e.target.value })}
                  placeholder="/path/to/repo or app.acme.io"
                  aria-label={`Target value for row ${index + 1}`}
                  className="h-10 flex-1 font-mono rounded-lg border border-primary bg-primary px-3.5 py-2 text-sm text-primary shadow-xs outline-none focus:border-brand focus:ring-2 focus:ring-brand/20 disabled:cursor-not-allowed disabled:opacity-50"
                />

                {scope.length > 1 && (
                  <button
                    type="button"
                    disabled={submitting}
                    onClick={() => setScope((rows) => rows.filter((_, rowIndex) => rowIndex !== index))}
                    aria-label={`Remove target row ${index + 1}`}
                    className="flex size-10 items-center justify-center rounded-lg text-tertiary transition hover:bg-secondary hover:text-utility-red-600 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <Trash01 className="size-4" />
                  </button>
                )}
              </div>
            ))}

            <button
              type="button"
              disabled={submitting}
              onClick={() => setScope((rows) => [...rows, { kind: 'repo', value: '' }])}
              className="inline-flex items-center gap-1.5 pt-1 text-xs font-semibold text-brand-secondary transition hover:text-brand-primary disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Plus className="size-3.5" />
              Add target
            </button>
          </div>
        </div>

        {/* Step 3: Authorization Window */}
        <div className="border-t border-secondary pt-6">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-primary">
            <span className="flex size-6 items-center justify-center rounded-full bg-brand-solid text-xs font-bold text-white">
              3
            </span>
            Authorization window
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label htmlFor="auth-from-input" className="block text-xs font-medium text-secondary">
                Authorized from <span className="text-tertiary">(Optional)</span>
              </label>
              <input
                id="auth-from-input"
                type="datetime-local"
                disabled={submitting}
                value={authFrom}
                onChange={(e) => setAuthFrom(e.target.value)}
                className="mt-1.5 w-full rounded-lg border border-primary bg-primary px-3.5 py-2 text-sm text-primary shadow-xs outline-none focus:border-brand focus:ring-2 focus:ring-brand/20 disabled:cursor-not-allowed disabled:opacity-50"
              />
            </div>

            <div>
              <label htmlFor="auth-to-input" className="block text-xs font-medium text-secondary">
                Authorized to <span className="text-tertiary">(Optional)</span>
              </label>
              <input
                id="auth-to-input"
                type="datetime-local"
                disabled={submitting}
                value={authTo}
                onChange={(e) => setAuthTo(e.target.value)}
                className="mt-1.5 w-full rounded-lg border border-primary bg-primary px-3.5 py-2 text-sm text-primary shadow-xs outline-none focus:border-brand focus:ring-2 focus:ring-brand/20 disabled:cursor-not-allowed disabled:opacity-50"
              />
            </div>
          </div>
        </div>

        {error && (
          <div className="rounded-lg border border-utility-red-200 bg-utility-red-50 p-3 text-xs font-medium text-utility-red-700 dark:border-utility-red-800 dark:bg-utility-red-950/40 dark:text-utility-red-300">
            {error}
          </div>
        )}

        <div className="flex items-center justify-end gap-3 border-t border-secondary pt-6">
          <button
            type="submit"
            disabled={submitting}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-brand-solid px-4 py-2.5 text-sm font-semibold text-white shadow-xs transition hover:bg-brand-solid_hover focus:outline-none focus:ring-2 focus:ring-brand/30 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? (
              <div className="size-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
            ) : (
              <Check className="size-4" />
            )}
            Create Engagement
          </button>
        </div>
      </form>
    </div>
  )
}
