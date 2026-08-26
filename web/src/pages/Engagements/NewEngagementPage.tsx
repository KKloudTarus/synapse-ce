import type { FC } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { CreateEngagementForm } from './components/CreateEngagementForm'

export const NewEngagementPage: FC = () => {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const initialAssetId = searchParams.get('assetId') ?? ''

  return (
    <div className="mx-auto max-w-[1200px] animate-fade-in space-y-6">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 pb-2">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">
            New Engagement
          </h1>
          <p className="mt-1 text-sm text-secondary">
            Define an authorized assessment scope and connect it to a business Asset.
          </p>
        </div>

        <Link
          to="/engagements"
          className="inline-flex items-center justify-center rounded-lg border border-brand/40 bg-primary px-3.5 py-2 text-sm font-semibold text-brand-secondary shadow-xs transition hover:border-brand hover:bg-brand-primary/10 hover:text-brand-primary focus:outline-none focus:ring-2 focus:ring-brand/30"
        >
          Cancel
        </Link>
      </header>

      {/* Form */}
      <CreateEngagementForm
        initialAssetId={initialAssetId}
        onCreated={() => navigate('/engagements')}
      />
    </div>
  )
}
