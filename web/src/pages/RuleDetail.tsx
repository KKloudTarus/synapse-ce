import { ArrowLeft, AlertCircle, RefreshCw, SearchX } from 'lucide-react'
import { useEffect, useState, useCallback } from 'react'
import { Link, useParams, useLocation } from 'react-router-dom'
import { api, ApiError } from '../lib/api'
import type { RuleDetail } from '../lib/types'
import { EmptyState, Spinner } from '../components/ui'
import { RuleMetadata } from '../components/rules/RuleMetadata'
import { RuleExamples } from '../components/rules/RuleExamples'

export default function RuleDetailPage() {
  const { key } = useParams<{ key: string }>()
  const location = useLocation()
  const from = location.state?.from || ''

  const [rule, setRule] = useState<RuleDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<{ status: number, message: string } | null>(null)

  const loadRule = useCallback(() => {
    if (!key) return
    let active = true
    setLoading(true)
    setError(null)

    api.getRule(key)
      .then((res) => {
        if (!active) return
        setRule(res)
      })
      .catch((err) => {
        if (!active) return
        if (err instanceof ApiError) {
          setError({ status: err.status, message: err.message })
        } else {
          setError({ status: 500, message: 'An error occurred' })
        }
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [key])

  useEffect(() => {
    const cleanup = loadRule()
    return cleanup
  }, [loadRule])

  if (error) {
    if (error.status === 404) {
      return (
        <div className="mx-auto max-w-4xl animate-fade-in">
          <Link
            to={`/rules${from}`}
            className="mb-6 inline-flex items-center gap-2 self-start text-sm font-medium text-mutedfg transition-colors hover:text-foreground"
          >
            <ArrowLeft className="size-4" />
            Back to rules
          </Link>
          <EmptyState
            icon={SearchX}
            title="Rule not found"
            hint="The requested rule key does not exist in the catalog."
            action={
              <div className="mt-4 flex items-center justify-center gap-3">
                <Link
                  to={`/rules${from}`}
                  className="rounded-lg border border-border bg-transparent px-4 py-2 text-sm font-medium text-foreground hover:bg-surface focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
                >
                  Back to rules
                </Link>
                <button
                  type="button"
                  onClick={() => loadRule()}
                  className="rounded-lg bg-brand px-4 py-2 text-sm font-medium text-brandfg hover:bg-brand/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-surface inline-flex items-center gap-2"
                >
                  <RefreshCw className="size-4" />
                  Retry
                </button>
              </div>
            }
          />
        </div>
      )
    }

    return (
      <div className="mx-auto max-w-4xl animate-fade-in">
        <Link
          to={`/rules${from}`}
          className="mb-6 inline-flex items-center gap-2 self-start text-sm font-medium text-mutedfg transition-colors hover:text-foreground"
        >
          <ArrowLeft className="size-4" />
          Back to rules
        </Link>
        <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-6 text-center text-red-600 dark:text-red-400">
          <AlertCircle className="mx-auto mb-3 size-6" />
          <h2 className="text-lg font-semibold">Failed to load rule details</h2>
          <p className="mt-2 text-sm">{error.message}</p>
          <button
            onClick={() => loadRule()}
            className="mt-6 inline-flex items-center gap-2 rounded-lg bg-red-500/10 px-4 py-2 text-sm font-medium text-red-600 transition-colors hover:bg-red-500/20 dark:text-red-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
          >
            <RefreshCw className="size-4" />
            Retry
          </button>
        </div>
      </div>
    )
  }

  if (loading || !rule) {
    return (
      <div className="mx-auto max-w-4xl animate-fade-in">
        <Link
          to={`/rules${from}`}
          className="mb-6 inline-flex items-center gap-2 self-start text-sm font-medium text-mutedfg transition-colors hover:text-foreground"
        >
          <ArrowLeft className="size-4" />
          Back to rules
        </Link>
        <div className="flex h-40 items-center justify-center">
          <Spinner className="size-6 text-brand" />
        </div>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-4xl animate-fade-in pb-12">
      <Link
        to={`/rules${from}`}
        className="mb-6 inline-flex items-center gap-2 self-start text-sm font-medium text-mutedfg transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-surface rounded-sm"
      >
        <ArrowLeft className="size-4" />
        Back to rules
      </Link>

      <header className="mb-8">
        <div className="mb-2 flex items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight text-foreground">{rule.name}</h1>
          <span className="rounded-md bg-elevated px-2 py-1 font-mono text-xs font-medium text-mutedfg border border-border">
            {rule.key}
          </span>
        </div>
        <RuleMetadata rule={rule} variant="detail" />
      </header>

      <div className="space-y-8">
        <section>
          <h2 className="mb-3 text-lg font-semibold text-foreground">Description</h2>
          <div className="prose prose-sm prose-zinc dark:prose-invert max-w-none text-mutedfg">
            {rule.description}
          </div>
        </section>

        {rule.rationale && (
          <section>
            <h2 className="mb-3 text-lg font-semibold text-foreground">Rationale</h2>
            <div className="prose prose-sm prose-zinc dark:prose-invert max-w-none text-mutedfg">
              {rule.rationale}
            </div>
          </section>
        )}

        {rule.remediation && (
          <section>
            <h2 className="mb-3 text-lg font-semibold text-foreground">Remediation</h2>
            <div className="prose prose-sm prose-zinc dark:prose-invert max-w-none text-mutedfg">
              {rule.remediation}
            </div>
          </section>
        )}

        <RuleExamples compliant={rule.compliantExample} noncompliant={rule.noncompliantExample} />
      </div>
    </div>
  )
}
