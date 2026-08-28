import { useCallback, useEffect, useRef, useState, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../../lib/api'
import { hasActiveRuleFilters, parseRuleFilters, serializeRuleFilters } from '../../lib/ruleFilters'
import { deriveRuleFacets } from '../../lib/ruleFormat'
import type { RuleFacets, RuleSummary } from '../../lib/types'

export type FilterKey = 'languages' | 'types' | 'severities' | 'tags' | 'cwe'

export function useRulesSearch() {
  const [params, setParams] = useSearchParams()
  const filters = useMemo(() => parseRuleFilters(params), [params])
  const activeFilters = hasActiveRuleFilters(filters)

  const [catalogRules, setCatalogRules] = useState<RuleSummary[]>([])
  const [catalogLoading, setCatalogLoading] = useState(true)
  const [catalogError, setCatalogError] = useState<string | null>(null)
  const [facets, setFacets] = useState<RuleFacets>({ languages: [], types: [], severities: [], tags: [], cwe: [] })

  const [resultRules, setResultRules] = useState<RuleSummary[]>([])
  const [resultLoading, setResultLoading] = useState(false)
  const [resultError, setResultError] = useState<string | null>(null)

  const [filteredRetryVersion, setFilteredRetryVersion] = useState(0)
  const reqSeq = useRef(0)
  const searchInputRef = useRef<HTMLInputElement>(null)

  const [query, setQuery] = useState(filters.query)

  useEffect(() => {
    setQuery(filters.query)
  }, [filters.query])

  useEffect(() => {
    const timeout = setTimeout(() => {
      if (query !== filters.query) {
        const nextFilters = { ...filters, query }
        setParams(serializeRuleFilters(nextFilters), { replace: true })
      }
    }, 250)
    return () => clearTimeout(timeout)
  }, [query, filters, setParams])

  const loadCatalog = useCallback(() => {
    let active = true
    setCatalogLoading(true)
    setCatalogError(null)

    api.listRules()
      .then((res) => {
        if (!active) return
        setCatalogRules(res)
        setFacets(deriveRuleFacets(res))
      })
      .catch((err) => {
        if (!active) return
        setCatalogError(err instanceof ApiError ? err.message : 'An error occurred')
      })
      .finally(() => {
        if (active) setCatalogLoading(false)
      })

    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    const cleanup = loadCatalog()
    return cleanup
  }, [loadCatalog])

  // Sync catalogRules → resultRules when no filters are active.
  useEffect(() => {
    if (!activeFilters) {
      setResultRules(catalogRules)
      setResultError(null)
      setResultLoading(false)
    }
  }, [activeFilters, catalogRules])

  // Filtered request — does NOT depend on catalogRules.
  const canonicalFilterKey = params.toString()
  useEffect(() => {
    if (!activeFilters) return

    let active = true
    const seq = ++reqSeq.current
    setResultError(null)
    setResultLoading(true)

    api.listRules(filters)
      .then((res) => {
        if (!active || seq !== reqSeq.current) return
        setResultRules(res)
      })
      .catch((err) => {
        if (!active || seq !== reqSeq.current) return
        setResultError(err instanceof ApiError ? err.message : 'An error occurred')
      })
      .finally(() => {
        if (active && seq === reqSeq.current) setResultLoading(false)
      })

    return () => {
      active = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeFilters, canonicalFilterKey, filteredRetryVersion])

  const handleFilterChange = (key: FilterKey, value: string[]) => {
    const nextFilters = { ...filters, [key]: value }
    setParams(serializeRuleFilters(nextFilters))
  }

  const removeChip = (key: FilterKey, val: string) => {
    const nextFilters = { ...filters, [key]: filters[key].filter(v => v !== val) }
    setParams(serializeRuleFilters(nextFilters))
  }

  const clearQuery = () => {
    setQuery('')
    const nextFilters = { ...filters, query: '' }
    setParams(serializeRuleFilters(nextFilters))
    searchInputRef.current?.focus()
  }

  const clearAllFilters = () => {
    setQuery('')
    setParams(new URLSearchParams())
  }

  const retryFiltered = () => setFilteredRetryVersion((v) => v + 1)

  return {
    params,
    filters,
    activeFilters,
    catalogRules,
    catalogLoading,
    catalogError,
    facets,
    resultRules,
    resultLoading,
    resultError,
    query,
    setQuery,
    searchInputRef,
    loadCatalog,
    handleFilterChange,
    removeChip,
    clearQuery,
    clearAllFilters,
    retryFiltered,
  }
}
