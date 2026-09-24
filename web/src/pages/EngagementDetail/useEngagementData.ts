import { useEffect, useState } from 'react'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import type {
  Engagement,
  Finding,
  ImportedSBOMMetadata,
  ScanJob,
  ScanResult,
  UploadedSourcePackage,
} from '../../lib/types'

export interface EngagementData {
  eng: Engagement | null | undefined
  /** Lets a tab patch the engagement in place after a write, without a refetch. */
  setEng: (next: Engagement | null | undefined) => void
  engLoading: boolean
  engError: string | null
  findings: Finding[] | null
  /** Replaces the whole list, for a scan that returns its own findings. */
  setFindings: (next: Finding[] | null) => void
  findingsError: string | null
  scan: ScanResult | null
  scanError: string | null
  setScan: (next: ScanResult | null) => void
  job: ScanJob | null
  setJob: (next: ScanJob | null) => void
  importedSBOM: ImportedSBOMMetadata | null
  uploadedSource: UploadedSourcePackage | null
  uploadedSourceError: string | null
  /** Replaces one finding in place with the server's updated row. */
  applyFinding: (updated: Finding) => void
  reloadFindings: () => void
  /** Re-pulls engagement, scan, findings and SBOM after an import or a VEX apply. */
  refreshAll: () => void
  refetchUploadedSource: () => void
}

/**
 * Loads everything the engagement screen renders.
 *
 * Kept out of the screen component so the component decides what to show and this decides what to
 * fetch. The error of each read is returned rather than folded into an empty value: a findings
 * failure rendered as an empty list tells the operator the engagement is clean when the screen
 * does not know, which is the worst thing a security dashboard can say.
 */
export function useEngagementData(id: string): EngagementData {
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [job, setJob] = useState<ScanJob | null>(null)

  const { data: engData, loading: engLoading, error: engError, refetch: refetchEng } = useFetch<Engagement | null>(
    async () => {
      try {
        return await api.getEngagement(id)
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) return null
        throw e
      }
    },
    { deps: [id] },
  )

  // Local patch state so a tab can update the engagement in place. It is deliberately never reset
  // on refetch: mirroring `engLoading` into `undefined` unmounted the entire view (header, scan
  // panel, active tab and its state) behind a full-page spinner on every VEX apply or SBOM import.
  const [engPatch, setEngPatch] = useState<Engagement | null | undefined>(undefined)
  useEffect(() => {
    // A different engagement id invalidates any patch from the previous one.
    setEngPatch(undefined)
  }, [id])
  const eng = engPatch !== undefined ? engPatch : engData

  // Findings are the engagement's core record, so a failure here is surfaced. Catching it into an
  // empty array rendered a findings-service outage as "this engagement has no findings", with a
  // zero on the tab bar.
  const { data: fetchedFindings, error: findingsError, refetch: refetchFindings } = useFetch<Finding[]>(
    () => api.findings(id),
    { deps: [id] },
  )
  useEffect(() => {
    if (fetchedFindings !== null) setFindings(fetchedFindings)
  }, [fetchedFindings])

  // An engagement with no scan yet answers 404, which is the "run a scan" state and stays silent.
  // Any other failure is an outage and must not read as "no scan has been run".
  const { data: fetchedScan, error: scanError, refetch: refetchScan } = useFetch<ScanResult | null>(
    () => api.latestScan(id).catch((error) => {
      if (error instanceof ApiError && error.status === 404) return null
      throw error
    }),
    { deps: [id] },
  )
  useEffect(() => {
    if (fetchedScan) setScan(fetchedScan)
  }, [fetchedScan])

  const { data: importedSBOM, refetch: refetchSBOM } = useFetch<ImportedSBOMMetadata | null>(
    () => api.importedSBOM(id).catch((error) => {
      // No imported SBOM is the ordinary case and answers 404. Anything else is an outage, and the
      // import panel says so rather than showing the engagement as having no SBOM.
      if (error instanceof ApiError && error.status === 404) return null
      throw error
    }),
    { deps: [id] },
  )

  const { data: uploadedSource, error: uploadedSourceError, refetch: refetchUploadedSource } = useFetch<UploadedSourcePackage | null>(
    () => api.uploadedSource(id).catch((error) => {
      if (error instanceof ApiError && error.status === 404) return null
      throw error
    }),
    { deps: [id] },
  )

  return {
    eng,
    setEng: setEngPatch,
    engLoading,
    engError,
    findings,
    setFindings,
    findingsError,
    scan,
    scanError,
    setScan,
    job,
    setJob,
    importedSBOM,
    uploadedSource,
    uploadedSourceError,
    applyFinding: (updated) =>
      setFindings((cur) => (cur ? cur.map((f) => (f.id === updated.id ? updated : f)) : cur)),
    reloadFindings: refetchFindings,
    refreshAll: () => {
      refetchEng()
      refetchScan()
      refetchFindings()
      refetchSBOM()
    },
    refetchUploadedSource,
  }
}
