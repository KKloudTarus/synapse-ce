import { describe, expect, it } from 'vitest'
import type { ScanJob, ScanResult } from '../../lib/types'
import { engineCoverageForDisplay, jobForEngagement } from './ScanPanel'

const cachedResult = { engineCoverage: { status: 'complete', required: 3, completed: 3 } } as ScanResult

describe('engineCoverageForDisplay', () => {
  it('does not inherit coverage from a cached result when a newer job has no metadata', () => {
    const currentJob = { engineCoverage: undefined } as ScanJob
    expect(engineCoverageForDisplay(currentJob, cachedResult)).toEqual({ status: 'unknown', required: 0, completed: 0 })
  })

  it('uses stored-result coverage when there is no current job', () => {
    expect(engineCoverageForDisplay(null, cachedResult)).toEqual({ status: 'complete', required: 3, completed: 3 })
  })

  it('drops engagement A job state before rendering engagement B coverage', () => {
    const completeA = { engagementId: 'A', engineCoverage: { status: 'complete', required: 3, completed: 3 } } as ScanJob
    const partialB = { engineCoverage: { status: 'partial', required: 3, completed: 2 } } as ScanResult
    const currentB = jobForEngagement(completeA, 'B')
    expect(currentB).toBeNull()
    expect(engineCoverageForDisplay(currentB, partialB)).toEqual({ status: 'partial', required: 3, completed: 2 })
  })
})
