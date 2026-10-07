import { describe, expect, it } from 'vitest'
import { mapScanJob, mapScanResult, mapVuln } from './scan'

// EPIC #860 D3.4: the scan mapper surfaces the COMPLETE set of introducing direct dependencies from
// the PascalCase API field, so the UI can list every direct dep to bump for a transitive vulnerability.
describe('mapVuln introducers', () => {
  it('maps the Introducers array from the API', () => {
    const v = mapVuln({ id: 'CVE-1', Path: ['app', 'a', 'target'], Direct: false, Introducers: ['a', 'b'] })
    expect(v.introducers).toEqual(['a', 'b'])
  })
  it('is undefined when the API omits it (a direct dep or a graph without a root)', () => {
    const v = mapVuln({ id: 'CVE-2', Path: ['target'], Direct: true })
    expect(v.introducers).toBeUndefined()
  })
})

describe('scan engine coverage mapping', () => {
  it('maps a complete result without using dependency completeness as coverage', () => {
    const result = mapScanResult({
      completeness: { confident: false },
      engine_coverage: { status: 'complete', required: 3, completed: 3 },
      engine_outcomes: [{ engine: 'sast', execution: 'completed', coverage: 'complete', required: true, counts: { findings: 0 } }],
      execution_mode: 'actual_run',
    })
    expect(result.engineCoverage).toEqual({ status: 'complete', required: 3, completed: 3 })
    expect(result.engineOutcomes).toHaveLength(1)
    expect(result.executionMode).toBe('actual_run')
  })

  it('maps missing or unrecognized coverage as unknown', () => {
    expect(mapScanResult({}).engineCoverage).toEqual({ status: 'unknown', required: 0, completed: 0 })
    expect(mapScanJob({ status: 'succeeded', engine_coverage: { status: 'invented', required: -1, completed: 4 } }).engineCoverage)
      .toEqual({ status: 'unknown', required: 0, completed: 4 })
  })

  it('maps a partial outcome and preserves its stable reason', () => {
    const result = mapScanResult({
      engine_coverage: { status: 'partial', required: 3, completed: 2 },
      engine_outcomes: [{ engine: 'sast', execution: 'timed_out', coverage: 'partial', reason: 'deadline_exceeded', required: true }],
    })
    expect(result.engineOutcomes?.[0]).toMatchObject({ execution: 'timed_out', coverage: 'partial', reason: 'deadline_exceeded' })
  })

  it('cannot display malformed aggregate claims as complete', () => {
    for (const aggregate of [
      { status: 'complete', required: 0, completed: 0 },
      { status: 'complete', required: 3, completed: 2 },
      { status: 'complete', required: 65, completed: 65 },
    ]) {
      expect(mapScanJob({ engine_coverage: aggregate }).engineCoverage?.status).toBe('unknown')
    }
  })
})
