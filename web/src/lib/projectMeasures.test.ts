import { describe, expect, it } from 'vitest'
import { mapBehavioralHotspotsResponse, mapProjectMeasureResponse } from './projectMeasures'

describe('projectMeasures mapper', () => {
  it('maps available zero values to zero', () => {
    const raw = {
      state: 'analyzed',
      node: {
        size: {
          files: { availability: 'available', value: 0 },
        },
      },
    }
    const res = mapProjectMeasureResponse(raw)
    expect(res.node?.size?.files.availability).toBe('available')
    expect(res.node?.size?.files.value).toBe(0)
  })

  it('maps unavailable values to null, not 0', () => {
    const raw = {
      state: 'analyzed',
      node: {
        size: {
          files: { availability: 'unavailable' },
        },
      },
    }
    const res = mapProjectMeasureResponse(raw)
    expect(res.node?.size?.files.availability).toBe('unavailable')
    expect(res.node?.size?.files.value).toBeNull()
  })

  it('keeps not_applicable distinct and value null', () => {
    const raw = {
      state: 'analyzed',
      node: {
        coverage: {
          new_code_coverage: { availability: 'not_applicable' },
        },
      },
    }
    const res = mapProjectMeasureResponse(raw)
    expect(res.node?.coverage?.newCodeCoverage.availability).toBe('not_applicable')
    expect(res.node?.coverage?.newCodeCoverage.value).toBeNull()
  })

  it('preserves unavailable_reason', () => {
    const raw = {
      node: {
        issues: {
          by_type: {
            bug: { availability: 'unavailable', unavailable_reason: 'no_attribution' },
          },
        },
      },
    }
    const res = mapProjectMeasureResponse(raw)
    expect(res.node?.issues?.byType['bug']?.reason).toBe('no_attribution')
  })

  it('treats omitted domains as null', () => {
    const raw = {
      node: {
        kind: 'project',
        // missing size, complexity, coverage, etc.
      },
    }
    const res = mapProjectMeasureResponse(raw)
    expect(res.node?.size).toBeNull()
    expect(res.node?.complexity).toBeNull()
    expect(res.node?.coupling).toBeNull()
    expect(res.node?.coverage).toBeNull()
  })

  it('maps coupling zero separately from unavailable instability', () => {
    const res = mapProjectMeasureResponse({
      node: { coupling: {
        afferent: { availability: 'available', value: 0 },
        efferent: { availability: 'available', value: 0 },
        instability: { availability: 'unavailable', unavailable_reason: 'isolated_module' },
      } },
    })
    expect(res.node?.coupling?.afferent.value).toBe(0)
    expect(res.node?.coupling?.instability.value).toBeNull()
    expect(res.node?.coupling?.instability.reason).toBe('isolated_module')
  })

  it('maps behavioral measure zero and pinned ranking metadata', () => {
    const measures = mapProjectMeasureResponse({
      node: { behavioral_hotspots: {
        cyclomatic_sum: { availability: 'available', value: 0 },
        change_count: { availability: 'available', value: 2 },
        score: { availability: 'available', value: 30 },
      } },
    })
    expect(measures.node?.behavioralHotspots?.cyclomaticSum.value).toBe(0)
    expect(measures.node?.behavioralHotspots?.score.value).toBe(30)

    const ranking = mapBehavioralHotspotsResponse({
      project: { key: 'p', name: 'Project' },
      analysis: { id: 'a1', source_ref: 'main', source_commit: 'abc' },
      availability: 'partial',
      unavailable_reason: '1_of_2_files_unmeasured',
      formula_version: 1,
      requested_commits: 255,
      evaluated_commits: 2,
      total_eligible: 2,
      total_measured: 1,
      total_excluded: 1,
      shown: 1,
      omitted: 0,
      items: [{ path: 'a.go', language: 'Go', cyclomatic: 10, change_count: 3, score: 30 }],
    })
    expect(ranking.availability).toBe('partial')
    expect(ranking.analysis.id).toBe('a1')
    expect(ranking.items[0]).toMatchObject({ path: 'a.go', changeCount: 3, score: 30 })
  })

  it('defaults omitted child items to an empty array', () => {
    const raw = {
      children: {
        // missing items
        next_cursor: 'abc',
      },
    }
    const res = mapProjectMeasureResponse(raw)
    expect(res.children.items).toEqual([])
    expect(res.children.nextCursor).toBe('abc')
  })

  it('preserves next_cursor exactly', () => {
    const raw = {
      children: {
        next_cursor: 'opaque_cursor_123==',
      },
    }
    const res = mapProjectMeasureResponse(raw)
    expect(res.children.nextCursor).toBe('opaque_cursor_123==')
  })

  it('available + null must not become zero', () => {
    const raw = {
      state: 'analyzed',
      node: {
        size: {
          files: { availability: 'available', value: null },
        },
        ratings: {
          security: { availability: 'available', grade: null },
        }
      },
    }
    const res = mapProjectMeasureResponse(raw)
    expect(res.node?.size?.files.availability).toBe('available')
    expect(res.node?.size?.files.value).toBeNull()
    expect(res.node?.ratings?.security.availability).toBe('available')
    expect(res.node?.ratings?.security.grade).toBeNull()
  })

  it('preserves signed complexity deltas, coverage, and baseline provenance', () => {
    const res = mapProjectMeasureResponse({
      node: {
        complexity: {
          cyclomatic: { availability: 'available', value: 12 },
          cognitive: { availability: 'available', value: 8 },
          cyclomatic_delta: { availability: 'available', value: -3 },
          cognitive_delta: { availability: 'available', value: 0 },
          coverage: {
            version: 1,
            eligible_files: { availability: 'available', value: 4 },
            measured_files: { availability: 'available', value: 3 },
            availability: 'unavailable',
            unavailable_reason: '1_of_4_files_unmeasured',
          },
          baseline: { analysis_id: 'a0', created_at: '2026-01-01T00:00:00Z', source_ref: 'main' },
        },
      },
    })
    expect(res.node?.complexity?.cyclomaticDelta.value).toBe(-3)
    expect(res.node?.complexity?.cognitiveDelta.value).toBe(0)
    expect(res.node?.complexity?.coverage.eligibleFiles.value).toBe(4)
    expect(res.node?.complexity?.coverage.measuredFiles.value).toBe(3)
    expect(res.node?.complexity?.coverage.reason).toBe('1_of_4_files_unmeasured')
    expect(res.node?.complexity?.baseline).toEqual({ analysisId: 'a0', createdAt: '2026-01-01T00:00:00Z', sourceRef: 'main' })
  })
})
