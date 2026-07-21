import { describe, expect, it } from 'vitest'
import { mapProjectMeasureResponse } from './projectMeasures'

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
    expect(res.node?.coverage).toBeNull()
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
})
