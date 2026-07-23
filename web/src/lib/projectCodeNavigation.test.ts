import { describe, expect, it } from 'vitest'
import { normalizeProjectCodeSearch, projectCodePath } from './projectCodeNavigation'

describe('project Code navigation', () => {
  it('round-trips immutable deep links', () => {
    const path = projectCodePath('my project', { analysisId: 'a 1', path: 'src/main file.ts', view: 'split', line: 42, findingId: 'f 1' })
    expect(path).toBe('/code-quality/projects/my%20project/code?analysis=a+1&path=src%2Fmain+file.ts&view=split&line=42&finding=f+1')
    expect(normalizeProjectCodeSearch(new URLSearchParams(path.split('?')[1]))).toMatchObject({ analysisId: 'a 1', path: 'src/main file.ts', view: 'split', line: 42, findingId: 'f 1', changed: false })
  })

  it('drops invalid and dependent parameters while retaining unrelated search', () => {
    const result = normalizeProjectCodeSearch(new URLSearchParams('analysis=+&path=+&view=nope&line=0&finding=f&other=kept'))
    expect(result).toMatchObject({ analysisId: null, path: null, view: 'source', line: null, findingId: null, changed: true })
    expect(result.params.toString()).toBe('other=kept')
  })
})
