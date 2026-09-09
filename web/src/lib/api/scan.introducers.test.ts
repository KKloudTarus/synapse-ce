import { describe, expect, it } from 'vitest'
import { mapVuln } from './scan'

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
