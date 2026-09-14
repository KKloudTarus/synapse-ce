import { describe, expect, it } from 'vitest'
import { mapFinding } from './findings'

describe('mapFinding', () => {
  it('preserves Vulnerability Intelligence provenance from the API', () => {
    const finding = mapFinding({
      ID: 'finding-1',
      AdvisoryID: 'CVE-2026-12346',
      OccurrenceID: 'occurrence-1',
      Sources: ['nvd', 'cisa_kev', { untrusted: true }],
      Confidence: 'high',
      FixedVersion: '2.0.1',
      DetectionState: 'detected',
      EvaluatedAt: '2026-09-14T00:00:00Z',
    })

    expect(finding).toMatchObject({
      advisoryId: 'CVE-2026-12346',
      occurrenceId: 'occurrence-1',
      sources: ['nvd', 'cisa_kev'],
      confidence: 'high',
      fixedVersion: '2.0.1',
      detectionState: 'detected',
      evaluatedAt: '2026-09-14T00:00:00Z',
    })
  })
})
