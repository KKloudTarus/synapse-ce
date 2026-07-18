import { describe, expect, it } from 'vitest'
import {
  parseProjectAnalysisFocus,
  projectAnalysisFocusValues,
  serializeProjectAnalysisFocus,
} from './projectAnalysisNavigation'

describe('projectAnalysisNavigation focus contract', () => {
  it('parses and serializes every supported focus', () => {
    for (const focus of projectAnalysisFocusValues) {
      expect(parseProjectAnalysisFocus(focus)).toBe(focus)
      expect(serializeProjectAnalysisFocus(focus)).toBe(focus)
    }
  })

  it.each([null, '', ' ', 'issues', 'hotspots', 'measures', 'foo', 'Security'])(
    'rejects unsupported focus %j',
    (value) => {
      expect(parseProjectAnalysisFocus(value)).toBeNull()
    },
  )
})
