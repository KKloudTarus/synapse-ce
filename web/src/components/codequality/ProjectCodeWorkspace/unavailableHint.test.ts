import { describe, expect, it } from 'vitest'

import { unavailableHint } from './index'
import type { ProjectCodeFile } from '../../../lib/types'

// A CI-pushed analysis records results without files, so its Code view read "This captured file is
// unavailable: Not retained." A reader cannot act on that: the fix is a CLI flag, and the message
// never named it. Every reason a reader can do something about now says what.
const file = (sourceReason: string | null): ProjectCodeFile =>
  ({
    path: 'main.go',
    status: 'unchanged',
    language: 'Go',
    lines: 0,
    findingCount: 0,
    changedLineCount: 0,
    binary: false,
    generated: false,
    sourceAvailable: false,
    sourceReason,
  }) as ProjectCodeFile

describe('unavailableHint', () => {
  it('names the flag and the command that retain source', () => {
    const hint = unavailableHint(file('not_retained'), 'a1b2c3')
    expect(hint).toContain('--push-source')
    expect(hint).toContain('synapse-cli publish-source --analysis a1b2c3')
    expect(hint).not.toContain('Not retained')
  })

  it('explains the reasons a reader cannot act on without naming a remedy', () => {
    expect(unavailableHint(file('capture_failed'), 'a1')).toContain('failed while the analysis ran')
    expect(unavailableHint(file('limit_exceeded'), 'a1')).toContain('larger than the source limit')
    expect(unavailableHint(file('binary'), 'a1')).toContain('not UTF-8 text')
  })

  it('keeps an unknown reason readable rather than dropping it', () => {
    expect(unavailableHint(file('some_new_reason'), 'a1')).toBe(
      'This captured file is unavailable: Some new reason.',
    )
  })
})
