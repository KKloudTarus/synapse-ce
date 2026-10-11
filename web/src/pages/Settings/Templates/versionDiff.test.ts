import { describe, expect, it } from 'vitest'
import { diffFields, diffLines } from './versionDiff'

const kinds = (before: string, after: string) => diffLines(before, after).map((row) => row.kind)

describe('template version diff', () => {
  it('keeps identical text as unchanged rows with both line numbers', () => {
    expect(diffLines('a\nb', 'a\nb')).toEqual([
      { kind: 'same', left: { number: 1, text: 'a' }, right: { number: 1, text: 'a' } },
      { kind: 'same', left: { number: 2, text: 'b' }, right: { number: 2, text: 'b' } },
    ])
  })

  it('pairs an edited line with the line it replaced', () => {
    expect(diffLines('Hello\nOld body\nBye', 'Hello\nNew body\nBye')).toEqual([
      { kind: 'same', left: { number: 1, text: 'Hello' }, right: { number: 1, text: 'Hello' } },
      { kind: 'changed', left: { number: 2, text: 'Old body' }, right: { number: 2, text: 'New body' } },
      { kind: 'same', left: { number: 3, text: 'Bye' }, right: { number: 3, text: 'Bye' } },
    ])
  })

  it('shows inserted and deleted lines on one side only, with each side numbered on its own', () => {
    const rows = diffLines('a\nc', 'a\nb\nc')
    expect(rows.map((row) => row.kind)).toEqual(['same', 'added', 'same'])
    expect(rows[1]).toEqual({ kind: 'added', right: { number: 2, text: 'b' } })
    expect(rows[2]).toMatchObject({ left: { number: 2 }, right: { number: 3 } })
    expect(kinds('a\nb\nc', 'a\nc')).toEqual(['same', 'removed', 'same'])
  })

  it('aligns unchanged lines in the middle of a larger edit', () => {
    expect(kinds('x\nkeep\ny', 'p\nq\nkeep\nr')).toEqual(['changed', 'added', 'same', 'changed'])
  })

  it('handles empty text on either side', () => {
    expect(diffLines('', '')).toEqual([])
    expect(kinds('', 'one\ntwo')).toEqual(['added', 'added'])
    expect(kinds('one', '')).toEqual(['removed'])
  })

  it('treats CRLF and LF line ends as the same line', () => {
    expect(kinds('a\r\nb', 'a\nb')).toEqual(['same', 'same'])
  })

  it('falls back to a block replacement when an exact diff would be too large', () => {
    const before = Array.from({ length: 2500 }, (_, i) => `old ${i}`).join('\n')
    const after = Array.from({ length: 2500 }, (_, i) => `new ${i}`).join('\n')
    const rows = diffLines(before, after)
    expect(rows).toHaveLength(2500)
    expect(rows.every((row) => row.kind === 'changed')).toBe(true)
  })

  it('diffs every field of the family and marks the ones that changed', () => {
    const diffs = diffFields(['title', 'body'], { title: 'Same', body: 'Old' }, { title: 'Same', body: 'New' })
    expect(diffs.map((d) => [d.field, d.changed])).toEqual([
      ['title', false],
      ['body', true],
    ])
    expect(diffFields(['summary'], {}, { summary: 'Added' })[0]).toMatchObject({ changed: true, rows: [{ kind: 'added' }] })
  })
})
