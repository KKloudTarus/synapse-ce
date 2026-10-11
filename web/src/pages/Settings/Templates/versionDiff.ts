/**
 * Side-by-side line diff for template versions (#1375). A field is at most 16 KiB, so a plain LCS over
 * the lines that differ is cheap; past MAX_CELLS the differing block is shown as one replacement
 * rather than spending seconds on an exact diff.
 */

export interface DiffLine {
  /** 1-based line number in its own version. */
  number: number
  text: string
}

export type DiffRowKind = 'same' | 'removed' | 'added' | 'changed'

/** One row of the side-by-side view: the left (older) line, the right (newer) line, or both. */
export interface DiffRow {
  kind: DiffRowKind
  left?: DiffLine
  right?: DiffLine
}

export interface FieldDiff {
  field: string
  changed: boolean
  rows: DiffRow[]
}

const MAX_CELLS = 4_000_000

function splitLines(text: string): string[] {
  return text === '' ? [] : text.split(/\r?\n/)
}

type Op = { kind: 'same' | 'removed' | 'added'; left?: number; right?: number }

/** Edit script for the middle block, by longest common subsequence. */
function lcsOps(a: string[], b: string[], aStart: number, bStart: number): Op[] {
  const n = a.length
  const m = b.length
  if (n * m > MAX_CELLS) {
    return [...a.map((_, i) => ({ kind: 'removed' as const, left: aStart + i })), ...b.map((_, j) => ({ kind: 'added' as const, right: bStart + j }))]
  }
  // table[i][j] = LCS length of a[i:] and b[j:], one flat array.
  const width = m + 1
  const table = new Uint32Array((n + 1) * width)
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      table[i * width + j] = a[i] === b[j] ? table[(i + 1) * width + j + 1] + 1 : Math.max(table[(i + 1) * width + j], table[i * width + j + 1])
    }
  }
  const ops: Op[] = []
  let i = 0
  let j = 0
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ kind: 'same', left: aStart + i++, right: bStart + j++ })
    } else if (table[(i + 1) * width + j] >= table[i * width + j + 1]) {
      ops.push({ kind: 'removed', left: aStart + i++ })
    } else {
      ops.push({ kind: 'added', right: bStart + j++ })
    }
  }
  while (i < n) ops.push({ kind: 'removed', left: aStart + i++ })
  while (j < m) ops.push({ kind: 'added', right: bStart + j++ })
  return ops
}

/**
 * Diffs two texts line by line. Consecutive removed and added lines are paired into `changed` rows,
 * so an edited line sits next to the line it replaced.
 */
export function diffLines(before: string, after: string): DiffRow[] {
  const a = splitLines(before)
  const b = splitLines(after)
  let prefix = 0
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) prefix++
  let suffix = 0
  while (suffix < a.length - prefix && suffix < b.length - prefix && a[a.length - 1 - suffix] === b[b.length - 1 - suffix]) suffix++

  const ops: Op[] = []
  for (let k = 0; k < prefix; k++) ops.push({ kind: 'same', left: k, right: k })
  ops.push(...lcsOps(a.slice(prefix, a.length - suffix), b.slice(prefix, b.length - suffix), prefix, prefix))
  for (let k = suffix; k > 0; k--) ops.push({ kind: 'same', left: a.length - k, right: b.length - k })

  const line = (lines: string[], index: number): DiffLine => ({ number: index + 1, text: lines[index] })
  const rows: DiffRow[] = []
  for (let k = 0; k < ops.length; ) {
    if (ops[k].kind === 'same') {
      rows.push({ kind: 'same', left: line(a, ops[k].left!), right: line(b, ops[k].right!) })
      k++
      continue
    }
    const removed: number[] = []
    const added: number[] = []
    while (k < ops.length && ops[k].kind !== 'same') {
      if (ops[k].kind === 'removed') removed.push(ops[k].left!)
      else added.push(ops[k].right!)
      k++
    }
    for (let p = 0; p < Math.max(removed.length, added.length); p++) {
      const left = p < removed.length ? line(a, removed[p]) : undefined
      const right = p < added.length ? line(b, added[p]) : undefined
      rows.push({ kind: left && right ? 'changed' : left ? 'removed' : 'added', left, right })
    }
  }
  return rows
}

/** Diffs every field of a family between two versions; a field missing from a version is empty. */
export function diffFields(fields: string[], before: Record<string, string>, after: Record<string, string>): FieldDiff[] {
  return fields.map((field) => {
    const left = before[field] ?? ''
    const right = after[field] ?? ''
    return { field, changed: left !== right, rows: diffLines(left, right) }
  })
}
