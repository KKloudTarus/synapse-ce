import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ProjectCodeWorkspace } from './ProjectCodeWorkspace'

const index = {
  analysisId: 'a1', base: null, head: { ref: 'main', commit: 'head', artifactDigest: 'sha256:head' },
  capabilities: { source: true, unifiedDiff: true, splitDiff: true, lineCoverage: false },
  files: [{ path: 'src/main.ts', oldPath: null, status: 'modified' as const, language: 'typescript', lines: 2, findingCount: 2, changedLineCount: 1, binary: false, generated: false, sourceAvailable: true, sourceReason: null }],
}

const source = {
  analysisId: 'a1', base: null, head: index.head, file: index.files[0], fromLine: 1, toLine: 2, totalLines: 2,
  capabilities: index.capabilities,
  lines: [{ number: 1, content: '<script>danger()</script>', change: 'addition' as const, duplicated: false, coverage: null }, { number: 2, content: 'return ok', change: 'unchanged' as const, duplicated: false, coverage: 'uncovered' as const }],
  findings: [
    { id: 'f1', kind: 'issue' as const, ruleKey: 'rule-a', ruleName: 'Rule A', type: 'bug' as const, severity: 'high' as const, detectionStatus: 'open', currentStatus: 'accepted', message: 'First', location: { file: 'src/main.ts', startLine: 1, endLine: 1, startColumn: 0, endColumn: 8 }, isNew: true },
    { id: 'f2', kind: 'issue' as const, ruleKey: 'rule-b', ruleName: 'Rule B', type: 'bug' as const, severity: 'low' as const, detectionStatus: 'open', currentStatus: null, message: 'Second', location: { file: 'src/main.ts', startLine: 1, endLine: 2, startColumn: null, endColumn: null }, isNew: false },
  ],
}

const originalRect = Element.prototype.getBoundingClientRect

beforeEach(() => {
  Element.prototype.getBoundingClientRect = vi.fn(() => ({ width: 900, height: 600, top: 0, left: 0, bottom: 600, right: 900, x: 0, y: 0, toJSON: () => {} }))
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', { configurable: true, value: 600 })
})
afterEach(() => { Element.prototype.getBoundingClientRect = originalRect })

describe('ProjectCodeWorkspace', () => {
  it('renders escaped source and selects collocated findings', () => {
    const select = vi.fn()
    render(<ProjectCodeWorkspace index={index} source={source} diff={null} selectedPath="src/main.ts" selectedFindingId={null} view="source" onSelectFile={vi.fn()} onSelectFinding={select} onView={vi.fn()} onRetrySource={vi.fn()} sourceError={null} diffError={null} />)
    expect(screen.getByText('<script>danger()</script>')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '2 findings on line 1' }))
    expect(select).toHaveBeenCalledWith(expect.objectContaining({ id: 'f1' }))
  })

  it('shows immutable and current finding statuses separately', () => {
    render(<ProjectCodeWorkspace index={index} source={source} diff={null} selectedPath="src/main.ts" selectedFindingId="f1" view="source" onSelectFile={vi.fn()} onSelectFinding={vi.fn()} onView={vi.fn()} onRetrySource={vi.fn()} sourceError={null} diffError={null} />)
    expect(screen.getByText('Detected status')).toBeInTheDocument()
    expect(screen.getByText('Current status')).toBeInTheDocument()
    expect(screen.getByText('accepted')).toBeInTheDocument()
  })

  it('resizes expanded finding details with the keyboard', () => {
    render(<ProjectCodeWorkspace index={index} source={source} diff={null} selectedPath="src/main.ts" selectedFindingId="f1" view="source" onSelectFile={vi.fn()} onSelectFinding={vi.fn()} onView={vi.fn()} onRetrySource={vi.fn()} sourceError={null} diffError={null} />)
    const separator = screen.getByRole('separator', { name: 'Resize finding details' })
    const panel = screen.getByRole('complementary', { name: 'Findings' })

    expect(panel).toHaveStyle({ height: '192px' })
    fireEvent.keyDown(separator, { key: 'ArrowUp' })
    expect(panel).toHaveStyle({ height: '216px' })
    fireEvent.keyDown(separator, { key: 'ArrowDown' })
    expect(panel).toHaveStyle({ height: '192px' })
  })

  it('disables diff modes for an unchanged file', () => {
    const onView = vi.fn()
    const unchangedIndex = { ...index, files: [{ ...index.files[0], status: 'unchanged' as const, changedLineCount: 0 }] }
    render(<ProjectCodeWorkspace index={unchangedIndex} source={{ ...source, file: unchangedIndex.files[0] }} diff={null} selectedPath="src/main.ts" selectedFindingId={null} view="source" onSelectFile={vi.fn()} onSelectFinding={vi.fn()} onView={onView} onRetrySource={vi.fn()} sourceError={null} diffError={null} />)

    expect(screen.getByRole('button', { name: 'source' })).toBeEnabled()
    for (const mode of ['unified', 'split']) {
      const button = screen.getByRole('button', { name: mode })
      expect(button).toBeDisabled()
      fireEvent.click(button)
    }
    expect(onView).not.toHaveBeenCalled()
  })

  it('filters files and exposes source window navigation', () => {
    const navigate = vi.fn()
    const files = [
      index.files[0],
      { ...index.files[0], path: 'src/quiet.ts', status: 'unchanged' as const, changedLineCount: 0, findingCount: 0 },
    ]
    render(<ProjectCodeWorkspace index={{ ...index, files }} source={{ ...source, totalLines: 1200, toLine: 1000 }} diff={null} selectedPath="src/main.ts" selectedFindingId={null} view="source" onSelectFile={vi.fn()} onSelectFinding={vi.fn()} onView={vi.fn()} onNavigateLine={navigate} onRetrySource={vi.fn()} sourceError={null} diffError={null} />)

    fireEvent.click(screen.getByRole('button', { name: /Changed 1/ }))
    expect(screen.queryByRole('button', { name: /src\/quiet.ts/ })).not.toBeInTheDocument()
    expect(screen.getByText(/Lines 1–1,000/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Next 1,000 lines' }))
    expect(navigate).toHaveBeenCalledWith(1001)
  })

  it('renders aligned split rows and newline markers', () => {
    const diff = {
      capabilities: { source: { available: true, reason: null }, comparison: { available: true, reason: null }, unifiedDiff: { available: true, reason: null }, splitDiff: { available: true, reason: null }, highlighting: { available: false, reason: 'unsupported' } },
      diff: { analysisId: 'a1', base: index.head, head: index.head, path: 'src/main.ts', view: 'split' as const, contextTruncated: true, change: { oldPath: 'src/main.ts', newPath: 'src/main.ts', status: 'modified' as const, binary: false, modeOld: '100644', modeNew: '100644', hunks: [{ oldStart: 1, oldLines: 1, newStart: 1, newLines: 1, rows: [{ kind: 'removed' as const, oldLine: 1, newLine: null, text: 'old', noFinalNewline: false }, { kind: 'added' as const, oldLine: null, newLine: 1, text: 'new', noFinalNewline: true }] }] } },
    }
    render(<ProjectCodeWorkspace index={index} source={source} diff={diff} selectedPath="src/main.ts" selectedFindingId={null} view="split" onSelectFile={vi.fn()} onSelectFinding={vi.fn()} onView={vi.fn()} onRetrySource={vi.fn()} sourceError={null} diffError={null} />)

    expect(screen.getByRole('table', { name: 'Split code diff' })).toBeInTheDocument()
    expect(screen.getByText('old')).toBeInTheDocument()
    expect(screen.getByText('new')).toBeInTheDocument()
    expect(screen.getByText('No newline at end of file')).toBeInTheDocument()
    expect(screen.getByRole('note')).toHaveTextContent('Unchanged context is limited')
    expect(screen.getAllByRole('columnheader')).toHaveLength(2)
    expect(screen.getAllByRole('rowgroup')).toHaveLength(2)
  })

  it('virtualizes large diffs and scopes live announcements', () => {
    const rows = Array.from({ length: 500 }, (_, offset) => ({ kind: 'added' as const, oldLine: null, newLine: offset + 1, text: `line-${offset + 1}`, noFinalNewline: false }))
    const diff = {
      capabilities: { source: { available: true, reason: null }, comparison: { available: true, reason: null }, unifiedDiff: { available: true, reason: null }, splitDiff: { available: true, reason: null }, highlighting: { available: false, reason: 'unsupported' } },
      diff: { analysisId: 'a1', base: index.head, head: index.head, path: 'src/main.ts', view: 'unified' as const, contextTruncated: false, change: { oldPath: 'src/main.ts', newPath: 'src/main.ts', status: 'modified' as const, binary: false, modeOld: '100644', modeNew: '100644', hunks: [{ oldStart: 1, oldLines: 0, newStart: 1, newLines: rows.length, rows }] } },
    }
    const { container } = render(<ProjectCodeWorkspace index={index} source={source} diff={diff} selectedPath="src/main.ts" selectedFindingId={null} view="unified" onSelectFile={vi.fn()} onSelectFinding={vi.fn()} onView={vi.fn()} onRetrySource={vi.fn()} sourceError={null} diffError={null} />)

    expect(screen.getByRole('table', { name: 'Unified code diff' })).toHaveAttribute('aria-rowcount', '502')
    expect(screen.getAllByRole('row').length).toBeLessThan(100)
    expect(screen.getByRole('status')).toHaveTextContent('src/main.ts, unified view')
    expect(container.firstElementChild).not.toHaveAttribute('aria-live')
  })

  it('opens and closes the mobile file dialog', () => {
    render(<ProjectCodeWorkspace index={index} source={source} diff={null} selectedPath="src/main.ts" selectedFindingId={null} view="source" onSelectFile={vi.fn()} onSelectFinding={vi.fn()} onView={vi.fn()} onRetrySource={vi.fn()} sourceError={null} diffError={null} />)
    const trigger = screen.getByRole('button', { name: 'Browse files' })
    fireEvent.click(trigger)
    expect(screen.getByRole('dialog', { name: 'Captured files' })).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog', { name: 'Captured files' })).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })
})
