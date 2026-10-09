import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { DemoEntry } from './DemoEntry'
import { ADVANCED_CHAPTERS, DEMO_JOURNEY, startDemoChapter } from './journey'
import { emptyScenario, scenarioStore } from './scenario/store'
import { emptyWorkflows, workflowStore } from './workflows/store'
import { advancedStore } from './advanced/store'

vi.mock('./journey', async importOriginal => ({ ...await importOriginal<typeof import('./journey')>(), startDemoChapter: vi.fn() }))

beforeEach(() => {
  vi.restoreAllMocks()
  vi.mocked(startDemoChapter).mockClear()
  vi.spyOn(scenarioStore, 'getSnapshot').mockReturnValue(emptyScenario())
  vi.spyOn(workflowStore, 'getSnapshot').mockReturnValue(emptyWorkflows())
  const advanced = structuredClone(advancedStore.getSnapshot())
  for (const chapter of ADVANCED_CHAPTERS) Object.assign(advanced[chapter.mode], { complete: false, step: 0, completed: [] })
  Object.assign(advanced['ci-setup'], { complete: false, step: 0, completed: [] })
  Object.assign(advanced['ai-setup'], { complete: false, step: 0, completed: [] })
  vi.spyOn(advancedStore, 'getSnapshot').mockReturnValue(advanced)
  Element.prototype.scrollIntoView = vi.fn()
})

describe('Demo journey map', () => {
  it('previews all ten chapters without starting them and launches the selected chapter', () => {
    render(<DemoEntry />)
    for (const chapter of [...DEMO_JOURNEY, ...ADVANCED_CHAPTERS]) {
      const node = screen.getByRole('button', { name: new RegExp(chapter.title) })
      fireEvent.click(node)
      expect(node).toHaveAttribute('aria-pressed', 'true')
      expect(within(screen.getByRole('region', { name: chapter.title })).getByRole('heading', { name: chapter.title })).toBeVisible()
    }
    expect(startDemoChapter).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Start walkthrough' }))
    expect(startDemoChapter).toHaveBeenCalledWith('policy')
    fireEvent.click(screen.getByRole('button', { name: 'Back to recommended' }))
    expect(screen.getByRole('button', { name: 'Start tour' })).toBeVisible()
  })

  it('preserves resume and restart actions and separates specialist completion from core progress', () => {
    const workflows = emptyWorkflows()
    workflows.overviewComplete = true
    workflows.quality.step = 2
    workflows.quality.completed = [0, 1]
    vi.mocked(workflowStore.getSnapshot).mockReturnValue(workflows)
    const advanced = advancedStore.getSnapshot()
    advanced.policy.complete = true
    render(<DemoEntry />)
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '1')
    expect(screen.getByText('2 steps complete', { exact: false })).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Resume walkthrough' }))
    expect(startDemoChapter).toHaveBeenLastCalledWith('quality')
    fireEvent.click(screen.getByRole('button', { name: 'Start over' }))
    expect(startDemoChapter).toHaveBeenLastCalledWith('quality', true)
    fireEvent.click(screen.getByRole('button', { name: /Quality Policies & CI/ }))
    expect(screen.getByRole('button', { name: 'Review walkthrough' })).toBeVisible()
  })
})
