import { updateAdvanced } from './advanced/store'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { PlaygroundTour } from './PlaygroundTour'
import { emptyScenario } from './scenario/store'
import { emptyWorkflows } from './workflows/store'
import { nextChapter, recommendedChapter } from './journey'
import { TOUR_STEPS } from './tour-steps'

describe('Learning journey', () => {
  it('recommends the first unfinished chapter and keeps partial progress incomplete', () => {
    const scenario = emptyScenario(), workflows = emptyWorkflows()
    expect(recommendedChapter(scenario, workflows)?.mode).toBe('overview')
    workflows.overviewComplete = true
    workflows.quality.step = 8
    workflows.quality.completed = [0, 1, 2, 3, 4, 5, 6, 7]
    expect(recommendedChapter(scenario, workflows)?.mode).toBe('quality')
    workflows.quality.complete = true
    scenario.completed = ['asset', 'engagement', 'scan']
    expect(recommendedChapter(scenario, workflows)?.mode).toBe('code')
    scenario.completed.push('finish')
    expect(recommendedChapter(scenario, workflows)?.mode).toBe('ci-setup')
    updateAdvanced(s => { s['ci-setup'].complete = true })
    expect(recommendedChapter(scenario, workflows)?.mode).toBe('ai-setup')
    updateAdvanced(s => { s['ai-setup'].complete = true })
    expect(recommendedChapter(scenario, workflows)?.mode).toBe('ai')
    workflows.ai.complete = true
    expect(recommendedChapter(scenario, workflows)?.mode).toBe('runtime')
    workflows.runtime.complete = true
    expect(recommendedChapter(scenario, workflows)).toBeUndefined()
    expect(nextChapter('quality')?.mode).toBe('code')
    expect(nextChapter('code')?.mode).toBe('ci-setup')
    expect(nextChapter('ai')?.mode).toBe('runtime')
    expect(nextChapter('runtime')).toBeUndefined()
  })
  it('records overview completion only when Finish is selected', async () => {
    const onComplete = vi.fn(), stop = vi.fn()
    render(<MemoryRouter initialEntries={['/dashboard']}><PlaygroundTour index={TOUR_STEPS.length - 1} setIndex={vi.fn()} stop={stop} onComplete={onComplete} /></MemoryRouter>)
    fireEvent.click(await screen.findByRole('button', { name: /^Finish$/ }))
    expect(onComplete).toHaveBeenCalledOnce()
    expect(stop).toHaveBeenCalledOnce()
  })
  it('allows an early exit without completing the overview chapter', async () => {
    const onComplete = vi.fn(), stop = vi.fn()
    render(<MemoryRouter initialEntries={['/dashboard']}><PlaygroundTour index={TOUR_STEPS.length - 1} setIndex={vi.fn()} stop={stop} onComplete={onComplete} /></MemoryRouter>)
    fireEvent.click(await screen.findByRole('button', { name: /^End the tour$/ }))
    expect(stop).toHaveBeenCalledOnce()
    expect(onComplete).not.toHaveBeenCalled()
  })
})
