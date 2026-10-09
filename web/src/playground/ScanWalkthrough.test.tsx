import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { useState } from 'react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { SCAN_STEPS } from './scan-steps'
import { ScanWalkthrough } from './ScanWalkthrough'
import { emptyScenario, resetScenario, scenarioStore, updateScenario } from './scenario/store'
import { findGuideTarget } from './guided-actions'
import { PHASE_DURATION } from './scenario/catalog'
import { Select } from '../components/ui'
import { Dialog, Modal, ModalOverlay } from '../components/application/modals/modal'
import { ScanConfigModal } from '../pages/EngagementDetail/components/ScanConfigModal'
import type { ScanMode } from '../lib/types'
import { COMPARISON_ID, INITIAL_ID, RETEST_ID, TARGET } from './scenario/store'

beforeEach(() => {
  resetScenario()
  vi.spyOn(HTMLElement.prototype, 'getClientRects').mockReturnValue([{}] as unknown as DOMRectList)
  HTMLElement.prototype.scrollIntoView = vi.fn()
  updateScenario(s => { s.enabled = true; s.open = true })
})
const guide = () => within(screen.getByRole('region', { name: 'Code Security Walkthrough' }))

describe('Code Security Walkthrough', () => {
  it('leaves the completed state when going back so the previous step can be replayed', async () => {
    updateScenario(s => { s.step = SCAN_STEPS.length - 1; s.completed = SCAN_STEPS.map(step => step.id) })
    render(<MemoryRouter initialEntries={['/vulnerability-intelligence/advisories/DEMO-CHECKOUT-004']}><ScanWalkthrough /></MemoryRouter>)
    fireEvent.click(guide().getByRole('button', { name: /^Back$/ }))
    expect(scenarioStore.getSnapshot().completed).not.toContain('finish')
    expect(scenarioStore.getSnapshot().step).toBe(SCAN_STEPS.length - 2)
    expect(guide().queryByRole('button', { name: 'Next chapter' })).not.toBeInTheDocument()
    expect(guide().getByRole('button', { name: /^Next$/ })).toBeInTheDocument()
  })
  const completedAssessment = () => ({ id: 'learn-checkout-initial', name: '', client: '', status: 'active', createdAt: '', scope: [], outOfScope: [], authorizedFrom: '', authorizedTo: '', timezone: '', tools: [], findings: [], snapshotAt: null, scan: { target: '', ref: 'main', mode: 'full', kind: 'git', startedAt: new Date().toISOString(), finishedAt: new Date().toISOString() } })

  it('waits for the rendered comparison summary and items instead of treating creation as completion', async () => {
    updateScenario(s => { s.step = 15; s.microStep = 6 })
    const run = vi.fn(() => updateScenario(s => { s.comparisonAt = new Date().toISOString() }))
    function Result() {
      const [loaded, setLoaded] = useState(false)
      return <><button onClick={run}>Run comparison</button><button onClick={() => setLoaded(true)}>Resolve comparison data</button>
        <div data-comparison-result={COMPARISON_ID} data-comparison-scope="all" data-comparison-ready={loaded}><div data-comparison-summary>{loaded ? 'Fixed 18 · 18 compared findings' : 'Loading comparison data'}</div></div>
      </>
    }
    render(<MemoryRouter initialEntries={[`/engagements/${RETEST_ID}/comparison?comparison_id=${COMPARISON_ID}`]}><Result /><ScanWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(run).toHaveBeenCalledOnce())
    expect(guide().getByRole('button', { name: 'Next' })).toBeDisabled()
    expect(scenarioStore.getSnapshot().microStep).toBe(6)
    fireEvent.click(screen.getByRole('button', { name: 'Resolve comparison data' }))
    await waitFor(() => expect(guide().getByRole('heading')).toHaveTextContent('Verify the remediation outcome'))
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    expect(scenarioStore.getSnapshot().step).toBe(15)
    expect(run).toHaveBeenCalledOnce()
  })

  it('restores the saved comparison URL and pair when resuming on the bare comparison route', async () => {
    updateScenario(s => { s.step = 15; s.comparisonAt = new Date().toISOString() })
    function SavedResult() {
      const location = useLocation()
      const params = new URLSearchParams(location.search)
      const correct = params.get('comparison_id') === COMPARISON_ID && params.get('comparison_scope') === 'all' && params.get('comparison_mode') === 'lifecycle' && params.get('comparison_base_assessment') === INITIAL_ID && params.get('comparison_baseline') === `${INITIAL_ID}-snapshot-1` && params.get('comparison_current') === `${RETEST_ID}-snapshot-1`
      return correct ? <div data-comparison-result={COMPARISON_ID} data-comparison-scope="all" data-comparison-ready="true"><div data-comparison-summary>Fixed 18</div></div> : <p>Configure a comparison</p>
    }
    render(<MemoryRouter initialEntries={[`/engagements/${RETEST_ID}/comparison`]}><SavedResult /><ScanWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText('Fixed 18')).toBeInTheDocument(), { timeout: 2500 })
    await waitFor(() => expect(guide().getByRole('heading')).toHaveTextContent('Verify the remediation outcome'))
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    expect(screen.queryByText('Configure a comparison')).not.toBeInTheDocument()
  })

  it('prefills the actual Re-test scan form in one review step and waits for its coverage', async () => {
    updateScenario(s => { s.step = 13; s.assessments = [{ ...completedAssessment(), id: RETEST_ID, scan: null }] })
    const run = vi.fn()
    function Scan() {
      const [open, setOpen] = useState(false)
      const [kind, setKind] = useState('local'), [target, setTarget] = useState('')
      const [branch, setBranch] = useState('main'), [mode, setMode] = useState<ScanMode>('vulnerabilities')
      const [codeQuality, setCodeQuality] = useState(true)
      return <><button onClick={() => setOpen(true)}>Scan settings</button>
        <ScanConfigModal open={open} onClose={() => setOpen(false)} kind={kind} setKind={setKind} mode={mode} setMode={setMode} codeQuality={codeQuality} setCodeQuality={setCodeQuality} target={target} setTarget={setTarget} branch={branch} setBranch={setBranch} usingImportedSBOM={false} importedSBOM={null} usingUploadedSource={false} uploadedSource={null} onTriggerUpload={() => undefined} sbomBusy={false} running={false} onRun={() => {
          run({ kind, target, ref: branch, mode, codeQuality }); setOpen(false)
          updateScenario(s => { s.assessments[0].scan = { kind, target, ref: branch, mode, startedAt: new Date().toISOString(), finishedAt: null } })
        }} />
        {!open && <div data-scan-inspector>Core pipeline coverage</div>}
      </>
    }
    render(<MemoryRouter initialEntries={[`/engagements/${RETEST_ID}`]}><Scan /><ScanWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(guide().getByRole('heading')).toHaveTextContent('Review the remediated revision'))
    await waitFor(() => expect(screen.getByLabelText('Git branch')).toHaveValue('remediated'))
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(guide().getByRole('heading')).toHaveTextContent('Save & Run scan'))
    fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(run).toHaveBeenCalledWith({ kind: 'git', target: TARGET, ref: 'remediated', mode: 'full', codeQuality: false }))
    await waitFor(() => expect(guide().getByRole('heading')).toHaveTextContent('Verify Re-test coverage'))
    expect(guide().getByRole('button', { name: 'Next' })).toBeDisabled()
    await act(async () => updateScenario(s => { s.assessments[0].scan!.finishedAt = new Date().toISOString() }))
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    expect(guide().getByText('Action 4 of 4')).toBeInTheDocument()
  })

  it('scrolls through actual package results without skipping the inventory after a completed scan', async () => {
    updateScenario(s => { s.step = 4; s.assessments = [completedAssessment()] })
    render(<MemoryRouter initialEntries={['/engagements/learn-checkout-initial/components']}>
      <section data-package-inventory><div data-package-summary>12 packages</div><table><tbody>
        <tr role="row"><td role="cell"><span data-package-name="checkout-parser">checkout-parser</span></td><td role="cell">1.0.0</td><td role="cell">MIT</td><td role="cell">pkg:npm/checkout-parser@1.0.0</td></tr>
        <tr role="row"><td role="cell"><span data-package-name="checkout-token">checkout-token</span></td><td role="cell">2.0.0</td><td role="cell">MIT</td><td role="cell">pkg:npm/checkout-token@2.0.0</td></tr>
      </tbody></table></section><ScanWalkthrough />
    </MemoryRouter>)
    const expected = ['Recorded package inventory', 'Package identity', 'Installed version', 'Package URL', 'Retained package for monitoring', 'Read the recorded inventory']
    for (const title of expected) {
      await waitFor(() => expect(guide().getByRole('heading')).toHaveTextContent(title))
      await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
      if (title !== expected.at(-1)) fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    }
    const scrolled = vi.mocked(HTMLElement.prototype.scrollIntoView).mock.instances as HTMLElement[]
    expect(scrolled.some(el => el.hasAttribute('data-package-summary'))).toBe(true)
    expect(scrolled.some(el => el.dataset.packageName === 'checkout-parser')).toBe(true)
    expect(scrolled.some(el => el.tagName === 'TD' && el.textContent === '1.0.0')).toBe(true)
    expect(scrolled.some(el => el.tagName === 'TD' && el.textContent === 'pkg:npm/checkout-parser@1.0.0')).toBe(true)
    expect(scrolled.some(el => el.tagName === 'TR' && el.textContent?.includes('checkout-token'))).toBe(true)
    expect(scenarioStore.getSnapshot().step).toBe(4)
  })

  it('allows completed scan phases to advance during execution and retains the phase explanation at finalization', async () => {
    const assessment = completedAssessment()
    assessment.scan.startedAt = new Date(Date.now() - PHASE_DURATION - 100).toISOString()
    updateScenario(s => { s.step = 3; s.microStep = 7; s.assessments = [{ ...assessment, scan: { ...assessment.scan, finishedAt: null } }] })
    function Pipeline() {
      const [selected, setSelected] = useState('acquiring target')
      return <details aria-label="Scan pipeline"><summary>Pipeline</summary>
        {['acquiring target', 'detecting languages'].map(stage => <button key={stage} data-scan-step={stage} aria-pressed={selected === stage} onClick={() => setSelected(stage)}>{stage}</button>)}
        <div data-scan-inspector>{selected}</div>
      </details>
    }
    render(<MemoryRouter initialEntries={['/engagements/learn-checkout-initial']}><Pipeline /><ScanWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(guide().getByRole('heading')).toHaveTextContent('Acquire the source revision'))
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(guide().getByRole('heading')).toHaveTextContent('Detect languages and manifests'))
    expect(guide().getByRole('button', { name: 'Next' })).toBeDisabled()
    await act(async () => updateScenario(s => { s.assessments[0].scan!.finishedAt = new Date().toISOString() }))
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    expect(guide().getByRole('heading')).toHaveTextContent('Detect languages and manifests')
    expect(screen.getByRole('button', { name: 'detecting languages' })).toHaveAttribute('aria-pressed', 'true')
    expect(scenarioStore.getSnapshot().microStep).toBe(8)
  })

  it('opens the form and fills controlled fields using only Next, highlighting one value at a time', async () => {
    function Form() {
      const [open, setOpen] = useState(false)
      const [values, setValues] = useState({ key: '', name: '', owner: '' })
      return <><button onClick={() => setOpen(true)}>New Asset</button>{open && <div>
        {(['key', 'name', 'owner'] as const).map(key => <label key={key}>{key[0].toUpperCase() + key.slice(1)}<input value={values[key]} onChange={event => setValues(v => ({ ...v, [key]: event.target.value }))} /></label>)}
      </div>}</>
    }
    render(<MemoryRouter initialEntries={['/assets']}><Form /><ScanWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(guide().getByRole('heading')).toHaveTextContent(/^Key$/))
    await waitFor(() => expect(screen.getByLabelText('Key')).toHaveValue('checkout-api'))
    expect(screen.getByLabelText('Key')).toHaveAttribute('data-demo-filled')
    expect(screen.getByLabelText('Name')).toHaveValue('')
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(screen.getByLabelText('Name')).toHaveValue('Checkout API'))
    expect(screen.getByLabelText('Name')).toHaveAttribute('data-demo-filled')
    expect(screen.getByLabelText('Key')).not.toHaveAttribute('data-demo-filled')
    expect(screen.getByLabelText('Key')).toHaveValue('checkout-api')
    expect(scenarioStore.getSnapshot().asset).toBeNull()
    fireEvent.click(guide().getByRole('button', { name: 'Pause code security walkthrough' }))
    expect(screen.getByLabelText('Name')).not.toHaveAttribute('data-demo-filled')
  })

  it('recovers a saved Asset checkpoint without recreating it, and pauses without losing data', async () => {
    updateScenario(s => { s.asset = { id: 'learn-checkout-asset', key: 'checkout-api', name: 'Checkout API', owner: 'Checkout Team', type: 'application', criticality: 'high', description: '', created_at: '' } })
    render(<MemoryRouter initialEntries={['/assets/checkout-api']}><ScanWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(guide().getByRole('heading')).toHaveTextContent('Create your first Asset'))
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    fireEvent.click(guide().getByRole('button', { name: 'Pause code security walkthrough' }))
    expect(screen.queryByRole('region', { name: 'Code Security Walkthrough' })).not.toBeInTheDocument()
    expect(scenarioStore.getSnapshot().asset?.key).toBe('checkout-api')
  })

  it('keeps the guide inside an active dialog and advances only after scan completion', async () => {
    updateScenario(s => { s.step = 3; s.microStep = 6 })
    const run = vi.fn()
    render(<MemoryRouter initialEntries={['/engagements/learn-checkout-initial']}><div role="dialog" aria-label="Scan Configuration"><button onClick={run}>Save &amp; Run scan</button></div><ScanWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(screen.getByRole('dialog')).toContainElement(screen.getByRole('region', { name: 'Code Security Walkthrough' })))
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(run).toHaveBeenCalledTimes(1))
    expect(guide().getByRole('button', { name: 'Next' })).toBeDisabled()
    await act(async () => updateScenario(s => { s.assessments = [{ id: 'learn-checkout-initial', name: '', client: '', status: 'active', createdAt: '', scope: [], outOfScope: [], authorizedFrom: '', authorizedTo: '', timezone: '', tools: [], findings: [], snapshotAt: null, scan: { target: '', ref: 'main', mode: 'full', kind: 'git', startedAt: '', finishedAt: new Date().toISOString() } }] }))
    await waitFor(() => expect(guide().getByRole('heading')).toHaveTextContent('Configure and run a scan'))
    expect(scenarioStore.getSnapshot().step).toBe(3)
  })

  it('ignores a closed mobile navigation dialog when positioning the guide', async () => {
    render(<MemoryRouter initialEntries={['/assets']}><div aria-hidden="true" inert><aside role="dialog" aria-label="Navigation"><button>New Asset</button></aside></div><button>New Asset</button><ScanWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(screen.getByRole('region', { name: 'Code Security Walkthrough' }).closest('[role="dialog"]')).toBeNull())
    expect(findGuideTarget({ kind: 'button', name: 'New Asset' })).toBe(screen.getByRole('button', { name: 'New Asset' }))
  })

  it('waits for the next page instead of sending a rapid Next back to the Inbox', async () => {
    updateScenario(s => { s.step = 24; s.microStep = 1; s.notificationReadAt = new Date().toISOString() })
    const inspect = vi.fn(() => updateScenario(s => { s.monitorInvestigated = true }))
    render(<MemoryRouter initialEntries={['/inbox']}><Routes>
      <Route path="/inbox" element={<p>Inbox</p>} />
      <Route path="/vulnerability-intelligence/advisories/DEMO-CHECKOUT-004" element={<button onClick={inspect}>checkout-token detected npm 2.0.0</button>} />
    </Routes><ScanWalkthrough /></MemoryRouter>)
    fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(screen.getByRole('button', { name: /checkout-token/ })).toBeInTheDocument())
    expect(scenarioStore.getSnapshot().microStep).toBe(1)
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    fireEvent.click(guide().getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(inspect).toHaveBeenCalledTimes(1))
    expect(screen.queryByText('Inbox')).not.toBeInTheDocument()
  })

  it('prefers the exact Open link over the mobile Open menu button', () => {
    render(<><button>Open menu</button><a href="/advisory">Open</a></>)
    expect(findGuideTarget({ kind: 'button', name: 'Open' })).toBe(screen.getByRole('link', { name: 'Open' }))
  })

  it('fills comparison scope through the actual modal select without activating an inert portal', async () => {
    updateScenario(s => { s.step = 15; s.microStep = 2 })
    function Comparison() {
      const [scope, setScope] = useState('vulnerabilities')
      return <ModalOverlay isOpen><Modal><Dialog aria-label="Configure comparison">
        <Select value={scope} onValueChange={setScope} ariaLabel="Comparison result scope" options={[{ value: 'vulnerabilities', label: 'Vulnerabilities' }, { value: 'all', label: 'All findings' }]} />
      </Dialog></Modal></ModalOverlay>
    }
    render(<MemoryRouter initialEntries={['/engagements/learn-checkout-retest/comparison']}><Comparison /><ScanWalkthrough /></MemoryRouter>)
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Comparison result scope' })).toHaveTextContent('All findings'))
    await waitFor(() => expect(guide().getByRole('button', { name: 'Next' })).toBeEnabled())
    expect(screen.getByRole('dialog')).toContainElement(screen.getByRole('region', { name: 'Code Security Walkthrough' }))
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
  })

  it('targets a labelled custom select and prefers modal controls over background duplicates', () => {
    render(<><label htmlFor="type">Type</label><button id="type" role="combobox">Application</button><button>Finalize snapshot</button><div role="dialog"><button data-testid="modal-finalize">Finalize snapshot</button></div></>)
    expect(findGuideTarget({ kind: 'field', name: 'Type' })).toBe(screen.getByRole('combobox'))
    expect(findGuideTarget({ kind: 'button', name: 'Finalize snapshot' })).toBe(screen.getByTestId('modal-finalize'))
    expect(emptyScenario().enabled).toBe(false)
  })


})
