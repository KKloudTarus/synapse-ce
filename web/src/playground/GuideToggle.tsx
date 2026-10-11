import './guide-presentation.css'
import { ChevronDown, ChevronUp } from '@untitledui/icons'
import { Button } from '@/components/base/buttons/button'
import { scrollGuideTarget } from './GuideSpotlight'

// The guide keeps navigation visible while its explanation can be tucked away to inspect the page.
export function GuideToggle({ minimized, onToggle }: { minimized: boolean; onToggle: () => void }) {
  return <Button size="sm" color="tertiary" iconLeading={minimized ? ChevronUp : ChevronDown} aria-label={minimized ? 'Expand guide' : 'Minimize guide'} aria-expanded={!minimized} onClick={() => {
    if (minimized) scrollGuideTarget(document.querySelector<HTMLElement>('[data-demo-focus]'))
    onToggle()
  }} />
}

export const guidePanelClass = 'demo-guide-panel fixed z-[120] flex max-h-[min(50dvh,28rem)] w-[min(32rem,calc(100vw-1rem))] flex-col overflow-hidden rounded-xl border border-secondary bg-primary p-4 shadow-xl'
