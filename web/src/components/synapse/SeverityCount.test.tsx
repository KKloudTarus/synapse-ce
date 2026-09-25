import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { SeverityBuckets } from './SeverityCount'

const counts = { critical: 1, high: 1, medium: 1, low: 0 }

describe('SeverityBuckets', () => {
  it('reports every bucket plus the total', () => {
    render(<SeverityBuckets counts={counts} total={3} />)

    expect(screen.getByText('crit')).toBeInTheDocument()
    expect(screen.getByText('high')).toBeInTheDocument()
    expect(screen.getByText('med')).toBeInTheDocument()
    expect(screen.getByText('low')).toBeInTheDocument()
  })

  // A total above the sum of the rated buckets is unrated exposure, and it has to be named: a row
  // that shows only the rated buckets under-reports what is open.
  it('names the remainder as unrated rather than dropping it', () => {
    render(<SeverityBuckets counts={counts} total={4} />)

    expect(screen.getByText('unrated')).toBeInTheDocument()
    expect(screen.getByTitle(/4 open: 1 critical, 1 high, 1 medium, 0 low, 1 unrated/)).toBeInTheDocument()
  })

  // The unrated group made this line wider than the table cell holding it. With nowrap the text ran
  // past the cell into the next column, so a row read as "1 unratedNot scanned". The groups now
  // wrap, and each group keeps its own number and label on one line.
  it('wraps its groups instead of running past the cell that holds it', () => {
    const { container } = render(<SeverityBuckets counts={counts} total={4} />)
    const line = container.firstElementChild as HTMLElement

    expect(line.className).toContain('flex-wrap')
    expect(line.className).not.toContain('whitespace-nowrap')
    const groups = [...line.querySelectorAll(':scope > span.inline-flex')]
    expect(groups.length).toBe(5)
    for (const group of groups) expect(group.className).toContain('whitespace-nowrap')
  })

  it('omits the unrated group when every finding is rated', () => {
    render(<SeverityBuckets counts={counts} total={3} />)

    expect(screen.queryByText('unrated')).not.toBeInTheDocument()
  })
})
