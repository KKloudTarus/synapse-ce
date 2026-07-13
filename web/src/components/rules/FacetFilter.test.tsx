import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { FacetFilter } from './FacetFilter'

describe('FacetFilter', () => {
  it('renders trigger with label', () => {
    render(<FacetFilter label="Type" values={['bug']} selected={[]} onChange={() => {}} />)
    expect(screen.getByRole('button', { name: /Type/i })).toBeInTheDocument()
  })

  it('shows selected count', () => {
    render(<FacetFilter label="Type" values={['bug', 'vulnerability']} selected={['bug', 'vulnerability']} onChange={() => {}} />)
    expect(screen.getByText('2')).toBeInTheDocument()
  })

  it('opens panel on click', () => {
    render(<FacetFilter label="Type" values={['bug']} selected={[]} onChange={() => {}} />)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Type/i }))
    expect(screen.getByRole('dialog', { name: /Filter by Type/i })).toBeInTheDocument()
  })

  it('calls onChange when selecting an option', () => {
    const onChange = vi.fn()
    render(<FacetFilter label="Type" values={['bug', 'vulnerability']} selected={[]} onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: /Type/i }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'bug' }))
    expect(onChange).toHaveBeenCalledWith(['bug'])
  })

  it('calls onChange when deselecting an option', () => {
    const onChange = vi.fn()
    render(<FacetFilter label="Type" values={['bug', 'vulnerability']} selected={['bug']} onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: /Type/i }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'bug' }))
    expect(onChange).toHaveBeenCalledWith([])
  })

  it('clears all selections', () => {
    const onChange = vi.fn()
    render(<FacetFilter label="Type" values={['bug', 'vulnerability']} selected={['bug', 'vulnerability']} onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: /Type/i }))
    fireEvent.click(screen.getByRole('button', { name: /Clear/i }))
    expect(onChange).toHaveBeenCalledWith([])
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('closes on Escape and returns focus', () => {
    render(<FacetFilter label="Type" values={['bug']} selected={[]} onChange={() => {}} />)
    const trigger = screen.getByRole('button', { name: /Type/i })
    fireEvent.click(trigger)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })

  it('closes on outside click', () => {
    render(
      <div>
        <FacetFilter label="Type" values={['bug']} selected={[]} onChange={() => {}} />
        <div data-testid="outside">Outside</div>
      </div>
    )
    fireEvent.click(screen.getByRole('button', { name: /Type/i }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByTestId('outside'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('formats values correctly', () => {
    render(
      <FacetFilter
        label="Type"
        values={['code_smell']}
        selected={[]}
        onChange={() => {}}
        formatValue={(v) => v === 'code_smell' ? 'Code smell' : v}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: /Type/i }))
    expect(screen.getByRole('checkbox', { name: 'Code smell' })).toBeInTheDocument()
  })
})
