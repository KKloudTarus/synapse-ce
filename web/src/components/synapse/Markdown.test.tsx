import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Markdown } from './Markdown'

describe('Markdown literal punctuation', () => {
  it('preserves escaped user text while rendering static emphasis', () => {
    const { container } = render(<Markdown>{'**Alert** a\\_b \\*literal\\* \\[label\\]\\(https://example.test\\) <script>unsafe()</script>'}</Markdown>)
    expect(screen.getByText('Alert', { selector: 'strong' })).toBeInTheDocument()
    expect(container).toHaveTextContent('a_b *literal* [label](https://example.test) <script>unsafe()</script>')
    expect(container.querySelector('em, a, script')).toBeNull()
  })

  it('does not close emphasis at an escaped delimiter or unescape code spans', () => {
    render(<Markdown>{'*one\\*two* `a\\_b`'}</Markdown>)
    expect(screen.getByText('one*two', { selector: 'em' })).toBeInTheDocument()
    expect(screen.getByText('a\\_b', { selector: 'code' })).toBeInTheDocument()
  })
})
