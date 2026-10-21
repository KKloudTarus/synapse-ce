import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { TicketPreview } from '../../../lib/api'
import { TicketPreviewView } from './TicketPreviewView'

const preview = (fields: Record<string, unknown>, description = 'Fallback description'): TicketPreview => ({
  fields,
  summary: 'SEC: SQL injection',
  description,
  dataClass: 'summary',
  digest: 'digest',
  mappingVersion: 1,
  links: [{ label: 'Finding SEC-1', url: 'https://console.example/findings/1' }],
})

describe('TicketPreviewView', () => {
  it('shows only the snapshot-bound destination and blocks an undisclosed legacy response', () => {
    const { rerender } = render(<TicketPreviewView preview={{ ...preview({ project: { key: 'owner/repo' }, issuetype: { id: 'issue' } }), provider: 'gitlab-issues', endpoint: 'https://bound.gitlab.example' }} />)
    expect(screen.getByLabelText('Authoritative ticket destination')).toHaveTextContent('gitlab-issues')
    expect(screen.getByLabelText('Authoritative ticket destination')).toHaveTextContent('https://bound.gitlab.example')
    rerender(<TicketPreviewView preview={preview({})} />)
    expect(screen.getByRole('alert')).toHaveTextContent('does not disclose a destination bound to its digest')
  })

  it('renders the provider-ready Cloud ADF without exposing escaped formatter input', () => {
    const { container } = render(<TicketPreviewView preview={preview({ description: {
      type: 'doc', version: 1, content: [
        { type: 'paragraph', content: [
          { type: 'text', text: 'Finding: Sandbox: SQL injection — tiếng Việt; literal *, _, and `code` stay. ' },
          { type: 'text', text: 'bold', marks: [{ type: 'strong' }] },
          { type: 'text', text: ' / ' },
          { type: 'text', text: 'italic', marks: [{ type: 'em' }] },
          { type: 'text', text: ' / ' },
          { type: 'text', text: '<script>window.pwned = true</script>', marks: [{ type: 'code' }] },
          { type: 'text', text: ' / ' },
          { type: 'text', text: 'Finding SEC-1', marks: [{ type: 'link', attrs: { href: 'https://console.example/findings/1' } }] },
          { type: 'text', text: ' / ' },
          { type: 'text', text: 'unsafe link', marks: [{ type: 'link', attrs: { href: 'javascript:alert(1)' } }] },
        ] },
        { type: 'bulletList', content: [{ type: 'listItem', content: [{ type: 'paragraph', content: [{ type: 'text', text: 'Mục tiếng Việt' }] }] }] },
      ],
    } })} />)

    expect(screen.getByText(/Finding: Sandbox: SQL injection — tiếng Việt; literal \*, _, and `code` stay/)).toBeInTheDocument()
    expect(screen.getByText('bold').tagName).toBe('STRONG')
    expect(screen.getByText('italic').tagName).toBe('EM')
    expect(screen.getByText('<script>window.pwned = true</script>').tagName).toBe('CODE')
    expect(screen.getByRole('link', { name: 'Finding SEC-1' })).toHaveAttribute('href', 'https://console.example/findings/1')
    expect(screen.queryByRole('link', { name: 'unsafe link' })).not.toBeInTheDocument()
    expect(screen.getByText('Mục tiếng Việt').closest('li')).toBeInTheDocument()
    expect(container.querySelector('script')).toBeNull()
  })

  it('renders Data Center wiki output with literal escapes, marks, lists, and trusted links', () => {
    const { container } = render(<TicketPreviewView preview={preview({
      description: 'Finding&#58; Sandbox\\*literal\\* and `literal code` *bold* _italic_ {{code &amp; <script>window.pwned = true</script>}}\n\n* Mục tiếng Việt\n* [Finding SEC-1|https://console.example/findings/1]\n* [unsafe|javascript:alert(1)]',
    })} />)

    expect(screen.getByText(/Finding: Sandbox\*literal\* and `literal code`/)).toBeInTheDocument()
    expect(screen.getByText('bold').closest('strong')).toBeInTheDocument()
    expect(screen.getByText('italic').closest('em')).toBeInTheDocument()
    expect(screen.getByText('code & <script>window.pwned = true</script>').tagName).toBe('CODE')
    expect(screen.getByRole('link', { name: 'Finding SEC-1' })).toHaveAttribute('href', 'https://console.example/findings/1')
    expect(screen.queryByRole('link', { name: 'unsafe' })).not.toBeInTheDocument()
    expect(screen.getByText('[unsafe|javascript:alert(1)]')).toBeInTheDocument()
    expect(container.querySelector('script')).toBeNull()
  })

  it('matches Data Center bracket-escaped trusted IPv6 links without decoding untrusted markup', () => {
    const ipv6URL = 'https://[2001:db8::1]/engagements/e1/findings#finding-f1'
    render(<TicketPreviewView preview={{ ...preview({
      description: '[Open finding|https://%5B2001:db8::1%5D/engagements/e1/findings#finding-f1]\n[untrusted|https://%5B2001:db8::2%5D/engagements/e1/findings#finding-f1]',
    }), links: [{ label: 'Open finding', url: ipv6URL }] }} />)

    expect(screen.getByRole('link', { name: 'Open finding' })).toHaveAttribute('href', ipv6URL)
    expect(screen.queryByRole('link', { name: 'untrusted' })).not.toBeInTheDocument()
    expect(screen.getByText('[untrusted|https://%5B2001:db8::2%5D/engagements/e1/findings#finding-f1]')).toBeInTheDocument()
  })

  it('falls back to the supported description when the provider payload is unavailable', () => {
    render(<TicketPreviewView preview={preview({})} />)
    expect(screen.getByText('Fallback description')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Finding SEC-1' })).toHaveAttribute('href', 'https://console.example/findings/1')
  })
})
