import { act, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, type NotificationChannel, type NotificationEventSpec, type NotificationTemplatePreview } from '../../../lib/api'
import { PREVIEW_DEBOUNCE_MS, PreviewPanel } from './PreviewPanel'

vi.mock('../../../lib/api', async (original) => ({
  ...(await original<typeof import('../../../lib/api')>()),
  api: {
    listNotificationChannels: vi.fn(),
    listNotificationTemplatePreviewEvents: vi.fn(),
    previewNotificationTemplate: vi.fn(),
    sendNotificationTemplatePreviewTest: vi.fn(),
  },
}))

const CHANNEL: NotificationChannel = {
  id: 'email-1', name: 'Security mail', type: 'email', enabled: true, destination: 'security@example.test', revision: 1, secret_version: 0,
  created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
}
const CATALOG = [{ type: 'incident.created', label: 'Incident created', variables: [] }] as unknown as NotificationEventSpec[]

function preview(overrides: Partial<NotificationTemplatePreview> = {}): NotificationTemplatePreview {
  return {
    rendered: true,
    channel: { id: 'email-1', name: 'Security mail', type: 'email', family: 'email' },
    sample: { source: 'fixture', event_type: 'incident.created' },
    message: { template_ref: 'draft:example', fields: { subject: 'Incident', body: 'Preview body' } },
    ...overrides,
  }
}

async function renderPreview(fields: Record<string, string> = { subject: 'Incident', body: 'Preview body' }) {
  const result = render(<PreviewPanel templateId="template-1" templateEventType="incident.created" family="email" fields={fields} catalog={CATALOG} />)
  await act(async () => { await Promise.resolve() })
  await act(async () => { await Promise.resolve() })
  screen.getByRole('combobox', { name: 'Preview channel' })
  return result
}

async function settlePreview() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(PREVIEW_DEBOUNCE_MS)
  })
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.mocked(api.listNotificationChannels).mockResolvedValue([CHANNEL])
  vi.mocked(api.listNotificationTemplatePreviewEvents).mockResolvedValue([])
  vi.mocked(api.previewNotificationTemplate).mockResolvedValue(preview())
  vi.mocked(api.sendNotificationTemplatePreviewTest).mockResolvedValue({ delivery_id: 'delivery-1', state: 'pending' } as never)
})
afterEach(() => {
  vi.useRealTimers()
  vi.resetAllMocks()
})

describe('PreviewPanel', () => {
  it('renders the current draft from the safe fixture by default', async () => {
    await renderPreview()
    await settlePreview()
    expect(api.previewNotificationTemplate).toHaveBeenCalledWith({
      channel_id: 'email-1', event_type: 'incident.created', event_id: undefined, template_id: 'template-1', fields: { subject: 'Incident', body: 'Preview body' },
    })
    expect(screen.getByText('Preview body')).toBeInTheDocument()
  })

  it('does not inject hostile rendered text into the page', async () => {
    vi.mocked(api.previewNotificationTemplate).mockResolvedValue(preview({
      channel: { id: 'chat-1', name: 'SOC chat', type: 'slack', family: 'chat' },
      message: { template_ref: 'draft:example', fields: { title: 'A title', body: '<script>window.pwned = true</script> **safe**' } },
    }))
    vi.mocked(api.listNotificationChannels).mockResolvedValue([{ ...CHANNEL, id: 'chat-1', type: 'slack' }])
    render(<PreviewPanel templateEventType="incident.created" family="chat" fields={{ title: 'A', body: 'B' }} catalog={CATALOG} />)
    await act(async () => { await Promise.resolve() })
    await act(async () => { await Promise.resolve() })
    screen.getByRole('combobox', { name: 'Preview channel' })
    await settlePreview()
    expect(screen.getByText(/<script>window\.pwned/)).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
  })

  it('uses a CSP-restricted sandbox for formatted email HTML', async () => {
    vi.mocked(api.previewNotificationTemplate).mockResolvedValue(preview({ formatted: { content_type: 'text/html', body: 'ignored', html_body: '<script>window.pwned = true</script><p>Mail</p>', subject: 'Email subject' } }))
    await renderPreview()
    await settlePreview()
    const frame = screen.getByTitle('Email preview')
    expect(frame).toHaveAttribute('sandbox', '')
    expect(frame.getAttribute('srcdoc')).toContain("default-src 'none'")
    expect(frame.getAttribute('srcdoc')).toContain('name="color-scheme" content="light"')
    expect(frame.getAttribute('srcdoc')).toContain('color: #101828; background: #fff')
    expect(frame.getAttribute('srcdoc')).toContain('<script>window.pwned = true</script>')
  })

  it('shows chat severity and safe console links sent by the formatter', async () => {
    vi.mocked(api.listNotificationChannels).mockResolvedValue([{ ...CHANNEL, id: 'chat-1', type: 'slack' }])
    vi.mocked(api.previewNotificationTemplate).mockResolvedValue(preview({
      channel: { id: 'chat-1', name: 'SOC chat', type: 'slack', family: 'chat' },
      message: { template_ref: 'draft:example', fields: { title: '**Incident** a\\_b', body: 'Review the incident' }, severity: 'high', links: [
        { label: 'Open incident', url: 'https://console.example/fleet/incidents/example' },
        { label: 'Unsafe link', url: 'javascript:alert(1)' },
        { label: 'Credential link', url: 'https://user:secret@console.example/' },
      ] },
    }))
    render(<PreviewPanel templateEventType="incident.created" family="chat" fields={{ title: 'A', body: 'B' }} catalog={CATALOG} />)
    await act(async () => { await Promise.resolve() })
    await act(async () => { await Promise.resolve() })
    await settlePreview()
    expect(screen.getByLabelText('Severity: high')).toBeInTheDocument()
    expect(screen.getByText('Incident', { selector: 'strong' })).toBeInTheDocument()
    expect(screen.getByText(/a_b/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open incident' })).toHaveAttribute('href', 'https://console.example/fleet/incidents/example')
    expect(screen.queryByRole('link', { name: 'Unsafe link' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Credential link' })).not.toBeInTheDocument()
  })

  it('presents the chat title before its body regardless of JSON field order', async () => {
    vi.mocked(api.listNotificationChannels).mockResolvedValue([{ ...CHANNEL, id: 'chat-1', type: 'slack' }])
    vi.mocked(api.previewNotificationTemplate).mockResolvedValue(preview({
      channel: { id: 'chat-1', name: 'SOC chat', type: 'slack', family: 'chat' },
      message: { template_ref: 'draft:example', fields: { body: 'Review the incident', title: 'Incident opened' }, severity: 'high' },
    }))
    render(<PreviewPanel templateEventType="incident.created" family="chat" fields={{ title: 'A', body: 'B' }} catalog={CATALOG} />)
    await act(async () => { await Promise.resolve() })
    await act(async () => { await Promise.resolve() })
    await settlePreview()
    const message = screen.getByLabelText('Rendered message preview')
    const title = within(message).getByText('Incident opened')
    const body = within(message).getByText('Review the incident')
    expect(title.compareDocumentPosition(body) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(within(message).queryByText('title', { exact: true })).not.toBeInTheDocument()
    expect(within(message).queryByText('body', { exact: true })).not.toBeInTheDocument()
    expect(within(message).getByLabelText('Severity: high')).toHaveTextContent('High')
  })

  it('shows a webhook body as inert text', async () => {
    vi.mocked(api.listNotificationChannels).mockResolvedValue([{ ...CHANNEL, id: 'hook-1', type: 'webhook' }])
    vi.mocked(api.previewNotificationTemplate).mockResolvedValue(preview({
      channel: { id: 'hook-1', name: 'Webhook', type: 'webhook', family: 'webhook' },
      message: undefined,
      webhook: { content_type: 'application/json', body: '{"body":"<script>window.pwned = true</script>"}', custom: true },
    }))
    render(<PreviewPanel templateEventType="incident.created" family="webhook" fields={{ body: 'x' }} catalog={CATALOG} />)
    await act(async () => { await Promise.resolve() })
    await act(async () => { await Promise.resolve() })
    await settlePreview()
    expect(screen.getByText(/<script>window\.pwned/)).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
  })

  it('ignores a stale response after draft text changes', async () => {
    let resolveFirst: (value: NotificationTemplatePreview) => void = () => undefined
    let resolveSecond: (value: NotificationTemplatePreview) => void = () => undefined
    vi.mocked(api.previewNotificationTemplate)
      .mockImplementationOnce(() => new Promise((resolve) => { resolveFirst = resolve }))
      .mockImplementationOnce(() => new Promise((resolve) => { resolveSecond = resolve }))
    const { rerender } = await renderPreview({ subject: 'A', body: 'First' })
    await settlePreview()
    rerender(<PreviewPanel templateId="template-1" templateEventType="incident.created" family="email" fields={{ subject: 'B', body: 'Second' }} catalog={CATALOG} />)
    await settlePreview()
    await act(async () => { resolveSecond(preview({ message: { template_ref: 'draft:2', fields: { subject: 'B', body: 'Second response' } } })) })
    expect(screen.getByText('Second response')).toBeInTheDocument()
    await act(async () => { resolveFirst(preview({ message: { template_ref: 'draft:1', fields: { subject: 'A', body: 'Stale response' } } })) })
    expect(screen.queryByText('Stale response')).not.toBeInTheDocument()
  })

  it('explains suppression without exposing preview input', async () => {
    vi.mocked(api.previewNotificationTemplate).mockResolvedValueOnce(preview({ suppressed: true, message: undefined }))
    await renderPreview()
    await settlePreview()
    expect(screen.getByText('Delivery is suppressed')).toBeInTheDocument()
  })

  it('shows the safe fallback content alongside its explanation', async () => {
    vi.mocked(api.previewNotificationTemplate).mockResolvedValueOnce(preview({
      fallback: true,
      message: { template_ref: 'fallback', fields: { subject: 'Fallback subject', body: 'Safe fallback body' } },
    }))
    await renderPreview()
    await settlePreview()
    expect(screen.getByText('Provider fallback would be used')).toBeInTheDocument()
    expect(screen.getByText('Safe fallback body')).toBeInTheDocument()
  })

  it('explains preview rate limits', async () => {
    vi.mocked(api.previewNotificationTemplate).mockRejectedValueOnce(new ApiError(429, 'slow down'))
    await renderPreview()
    await settlePreview()
    expect(screen.getByText(/temporarily rate limited/)).toBeInTheDocument()
  })

  it('sends a fixture test even when an operator has picked a recent-event preview', async () => {
    vi.mocked(api.listNotificationTemplatePreviewEvents).mockResolvedValue([{ id: 'recent-event', event_type: 'incident.created', occurred_at: '2026-10-16T00:00:00Z' }])
    await renderPreview()
    await act(async () => { await Promise.resolve() })
    fireEvent.click(screen.getByRole('combobox', { name: 'Preview sample' }))
    fireEvent.click(screen.getByRole('option', { name: /10\/16\/2026/ }))
    await settlePreview()
    fireEvent.click(screen.getByRole('button', { name: 'Send fixture test' }))
    await act(async () => { await Promise.resolve() })
    expect(api.sendNotificationTemplatePreviewTest).toHaveBeenCalledWith({
      channel_id: 'email-1', event_type: 'incident.created', template_id: 'template-1', fields: { subject: 'Incident', body: 'Preview body' },
    })
    expect(screen.getByText('Fixture test queued (delivery-1).')).toBeInTheDocument()
  })

  it('explains fixture test rate limits', async () => {
    vi.mocked(api.sendNotificationTemplatePreviewTest).mockRejectedValue(new ApiError(503, 'busy'))
    await renderPreview()
    await settlePreview()
    fireEvent.click(screen.getByRole('button', { name: 'Send fixture test' }))
    await act(async () => { await Promise.resolve() })
    expect(screen.getByText(/Test sends are temporarily rate limited/)).toBeInTheDocument()
  })
})
