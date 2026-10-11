import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { NotificationChannel, NotificationTemplateOption } from '../../lib/api'
import { ChannelTemplateFields, RuleTemplatePreview, describeResolution } from './ChannelTemplateBinding'

vi.mock('../../lib/api', () => ({
  api: {
    listBindableNotificationTemplates: vi.fn(),
    previewNotificationTemplateResolution: vi.fn(),
  },
}))

// jsdom lacks the element APIs Radix Select calls when it opens.
for (const name of ['scrollIntoView', 'hasPointerCapture', 'releasePointerCapture'] as const) {
  if (!(name in HTMLElement.prototype))
    Object.defineProperty(HTMLElement.prototype, name, { configurable: true, value: () => false })
}

const chatAny: NotificationTemplateOption = {
  id: 'tpl-1', name: 'Ops chat', event_type: '*', family: 'chat', locale: '*', status: 'active', active_version: 3,
}
const channel = (id: string, name: string): NotificationChannel => ({
  id, name, type: 'slack', enabled: true, destination: 'https://hooks.slack.com/services/…', revision: 1, secret_version: 1,
  created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
})

describe('ChannelTemplateFields', () => {
  beforeEach(() => vi.resetAllMocks())

  it('lists active templates of the channel family and reports the choice', async () => {
    vi.mocked(api.listBindableNotificationTemplates).mockResolvedValue([chatAny])
    const onTemplate = vi.fn()
    const onLocale = vi.fn()
    render(<ChannelTemplateFields type="slack" templateId="" locale="" onTemplateChange={onTemplate} onLocaleChange={onLocale} />)
    await waitFor(() => expect(api.listBindableNotificationTemplates).toHaveBeenCalledWith('chat'))
    const select = await screen.findByRole('combobox', { name: 'Message template' })
    await waitFor(() => expect(select).not.toBeDisabled())
    expect(select).toHaveTextContent('No binding')
    fireEvent.click(select)
    fireEvent.click(await screen.findByRole('option', { name: 'Ops chat (all events, any locale)' }))
    expect(onTemplate).toHaveBeenCalledWith('tpl-1')

    fireEvent.click(screen.getByRole('combobox', { name: 'Locale' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Vietnamese' }))
    expect(onLocale).toHaveBeenCalledWith('vi')
  })

  it('maps the unset choices back to empty strings and keeps an inactive binding visible', async () => {
    vi.mocked(api.listBindableNotificationTemplates).mockResolvedValue([])
    const onTemplate = vi.fn()
    const onLocale = vi.fn()
    render(<ChannelTemplateFields type="webhook" templateId="tpl-old" locale="vi" onTemplateChange={onTemplate} onLocaleChange={onLocale} />)
    await waitFor(() => expect(api.listBindableNotificationTemplates).toHaveBeenCalledWith('webhook'))
    const select = await screen.findByRole('combobox', { name: 'Message template' })
    await waitFor(() => expect(select).toHaveTextContent('tpl-old (not active)'))
    fireEvent.click(select)
    fireEvent.click(await screen.findByRole('option', { name: /No binding/ }))
    expect(onTemplate).toHaveBeenCalledWith('')
    fireEvent.click(screen.getByRole('combobox', { name: 'Locale' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Tenant default' }))
    expect(onLocale).toHaveBeenCalledWith('')
  })
})

describe('custom webhook body toggle', () => {
  beforeEach(() => vi.resetAllMocks())

  it('is offered on webhook channels only and needs a bound template', async () => {
    vi.mocked(api.listBindableNotificationTemplates).mockResolvedValue([])
    const onCustomBody = vi.fn()
    const { rerender } = render(
      <ChannelTemplateFields type="webhook" templateId="" locale="" onTemplateChange={vi.fn()} onLocaleChange={vi.fn()} customBody={false} onCustomBodyChange={onCustomBody} />,
    )
    const toggle = await screen.findByRole('checkbox', { name: /custom JSON body/ })
    expect(toggle).toBeDisabled()
    expect(screen.getByText(/Bind a webhook template first/)).toBeInTheDocument()

    rerender(<ChannelTemplateFields type="webhook" templateId="tpl-1" locale="" onTemplateChange={vi.fn()} onLocaleChange={vi.fn()} customBody={false} onCustomBodyChange={onCustomBody} />)
    fireEvent.click(screen.getByRole('checkbox', { name: /custom JSON body/ }))
    expect(onCustomBody).toHaveBeenCalledWith(true)

    rerender(<ChannelTemplateFields type="slack" templateId="tpl-1" locale="" onTemplateChange={vi.fn()} onLocaleChange={vi.fn()} customBody={false} onCustomBodyChange={onCustomBody} />)
    expect(screen.queryByRole('checkbox', { name: /custom JSON body/ })).not.toBeInTheDocument()
    await waitFor(() => expect(api.listBindableNotificationTemplates).toHaveBeenCalledWith('chat'))
  })
})

describe('RuleTemplatePreview', () => {
  beforeEach(() => vi.resetAllMocks())

  it('shows the template each selected channel resolves to', async () => {
    vi.mocked(api.previewNotificationTemplateResolution).mockImplementation(async (id) =>
      id === 'c1'
        ? { tier: 'channel', event_type: 'scan.completed', locale: 'vi', locale_source: 'channel', template: chatAny, version: 3 }
        : { tier: 'tenant_wildcard', event_type: 'scan.completed', locale: 'en', locale_source: 'tenant', template: { ...chatAny, id: 'tpl-2', name: 'Tenant chat' }, version: 1,
            binding_skipped: 'event_not_covered' },
    )
    render(<RuleTemplatePreview channels={[channel('c1', 'Ops'), channel('c2', 'SOC')]} eventType="scan.completed" />)
    expect(await screen.findByText(/Ops: Ops chat v3 \(channel binding, vi\)/)).toBeInTheDocument()
    expect(await screen.findByText(/SOC: Tenant chat v1 \(tenant template for all events, en\)/)).toBeInTheDocument()
    expect(screen.getByText(/does not cover this event/)).toBeInTheDocument()
    expect(api.previewNotificationTemplateResolution).toHaveBeenCalledWith('c1', 'scan.completed')
  })

  it('renders nothing when the deployment has no template API', async () => {
    vi.mocked(api.previewNotificationTemplateResolution).mockRejectedValue(new Error('not found'))
    const { container } = render(<RuleTemplatePreview channels={[channel('c1', 'Ops')]} eventType="scan.completed" />)
    await waitFor(() => expect(api.previewNotificationTemplateResolution).toHaveBeenCalled())
    await waitFor(() => expect(container).toBeEmptyDOMElement())
  })

  it('describes the built-in and fallback tiers', () => {
    expect(describeResolution({ tier: 'fallback', event_type: 'x', locale: 'en', locale_source: 'default' })).toBe('Default rendering (en)')
    expect(describeResolution({ tier: 'builtin', event_type: 'x', locale: 'vi', locale_source: 'tenant', builtin_ref: 'builtin:x' })).toBe('Built-in template (vi)')
  })
})
