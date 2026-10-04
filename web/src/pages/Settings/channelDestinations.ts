import type { NotificationChannelType } from '../../lib/api'

/**
 * How the channel form asks for each channel type's destination. Every chat channel's URL or bot
 * token is the credential (#1378 to #1381), so the input is a password field, the server only ever
 * returns `scheme://host/…`, and replacing it means entering the whole value again.
 */
export interface ChannelDestinationSpec {
  /** Shown in the type select. */
  label: string
  /** How the destination is entered: one URL, an email list, or a Telegram bot token and chat. */
  kind: 'url' | 'signed_url' | 'recipients' | 'telegram'
  urlLabel?: string
  placeholder?: string
  /** One sentence on where the administrator gets the value. */
  hint?: string
}

export const CHANNEL_DESTINATIONS: Record<NotificationChannelType, ChannelDestinationSpec> = {
  webhook: {
    label: 'Signed webhook',
    kind: 'signed_url',
    urlLabel: 'Webhook URL',
    placeholder: 'https://…',
  },
  slack: {
    label: 'Slack incoming webhook',
    kind: 'url',
    urlLabel: 'Slack webhook URL',
    placeholder: 'https://hooks.slack.com/services/…',
  },
  email: { label: 'Email (SMTP)', kind: 'recipients' },
  teams: {
    label: 'Microsoft Teams (Workflows)',
    kind: 'url',
    urlLabel: 'Teams Workflows webhook URL',
    placeholder: 'https://….logic.azure.com/workflows/…',
    hint: 'In Teams, add the "Post to a channel when a webhook request is received" workflow and copy its URL. Office 365 connector URLs are retired and not accepted.',
  },
  telegram: {
    label: 'Telegram bot',
    kind: 'telegram',
    hint: 'Create a bot with @BotFather, add it to the chat, then enter its token and the chat ID.',
  },
  google_chat: {
    label: 'Google Chat incoming webhook',
    kind: 'url',
    urlLabel: 'Google Chat webhook URL',
    placeholder: 'https://chat.googleapis.com/v1/spaces/…/messages?key=…&token=…',
    hint: 'In the space, open Apps & integrations → Webhooks and copy the full URL, including key and token.',
  },
  discord: {
    label: 'Discord webhook',
    kind: 'url',
    urlLabel: 'Discord webhook URL',
    placeholder: 'https://discord.com/api/webhooks/…',
    hint: 'In the channel settings, open Integrations → Webhooks and copy the webhook URL. Messages never mention anyone.',
  },
}

export const CHANNEL_TYPE_ORDER: NotificationChannelType[] = [
  'webhook',
  'slack',
  'email',
  'teams',
  'telegram',
  'google_chat',
  'discord',
]

/** The type's display name, or the raw type for one this console does not know. */
export function channelTypeLabel(type: string): string {
  return CHANNEL_DESTINATIONS[type as NotificationChannelType]?.label ?? type
}

/** The text that tells an editor what to re-enter to replace a channel's destination. */
export function replaceDestinationHint(type: NotificationChannelType): string {
  switch (CHANNEL_DESTINATIONS[type].kind) {
    case 'signed_url':
      return 'Leave URL and secret blank to keep them. To replace a webhook destination, supply both a new URL and signing secret.'
    case 'telegram':
      return 'Leave the token and chat blank to keep them. To change the bot, chat or topic, enter the bot token and chat ID again.'
    case 'recipients':
      return 'Changing the recipient list changes where this channel delivers.'
    default:
      return 'Leave the URL blank to keep it. The saved URL is never shown; to replace it, paste the full new URL.'
  }
}

/** Telegram chat IDs are numeric (groups and channels are negative) or an @channel username. */
export const TELEGRAM_CHAT_PATTERN = /^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$/
