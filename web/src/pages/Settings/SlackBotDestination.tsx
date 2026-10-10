import { useState } from 'react'
import { api, ApiError } from '../../lib/api'
import type { SlackConversation } from '../../lib/api'
import { Button, Field, Input, Select } from '../../components/ui'
import { SLACK_BOT_TOKEN_PATTERN, SLACK_CONVERSATION_PATTERN } from './channelDestinations'

/**
 * The destination of a Slack bot channel (#1383): a bot token, the conversation the app posts to,
 * and whether a Slack Connect or organisation-shared conversation is allowed.
 *
 * The token is write-only. The conversation picker lists what the token can post to, asking the
 * server with the token being typed, or with an existing channel's sealed token when none is typed.
 * A conversation ID can also be typed, for a workspace where listing is not granted.
 */
export function SlackBotDestinationFields({
  channelId,
  token,
  onTokenChange,
  conversationId,
  onConversationChange,
  allowShared,
  onAllowSharedChange,
  disabled,
}: {
  /** The existing channel being edited, whose stored token can list conversations. */
  channelId?: string
  token: string
  onTokenChange: (value: string) => void
  conversationId: string
  onConversationChange: (value: string) => void
  allowShared: boolean
  onAllowSharedChange: (value: boolean) => void
  disabled: boolean
}) {
  const [conversations, setConversations] = useState<SlackConversation[] | null>(null)
  const [workspace, setWorkspace] = useState('')
  const [truncated, setTruncated] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const typedToken = token.trim()
  const canList = !disabled && (SLACK_BOT_TOKEN_PATTERN.test(typedToken) || (!typedToken && !!channelId))
  const selected = conversations?.find((c) => c.id === conversationId.trim())

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const result = await api.listSlackConversations(
        typedToken ? { bot_token: typedToken } : { channel_id: channelId ?? '' },
      )
      setConversations(result.items)
      setWorkspace(result.team_name || result.team_id)
      setTruncated(result.truncated)
    } catch (e) {
      setConversations(null)
      setError(e instanceof ApiError ? e.message : 'Could not list Slack conversations')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <Field
        label="Bot token"
        htmlFor="notification-slack-token"
        hint={
          channelId
            ? 'Write-only. Enter it again to change the app, the conversation or the shared setting.'
            : 'Write-only after save. Starts with xoxb-.'
        }
      >
        <Input
          id="notification-slack-token"
          type="password"
          disabled={disabled}
          value={token}
          onChange={(e) => {
            onTokenChange(e.target.value)
            // A different token is a different workspace; its conversations must be listed again.
            setConversations(null)
          }}
          placeholder="xoxb-…"
          autoComplete="new-password"
        />
      </Field>
      <Field
        label="Conversation ID"
        htmlFor="notification-slack-conversation"
        hint="The channel ID (C…), from Load channels or from the channel's details in Slack."
      >
        <Input
          id="notification-slack-conversation"
          disabled={disabled}
          value={conversationId}
          onChange={(e) => onConversationChange(e.target.value)}
          placeholder={channelId ? 'Unchanged' : 'C0123456789'}
          autoComplete="off"
        />
      </Field>
      <div className="flex flex-col gap-2 md:col-span-2">
        <div className="flex flex-wrap items-center gap-3">
          <Button type="button" variant="secondary" disabled={!canList} loading={loading} onClick={load}>
            Load channels
          </Button>
          {conversations && (
            <span className="text-sm text-tertiary">
              {conversations.length} channel{conversations.length === 1 ? '' : 's'} in {workspace}
              {truncated && ' (first 2,000 only; type the ID of any other)'}
            </span>
          )}
        </div>
        {error && (
          <p role="alert" className="text-sm text-error-primary">
            {error}
          </p>
        )}
        {conversations && conversations.length > 0 && (
          <Field label="Slack channel" htmlFor="notification-slack-picker">
            <Select
              id="notification-slack-picker"
              disabled={disabled}
              value={selected?.id ?? ''}
              placeholder="Choose a channel"
              onValueChange={onConversationChange}
              options={conversations.map((c) => ({ value: c.id, label: conversationLabel(c) }))}
            />
          </Field>
        )}
        {selected?.is_private && !selected.is_member && (
          <p className="text-sm text-warning-primary">
            The app is not in #{selected.name}. Invite it to the channel before saving.
          </p>
        )}
        {selected?.is_shared && !allowShared && (
          <p className="text-sm text-warning-primary">
            #{selected.name} is shared with another workspace or organisation. Allow shared
            conversations below to post into it.
          </p>
        )}
      </div>
      <label className="flex items-start gap-2 text-sm text-secondary md:col-span-2">
        <input
          type="checkbox"
          checked={allowShared}
          disabled={disabled}
          onChange={(e) => onAllowSharedChange(e.target.checked)}
        />
        <span>
          Allow Slack Connect and organisation-shared conversations. People outside this workspace
          can read what is posted there. Without this, a channel that becomes shared later stops
          receiving messages.
        </span>
      </label>
    </>
  )
}

function conversationLabel(c: SlackConversation): string {
  const notes = [c.is_private && 'private', c.is_shared && 'shared', c.is_private && !c.is_member && 'app not invited']
    .filter(Boolean)
    .join(', ')
  return `#${c.name}${notes ? ` (${notes})` : ''}`
}

/** Whether the Slack bot fields form a complete new destination, or none for a rename. */
export function slackBotDestinationValid(
  editing: boolean,
  token: string,
  conversationId: string,
  allowShared: boolean,
  initialAllowShared = false,
): boolean {
  const touched = !!token.trim() || !!conversationId.trim() || allowShared !== initialAllowShared
  if (editing && !touched) return true
  return SLACK_BOT_TOKEN_PATTERN.test(token.trim()) && SLACK_CONVERSATION_PATTERN.test(conversationId.trim())
}
