// Package messageformat turns rendered message content, a notification or a ticket body, into each
// destination's wire format (EPIC #1327 D5, step 3). The notification formatters implement
// ports.NotificationFormatter, so delivery and the API preview produce the same bytes; ticketing
// uses the Jira renderers.
//
// Every formatter starts from the same syntax tree, msgmarkdown.Parse of the rendered fields. Where
// a channel offers a structured form that shows text literally, the formatter uses it (Slack
// rich_text, Teams TextRun, Jira ADF text nodes). Where it only takes markup, every text node is
// escaped by that channel's documented rules (HTML for email and Google Chat, MarkdownV2 for
// Telegram, Markdown for Discord, wiki markup for Jira Data Center). Either way a value cannot
// become a mention, a link or formatting in any channel, whatever characters it holds.
//
// Links come only from ports.RenderedMessage.Links, are checked to be absolute https URLs without
// credentials, and are placed by the formatter after the content.
//
// Slack, Email, TeamsFormatter, TelegramFormatter, GoogleChatFormatter and DiscordFormatter are
// registered as ports.NotificationFormatter, one per channel type. JiraADF and JiraWiki render
// ticket bodies for Jira Cloud and Data Center.
package messageformat
