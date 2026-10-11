package ports

import "context"

// SlackWorkspace reads a Slack workspace through a bot token (#1383). The notification service
// uses it when an administrator saves a Slack bot channel, to identify the workspace and refuse a
// shared or archived conversation, and to fill the console's conversation picker.
//
// Errors implement SlackErrorCoder and their text is only a stable code; the token never appears
// in an error.
type SlackWorkspace interface {
	Identify(ctx context.Context, token string) (SlackIdentity, error)
	Conversation(ctx context.Context, token, id string) (SlackConversation, error)
	// Conversations lists public channels and the private channels the bot is in. truncated
	// reports that the workspace had more than one listing returns.
	Conversations(ctx context.Context, token string) (items []SlackConversation, truncated bool, err error)
}

// SlackIdentity is the workspace and bot user of a token.
type SlackIdentity struct {
	TeamID    string
	TeamName  string
	BotUserID string
}

// SlackConversation is the metadata the console shows and the shared-channel check reads.
type SlackConversation struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Private bool   `json:"is_private"`
	// Shared is true for a Slack Connect, externally shared or organisation-shared conversation.
	Shared   bool `json:"is_shared"`
	Archived bool `json:"is_archived"`
	Member   bool `json:"is_member"`
}

// SlackErrorCoder is implemented by SlackWorkspace errors: SlackCode is Slack's error string
// (invalid_auth, channel_not_found, …) or a transport code, never free text.
type SlackErrorCoder interface {
	SlackCode() string
}
