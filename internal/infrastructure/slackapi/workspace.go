package slackapi

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Workspace adapts Client to ports.SlackWorkspace.
type Workspace struct{ Client *Client }

var _ ports.SlackWorkspace = Workspace{}

// Identify implements ports.SlackWorkspace.
func (w Workspace) Identify(ctx context.Context, token string) (ports.SlackIdentity, error) {
	id, err := w.Client.AuthTest(ctx, token)
	if err != nil {
		return ports.SlackIdentity{}, AsError(err)
	}
	return ports.SlackIdentity{TeamID: id.TeamID, TeamName: id.TeamName, BotUserID: id.BotUserID}, nil
}

// Conversation implements ports.SlackWorkspace.
func (w Workspace) Conversation(ctx context.Context, token, id string) (ports.SlackConversation, error) {
	c, err := w.Client.ConversationInfo(ctx, token, id)
	if err != nil {
		return ports.SlackConversation{}, AsError(err)
	}
	return portConversation(c), nil
}

// Conversations implements ports.SlackWorkspace.
func (w Workspace) Conversations(ctx context.Context, token string) ([]ports.SlackConversation, bool, error) {
	items, truncated, err := w.Client.ListConversations(ctx, token)
	if err != nil {
		return nil, false, AsError(err)
	}
	out := make([]ports.SlackConversation, 0, len(items))
	for _, c := range items {
		out = append(out, portConversation(c))
	}
	return out, truncated, nil
}

func portConversation(c Conversation) ports.SlackConversation {
	return ports.SlackConversation{ID: c.ID, Name: c.Name, Private: c.Private, Shared: c.SharedAnyway(), Archived: c.Archived, Member: c.Member}
}
