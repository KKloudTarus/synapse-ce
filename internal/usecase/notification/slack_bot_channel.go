package notification

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Slack bot mode (#1383). A Slack app posts to one conversation with chat.postMessage, so unlike
// an incoming webhook it can thread follow-ups (#1384) and, later, send direct messages (#1419).
// The bot token is the credential: it is sealed with the channel and never returned. The Web API
// host is always slack.com; a tenant never supplies a host.

var (
	slackBotToken = regexp.MustCompile(`^xoxb-[0-9A-Za-z-]{10,250}$`)
	// Slack conversation IDs: C… for public and newer private channels, G… for older private
	// channels. Direct messages (D…) are not a channel destination.
	slackConversationID = regexp.MustCompile(`^[CG][A-Z0-9]{8,20}$`)
)

// slackBotDestination is the masked destination of every Slack bot channel. The conversation ID is
// not secret, but the console has no use for it without its name, which can change in Slack.
const slackBotDestination = "https://slack.com/…"

var (
	errSlackUnavailable      = fmt.Errorf("%w: Slack bot channels are not available in this deployment", shared.ErrValidation)
	errDestinationUnverified = fmt.Errorf("%w: the destination changed while it was being checked; save it again", shared.ErrConflict)
	errSlackShared           = fmt.Errorf("%w: the Slack conversation is shared with another workspace or organisation; an administrator must allow shared conversations for this channel", shared.ErrValidation)
)

func validateSlackBotChannel(in ChannelInput, _ bool) (ports.NotificationChannelConfig, string, []string, error) {
	token := strings.TrimSpace(in.Secret)
	conversation := strings.TrimSpace(in.ConversationID)
	if !slackBotToken.MatchString(token) {
		// The message never echoes the token, even a malformed one.
		return nil, "", nil, fmt.Errorf("%w: Slack bot channel requires a bot token (xoxb-…)", shared.ErrValidation)
	}
	if !slackConversationID.MatchString(conversation) {
		return nil, "", nil, fmt.Errorf("%w: Slack conversation must be a channel ID such as C0123456789", shared.ErrValidation)
	}
	return ports.SlackBotChannelConfig{BotToken: token, ChannelID: conversation, AllowShared: in.AllowSharedConversation}, slackBotDestination, nil, nil
}

// SetSlackWorkspace wires the Slack Web API reader (#1383). Without it Slack bot channels cannot be
// created or re-pointed, because the workspace and the shared-conversation check cannot be read.
func (s *Service) SetSlackWorkspace(workspace ports.SlackWorkspace) { s.slack = workspace }

// verifyDestination checks a destination against its provider before it is sealed. Only Slack bot
// channels need it today: the token must be a bot token of a reachable workspace, and the
// conversation must exist, not be archived, admit the bot, and not be shared unless allowed.
func (s *Service) verifyDestination(ctx context.Context, config ports.NotificationChannelConfig) (ports.NotificationChannelConfig, error) {
	cfg, ok := config.(ports.SlackBotChannelConfig)
	if !ok {
		return config, nil
	}
	if s.slack == nil {
		return nil, errSlackUnavailable
	}
	identity, err := s.slack.Identify(ctx, cfg.BotToken)
	if err != nil {
		return nil, slackValidationError("the bot token was refused", err)
	}
	conversation, err := s.slack.Conversation(ctx, cfg.BotToken, cfg.ChannelID)
	if err != nil {
		return nil, slackValidationError("the conversation could not be read", err)
	}
	switch {
	case conversation.Archived:
		return nil, fmt.Errorf("%w: the Slack conversation is archived", shared.ErrValidation)
	case conversation.Private && !conversation.Member:
		return nil, fmt.Errorf("%w: invite the Slack app to the private conversation first", shared.ErrValidation)
	case conversation.Shared && !cfg.AllowShared:
		return nil, errSlackShared
	}
	cfg.TeamID = identity.TeamID
	return cfg, nil
}

// slackValidationError turns a Slack error into a validation error that names Slack's code, which
// tells an administrator what to fix (invalid_auth, missing_scope, channel_not_found) and holds no
// secret.
func slackValidationError(what string, err error) error {
	code := "slack_error"
	var coder ports.SlackErrorCoder
	if errors.As(err, &coder) && coder.SlackCode() != "" {
		code = coder.SlackCode()
	}
	return fmt.Errorf("%w: Slack bot channel: %s (%s)", shared.ErrValidation, what, code)
}

// SlackConversationsInput selects the bot token whose conversations are listed: a token the
// administrator is entering, or the sealed token of an existing Slack bot channel.
type SlackConversationsInput struct {
	BotToken  string    `json:"bot_token,omitempty"`
	ChannelID shared.ID `json:"channel_id,omitempty"`
}

// SlackConversations is the console's conversation picker.
type SlackConversations struct {
	TeamID    string                    `json:"team_id"`
	TeamName  string                    `json:"team_name"`
	Items     []ports.SlackConversation `json:"items"`
	Truncated bool                      `json:"truncated"`
}

// ListSlackConversations lists the conversations a Slack bot token can post to, for the channel
// form's picker. Shared conversations are listed and marked, so the console can explain why one is
// refused. The token is never returned.
func (s *Service) ListSlackConversations(ctx context.Context, in SlackConversationsInput) (SlackConversations, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return SlackConversations{}, err
	}
	if err = s.refuseDisabled(domain.ChannelSlackBot); err != nil {
		return SlackConversations{}, err
	}
	if s.slack == nil {
		return SlackConversations{}, errSlackUnavailable
	}
	token := strings.TrimSpace(in.BotToken)
	switch {
	case token != "" && !in.ChannelID.IsZero():
		return SlackConversations{}, fmt.Errorf("%w: give a bot token or a channel, not both", shared.ErrValidation)
	case token != "":
		if !slackBotToken.MatchString(token) {
			return SlackConversations{}, fmt.Errorf("%w: Slack bot channel requires a bot token (xoxb-…)", shared.ErrValidation)
		}
	case !in.ChannelID.IsZero():
		cfg, e := s.openSlackBotConfig(ctx, tenant, in.ChannelID)
		if e != nil {
			return SlackConversations{}, e
		}
		token = cfg.BotToken
	default:
		return SlackConversations{}, fmt.Errorf("%w: a bot token or a Slack bot channel is required", shared.ErrValidation)
	}
	identity, err := s.slack.Identify(ctx, token)
	if err != nil {
		return SlackConversations{}, slackValidationError("the bot token was refused", err)
	}
	items, truncated, err := s.slack.Conversations(ctx, token)
	if err != nil {
		return SlackConversations{}, slackValidationError("the conversations could not be listed", err)
	}
	out := make([]ports.SlackConversation, 0, len(items))
	for _, item := range items {
		if item.Archived || !slackConversationID.MatchString(item.ID) {
			continue
		}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return SlackConversations{TeamID: identity.TeamID, TeamName: identity.TeamName, Items: out, Truncated: truncated}, nil
}

// openSlackBotConfig opens the sealed configuration of an existing Slack bot channel.
func (s *Service) openSlackBotConfig(ctx context.Context, tenant, id shared.ID) (ports.SlackBotChannelConfig, error) {
	reader, ok := s.repo.(ports.NotificationChannelSecretReader)
	if !ok {
		return ports.SlackBotChannelConfig{}, errSlackUnavailable
	}
	channel, sealed, err := reader.GetChannelSealedConfig(ctx, tenant, id)
	if err != nil {
		return ports.SlackBotChannelConfig{}, err
	}
	if channel.Type != domain.ChannelSlackBot {
		return ports.SlackBotChannelConfig{}, fmt.Errorf("%w: channel is not a Slack bot channel", shared.ErrValidation)
	}
	raw, err := s.protector.Open(sealed, channelAAD(tenant, channel.ID, channel.SecretVersion))
	if err != nil {
		return ports.SlackBotChannelConfig{}, fmt.Errorf("%w: the channel's credential is unavailable", shared.ErrValidation)
	}
	config, code := decodeChannelConfig(channel.Type, raw)
	cfg, ok := config.(ports.SlackBotChannelConfig)
	if code != "" || !ok {
		return ports.SlackBotChannelConfig{}, fmt.Errorf("%w: the channel's configuration is invalid", shared.ErrValidation)
	}
	return cfg, nil
}

// prepareDestination checks a new provider-verified destination before the administration
// transaction opens, so no database transaction waits on a provider call. Inputs that carry no such
// destination pass through unchanged and are validated inside the transaction as before.
func (s *Service) prepareDestination(ctx context.Context, in ChannelInput) (ChannelInput, error) {
	in.verified = nil
	if in.Type != domain.ChannelSlackBot || strings.TrimSpace(in.Secret) == "" {
		return in, nil
	}
	config, _, _, err := validateChannel(in, true)
	if err != nil {
		return in, err
	}
	if in.verified, err = s.verifyDestination(ctx, config); err != nil {
		return in, err
	}
	return in, nil
}

// verifiedDestination returns the configuration to seal: the one prepareDestination checked before
// the transaction opened. It runs inside the administration transaction, so it never calls a
// provider: a provider-checked destination that was not prepared, or that differs from what was
// prepared, is refused instead of being checked with the transaction held.
func (s *Service) verifiedDestination(_ context.Context, in ChannelInput, config ports.NotificationChannelConfig) (ports.NotificationChannelConfig, error) {
	if prepared, ok := in.verified.(ports.SlackBotChannelConfig); ok {
		if current, same := config.(ports.SlackBotChannelConfig); same && current.BotToken == prepared.BotToken && current.ChannelID == prepared.ChannelID && current.AllowShared == prepared.AllowShared {
			return prepared, nil
		}
	}
	if _, provider := config.(ports.SlackBotChannelConfig); provider {
		return nil, errDestinationUnverified
	}
	return config, nil
}
