package notification

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/consolelink"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Personal Slack messages (#1419). A person links their Slack account by its member ID in a
// workspace that has a Slack bot channel (#1383); the link is verified by a code the app sends them
// as a direct message. A personal notification then goes to them as the app's direct message, sent
// with the bot token of an enabled Slack bot channel of the same workspace. Synapse never looks a
// person up in Slack by email or name.

// codeSlackWorkspaceUnavailable is the final failure of a personal Slack message whose workspace
// no longer has an enabled Slack bot channel.
const codeSlackWorkspaceUnavailable = "slack_workspace_unavailable"

// ErrSlackWorkspaceUnavailable reports that the tenant has no enabled Slack bot for a workspace.
var ErrSlackWorkspaceUnavailable = fmt.Errorf("%w: no Slack app is set up for that workspace", shared.ErrValidation)

// SlackWorkspace is a workspace a person can link, as the profile shows it.
type SlackWorkspace struct {
	TeamID   string `json:"team_id"`
	TeamName string `json:"team_name"`
}

// SetSlackDirect wires the sender of the app's direct messages (#1419).
func (s *Service) SetSlackDirect(direct ports.SlackDirectSender) { s.slackDirect = direct }

// SetPublicBaseURL sets the console origin personal messages link to. An empty or invalid base
// leaves personal messages without a link; the configuration loader has already refused an
// invalid SYNAPSE_PUBLIC_BASE_URL.
func (s *Service) SetPublicBaseURL(base string) {
	if builder, err := consolelink.NewBuilder(base); err == nil {
		s.console = &builder
	}
}

type slackBot struct {
	channel domain.Channel
	config  ports.SlackBotChannelConfig
}

// slackBots opens the configuration of every enabled, unpaused Slack bot channel of the tenant, in
// the repository's order (name, then ID), so the same bot is chosen every time.
func (s *Service) slackBots(ctx context.Context, tenant shared.ID) ([]slackBot, error) {
	reader, ok := s.repo.(ports.NotificationChannelSecretReader)
	if !ok {
		return nil, nil
	}
	channels, err := s.repo.ListChannels(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var out []slackBot
	for _, channel := range channels {
		if channel.Type != domain.ChannelSlackBot || !channel.Enabled || channel.Health.Paused() || s.disabled[domain.ChannelSlackBot] {
			continue
		}
		current, sealed, err := reader.GetChannelSealedConfig(ctx, tenant, channel.ID)
		if errors.Is(err, shared.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		raw, err := s.protector.Open(sealed, channelAAD(tenant, current.ID, current.SecretVersion))
		if err != nil {
			continue
		}
		config, code := decodeChannelConfig(current.Type, raw)
		cfg, ok := config.(ports.SlackBotChannelConfig)
		if code != "" || !ok || cfg.TeamID == "" {
			continue
		}
		out = append(out, slackBot{channel: current, config: cfg})
	}
	return out, nil
}

// SlackWorkspaces lists the workspaces of the tenant's enabled Slack bot channels, for the person
// linking their account. It names no channel and no token.
func (s *Service) SlackWorkspaces(ctx context.Context) ([]SlackWorkspace, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	bots, err := s.slackBots(ctx, tenant)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []SlackWorkspace{}
	for _, bot := range bots {
		if seen[bot.config.TeamID] {
			continue
		}
		seen[bot.config.TeamID] = true
		name := bot.config.TeamName
		if name == "" {
			name = bot.config.TeamID
		}
		out = append(out, SlackWorkspace{TeamID: bot.config.TeamID, TeamName: name})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TeamName < out[j].TeamName })
	return out, nil
}

func (s *Service) botForTeam(ctx context.Context, tenant shared.ID, team string) (ports.SlackBotChannelConfig, error) {
	bots, err := s.slackBots(ctx, tenant)
	if err != nil {
		return ports.SlackBotChannelConfig{}, err
	}
	for _, bot := range bots {
		if bot.config.TeamID == team {
			return bot.config, nil
		}
	}
	return ports.SlackBotChannelConfig{}, ErrSlackWorkspaceUnavailable
}

// CheckSlackMember confirms that a member ID names an active person in a workspace the tenant has a
// Slack app in, before a contact is created for it.
func (s *Service) CheckSlackMember(ctx context.Context, tenant shared.ID, team, member string) error {
	bot, err := s.botForTeam(ctx, tenant, team)
	if err != nil {
		return err
	}
	reader, ok := s.slack.(ports.SlackMemberReader)
	if !ok || reader == nil {
		return errSlackUnavailable
	}
	found, err := reader.Member(ctx, bot.BotToken, member)
	if err != nil {
		return slackValidationError("the member could not be read", err)
	}
	if found.Deleted || found.Bot || (found.TeamID != "" && found.TeamID != team) {
		return fmt.Errorf("%w: that Slack member is not an active person in the workspace", shared.ErrValidation)
	}
	return nil
}

// PersonalSlack returns the sender of personal Slack messages, for the personal job runner.
func (s *Service) PersonalSlack() ports.PersonalChannelSender { return personalSlack{s} }

type personalSlack struct{ s *Service }

// SendPersonal implements ports.PersonalChannelSender for Slack.
func (p personalSlack) SendPersonal(ctx context.Context, m ports.PersonalMessage) ports.NotificationSendResult {
	title := limitRunes(strings.TrimSpace(m.Title), 150)
	if title == "" {
		title = "Synapse notification"
	}
	body := escapeLine(m.Summary, 2500)
	message := ports.RenderedMessage{Fields: map[string]string{"title": title, "body": body}}
	if p.s.console != nil {
		if href, ok := p.s.console.Path(m.LinkPath); ok {
			message.Links = []ports.RenderedLink{{Label: "Open in Synapse", URL: href}}
		}
	}
	return p.s.sendSlackDirect(ctx, m.TenantID, m.Recipient, message)
}

// SendSlackVerification sends a contact verification code as the app's direct message (#1419).
func (s *Service) SendSlackVerification(ctx context.Context, tenant shared.ID, recipient, code string) ports.NotificationSendResult {
	body := "Your Synapse verification code is `" + code + "`. It expires in 10 minutes. If you did not ask to link Slack to Synapse, ignore this message."
	return s.sendSlackDirect(ctx, tenant, recipient, ports.RenderedMessage{Fields: map[string]string{"title": "Link Slack to Synapse", "body": body}})
}

func (s *Service) sendSlackDirect(ctx context.Context, tenant shared.ID, recipient string, message ports.RenderedMessage) ports.NotificationSendResult {
	team, member, ok := domain.ParseSlackContact(recipient)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "contact_invalid"}
	}
	if s.slackDirect == nil {
		return ports.NotificationSendResult{ErrorCode: "slack_unavailable"}
	}
	formatter, ok := s.formatters[domain.ChannelSlackBot]
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "format_unavailable"}
	}
	bot, err := s.botForTeam(ctx, tenant, team)
	if errors.Is(err, ErrSlackWorkspaceUnavailable) {
		return ports.NotificationSendResult{ErrorCode: codeSlackWorkspaceUnavailable}
	}
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "store_unavailable", Retryable: true}
	}
	formatted, err := formatter.Format(message)
	if err != nil || len(formatted.Body) == 0 {
		return ports.NotificationSendResult{ErrorCode: "format_failed"}
	}
	return s.slackDirect.SendSlackDirect(ctx, bot.BotToken, member, formatted.Body)
}

// escapeLine makes one line of plain text safe as the Markdown subset: controls removed, then every
// Markdown character escaped, so a value can never become formatting or a link.
func escapeLine(value string, max int) string {
	var lines []string
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(msgtemplate.Sanitize(line)); line != "" {
			lines = append(lines, msgtemplate.EscapeMarkdown(limitRunes(line, max)))
		}
	}
	return strings.Join(lines, "\n\n")
}

func limitRunes(value string, max int) string {
	if utf8.RuneCountInString(value) <= max {
		return value
	}
	return string([]rune(value)[:max])
}

var _ ports.UserContactSlack = (*Service)(nil)
