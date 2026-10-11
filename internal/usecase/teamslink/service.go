// Package teamslink delivers personal notifications in Microsoft Teams (EPIC #1327, #1420).
//
// Workflows webhooks cannot reach one person, so the operator registers one Bot Framework bot for
// the deployment. Linking works without the bot ever knowing a tenant: a person messages the bot
// in a 1:1 chat, the bot answers with a one-time code, and the person enters that code in their
// Synapse profile. The code is stored only as a keyed digest in a global, owner-only table, next to
// the sealed conversation reference; claiming it moves the reference into the person's tenant,
// sealed again under that tenant. Personal notifications are then posted into that conversation.
package teamslink

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/consolelink"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	// codeAlphabet is Crockford base32 without the letters people misread (I, L, O, U).
	codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	codeLength   = 10
	// codeTTL is how long a link code works.
	codeTTL = 10 * time.Minute
)

var (
	objectID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	// ErrUnavailable reports that the operator configured no Teams bot.
	ErrUnavailable = errors.New("microsoft teams linking is unavailable")
	// ErrInvalidCode is the one answer for a wrong, used or expired code.
	ErrInvalidCode = fmt.Errorf("%w: the Teams link code is not valid or has expired", shared.ErrForbidden)
)

// Service runs the bot side of linking, the profile side, and personal delivery.
type Service struct {
	bot       ports.TeamsBot
	offers    ports.TeamsLinkOffers
	contacts  ports.TeamsContactStore
	protector ports.NotificationSecretProtector
	ids       ports.IDGenerator
	clock     ports.Clock
	key       []byte
	// accepts reports whether a service URL is a Teams Bot Connector endpoint.
	accepts   func(string) bool
	formatter ports.NotificationFormatter
	console   *consolelink.Builder
}

// Config collects the service's dependencies.
type Config struct {
	Bot       ports.TeamsBot
	Offers    ports.TeamsLinkOffers
	Contacts  ports.TeamsContactStore
	Protector ports.NotificationSecretProtector
	IDs       ports.IDGenerator
	Clock     ports.Clock
	// Key derives code and conversation digests; use DeriveKey of the vault master secret.
	Key []byte
	// AcceptsServiceURL validates a conversation's service URL (teamsbot.ValidServiceURL).
	AcceptsServiceURL func(string) bool
	// Formatter renders a personal message as the Teams Adaptive Card message.
	Formatter ports.NotificationFormatter
	// PublicBaseURL is the console origin personal messages link to; empty sends no link.
	PublicBaseURL string
}

// NewService validates the configuration.
func NewService(cfg Config) (*Service, error) {
	if cfg.Bot == nil || cfg.Offers == nil || cfg.Contacts == nil || cfg.Protector == nil || cfg.IDs == nil || cfg.Clock == nil || len(cfg.Key) < 32 || cfg.AcceptsServiceURL == nil || cfg.Formatter == nil {
		return nil, fmt.Errorf("%w: invalid Teams link configuration", shared.ErrValidation)
	}
	s := &Service{bot: cfg.Bot, offers: cfg.Offers, contacts: cfg.Contacts, protector: cfg.Protector, ids: cfg.IDs, clock: cfg.Clock,
		key: append([]byte(nil), cfg.Key...), accepts: cfg.AcceptsServiceURL, formatter: cfg.Formatter}
	if builder, err := consolelink.NewBuilder(cfg.PublicBaseURL); err == nil {
		s.console = &builder
	}
	return s, nil
}

// DeriveKey separates the link-code digest key from the vault AEAD key. API and worker must use
// the same master secret.
func DeriveKey(master string) []byte {
	sum := sha256.Sum256([]byte("synapse:teams-link:v1:" + master))
	return sum[:]
}

func (s *Service) digest(kind, value string) string {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(kind + ":" + value))
	return hex.EncodeToString(mac.Sum(nil))
}

func offerAAD(codeDigest string) []byte { return []byte("teams-link-offer:" + codeDigest) }

// ConversationAAD binds a stored conversation to its tenant and contact.
func ConversationAAD(tenant, contact shared.ID) []byte {
	return []byte("teams-conversation:" + tenant.String() + ":" + contact.String())
}

// HandleActivity answers a message a person sent the bot in a 1:1 chat with a link code. Anything
// else (a channel or group message, an update, a typing indicator) is ignored. The caller has
// verified the activity's token.
func (s *Service) HandleActivity(ctx context.Context, a ports.TeamsActivity) error {
	if a.Type != "message" || a.ConversationType != "personal" || a.ConversationID == "" || len(a.ConversationID) > 512 || !s.accepts(a.ServiceURL) {
		return nil
	}
	user := strings.ToLower(strings.TrimSpace(a.FromObjectID))
	if !objectID.MatchString(user) {
		return nil
	}
	ref := ports.TeamsConversationRef{ServiceURL: a.ServiceURL, ConversationID: a.ConversationID, UserObjectID: user, EntraTenantID: limit(a.TenantID, 64)}
	code, err := newCode()
	if err != nil {
		return err
	}
	codeDigest := s.digest("code", code)
	raw, err := json.Marshal(ref)
	if err != nil {
		return err
	}
	sealed, err := s.protector.Seal(raw, offerAAD(codeDigest))
	if err != nil {
		return fmt.Errorf("seal Teams link offer: %w", err)
	}
	accepted, err := s.offers.OfferTeamsLink(ctx, codeDigest, s.digest("conversation", a.ServiceURL+"|"+a.ConversationID), sealed, s.clock.Now().UTC().Add(codeTTL))
	if err != nil {
		return err
	}
	text := "Your Synapse link code is " + formatCode(code) + ". In Synapse, open My profile, then Microsoft Teams, and enter it within 10 minutes. If you did not ask to link Teams to Synapse, ignore this message."
	if !accepted {
		text = "You already have Synapse link codes waiting. Use one of them, or wait 10 minutes and message me again."
	}
	reply, err := json.Marshal(map[string]any{"type": "message", "textFormat": "plain", "text": text})
	if err != nil {
		return err
	}
	_, err = s.bot.Send(ctx, ref, reply)
	return err
}

// Link claims a code for the signed-in person and stores their Teams contact, verified, with the
// bot's conversation. Every attempt counts against the person's verification quota first, so a
// code cannot be guessed; a wrong, used or expired code gets one answer.
func (s *Service) Link(ctx context.Context, tenant, user shared.ID, code string) (ports.UserContact, error) {
	tenant = shared.TenantOrDefault(tenant)
	normalized, ok := normalizeCode(code)
	now := s.clock.Now().UTC()
	if err := s.contacts.CountTeamsLinkAttempt(ctx, tenant, user, s.ids.NewID(), now); err != nil {
		return ports.UserContact{}, err
	}
	if !ok {
		return ports.UserContact{}, ErrInvalidCode
	}
	codeDigest := s.digest("code", normalized)
	contactID := s.ids.NewID()
	// The claim, the contact and its conversation commit together: if anything below fails, the
	// code is still there to be entered again.
	link := func(sealed string) (ports.UserContact, string, error) {
		raw, err := s.protector.Open(sealed, offerAAD(codeDigest))
		if err != nil {
			return ports.UserContact{}, "", fmt.Errorf("open Teams link offer: %w", err)
		}
		var ref ports.TeamsConversationRef
		if json.Unmarshal(raw, &ref) != nil || !objectID.MatchString(ref.UserObjectID) || !s.accepts(ref.ServiceURL) || ref.ConversationID == "" {
			return ports.UserContact{}, "", ErrInvalidCode
		}
		contact := ports.UserContact{TenantID: tenant, ID: contactID, UserID: user, Kind: notification.PersonalTeams, Source: "manual", Value: ref.UserObjectID, VerifiedAt: &now, Version: 1, CreatedAt: now, UpdatedAt: now}
		tenantSealed, err := s.protector.Seal(raw, ConversationAAD(tenant, contactID))
		if err != nil {
			return ports.UserContact{}, "", fmt.Errorf("seal Teams conversation: %w", err)
		}
		return contact, tenantSealed, nil
	}
	contact, found, err := s.contacts.LinkTeamsContact(ctx, tenant, user, codeDigest, link)
	if err != nil {
		return ports.UserContact{}, err
	}
	if !found {
		return ports.UserContact{}, ErrInvalidCode
	}
	return contact, nil
}

// SendPersonal implements ports.PersonalChannelSender for Teams.
func (s *Service) SendPersonal(ctx context.Context, m ports.PersonalMessage) ports.NotificationSendResult {
	sealed, ok, err := s.contacts.TeamsConversation(ctx, m.TenantID, m.ContactID)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "store_unavailable", Retryable: true}
	}
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "teams_conversation_missing"}
	}
	raw, err := s.protector.Open(sealed, ConversationAAD(m.TenantID, m.ContactID))
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "teams_conversation_unavailable"}
	}
	var ref ports.TeamsConversationRef
	if json.Unmarshal(raw, &ref) != nil || ref.UserObjectID != m.Recipient || !s.accepts(ref.ServiceURL) {
		return ports.NotificationSendResult{ErrorCode: "teams_conversation_invalid"}
	}
	title := limit(strings.TrimSpace(msgtemplate.Sanitize(m.Title)), 200)
	if title == "" {
		title = "Synapse notification"
	}
	message := ports.RenderedMessage{Fields: map[string]string{"title": title, "body": escapeText(m.Summary)}}
	if s.console != nil {
		if href, ok := s.console.Path(m.LinkPath); ok {
			message.Links = []ports.RenderedLink{{Label: "Open in Synapse", URL: href}}
		}
	}
	formatted, err := s.formatter.Format(message)
	if err != nil || len(formatted.Body) == 0 {
		return ports.NotificationSendResult{ErrorCode: "format_failed"}
	}
	id, err := s.bot.Send(ctx, ref, formatted.Body)
	if err != nil {
		var coder ports.TeamsErrorCoder
		if errors.As(err, &coder) {
			return coder.TeamsResult()
		}
		return ports.NotificationSendResult{ErrorCode: "network_error", Retryable: true}
	}
	return ports.NotificationSendResult{StatusCode: 201, RemoteRef: limit(id, 200)}
}

func newCode() (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(codeAlphabet)))
	for i := 0; i < codeLength; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("generate Teams link code: %w", err)
		}
		b.WriteByte(codeAlphabet[n.Int64()])
	}
	return b.String(), nil
}

func formatCode(code string) string { return code[:5] + "-" + code[5:] }

// normalizeCode accepts the code as shown (ABCDE-FGHJK), in any case, with spaces or hyphens.
func normalizeCode(raw string) (string, bool) {
	if len(raw) > 64 {
		return "", false
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(raw) {
		switch {
		case r == '-' || r == ' ':
		case strings.ContainsRune(codeAlphabet, r):
			b.WriteRune(r)
		default:
			return "", false
		}
	}
	return b.String(), b.Len() == codeLength
}

func escapeText(value string) string {
	var lines []string
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(msgtemplate.Sanitize(line)); line != "" {
			lines = append(lines, msgtemplate.EscapeMarkdown(limit(line, 2500)))
		}
	}
	return strings.Join(lines, "\n\n")
}

func limit(value string, max int) string {
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max])
}

var _ ports.PersonalChannelSender = (*Service)(nil)
