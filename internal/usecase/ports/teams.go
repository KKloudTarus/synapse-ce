package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Microsoft Teams personal delivery (#1420). The operator registers one bot for the deployment. A
// person messages it in Teams; it answers with a one-time link code that holds no tenant; the
// person enters the code in their Synapse profile, which links their Teams account to their user
// and keeps the bot's 1:1 conversation with them. Personal notifications are then sent into that
// conversation.

// TeamsConversationRef addresses the bot's 1:1 conversation with one person. It is sealed whenever
// it is stored.
type TeamsConversationRef struct {
	ServiceURL     string `json:"service_url"`
	ConversationID string `json:"conversation_id"`
	// UserObjectID is the person's Microsoft Entra object ID, the value of their Teams contact.
	UserObjectID string `json:"user_object_id"`
	// EntraTenantID is the person's Microsoft Entra tenant.
	EntraTenantID string `json:"entra_tenant_id,omitempty"`
}

// TeamsActivity is the part of an inbound Bot Framework activity the bot reads.
type TeamsActivity struct {
	Type             string
	Text             string
	ServiceURL       string
	ConversationID   string
	ConversationType string
	FromObjectID     string
	TenantID         string
}

// TeamsBot sends activities as the operator's bot.
type TeamsBot interface {
	// Send posts an activity into a conversation and returns the created activity ID. Errors
	// implement TeamsErrorCoder.
	Send(ctx context.Context, ref TeamsConversationRef, activity []byte) (string, error)
}

// TeamsErrorCoder is implemented by TeamsBot errors.
type TeamsErrorCoder interface {
	TeamsResult() NotificationSendResult
}

// TeamsActivityVerifier checks the Bot Framework JWT on an inbound activity: the signature, the
// issuer, the audience (the bot's app ID) and the service URL claim, which must equal the
// activity's service URL.
type TeamsActivityVerifier interface {
	Verify(ctx context.Context, authorization, serviceURL string) error
}

// TeamsLinkOffers keeps the global, owner-only link codes the bot hands out (migration 0224).
type TeamsLinkOffers interface {
	// OfferTeamsLink stores a code digest with its sealed conversation reference. It returns false
	// when the conversation already holds the most live codes it may.
	OfferTeamsLink(ctx context.Context, codeDigest, conversationKey, sealedReference string, expiresAt time.Time) (bool, error)
}

// TeamsLinker builds the contact and its tenant-sealed conversation from a claimed offer.
type TeamsLinker func(sealedOffer string) (contact UserContact, sealedConversation string, err error)

// TeamsContactStore links a Teams account to a user and keeps its conversation.
type TeamsContactStore interface {
	// LinkTeamsContact claims a live link code and stores the contact it links in one transaction:
	// the code is consumed only if the contact, its sealed conversation and the audit entry commit,
	// so a failure on the way leaves the code usable. link turns the claimed offer into the contact
	// and its conversation sealed for the tenant; it must not do I/O. found is false when the code
	// is unknown, used or expired. Linking the same Teams account again replaces its contact.
	LinkTeamsContact(ctx context.Context, tenant, user shared.ID, codeDigest string, link TeamsLinker) (contact UserContact, found bool, err error)
	// CountTeamsLinkAttempt records one code attempt against the person's verification quota (the
	// table email and Slack verification requests use) and returns shared.ErrConflict when the person
	// has used it up.
	CountTeamsLinkAttempt(ctx context.Context, tenant, user, requestID shared.ID, at time.Time) error
	// TeamsConversation returns the sealed conversation of one verified Teams contact.
	TeamsConversation(ctx context.Context, tenant, contact shared.ID) (string, bool, error)
}
