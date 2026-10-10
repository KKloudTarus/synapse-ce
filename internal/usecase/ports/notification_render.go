package ports

import "github.com/KKloudTarus/synapse-ce/internal/domain/notification"

// RenderedMessage is the channel-neutral content of one notification after its template has been
// rendered (EPIC #1327 D5). A driver receives it and never sees a template; a formatter turns it
// into the channel's wire payload.
type RenderedMessage struct {
	// Fields holds the content fields of the channel family, for example "title" and "body" for
	// chat, "subject" and "body" for email, "summary" for pager. Values are plain text plus the
	// Markdown subset of internal/domain/msgtemplate, with variable values already escaped.
	Fields map[string]string
	// Links are built server-side from the configured public base URL. They are the only links a
	// message carries; link syntax inside Fields renders as literal text.
	Links []RenderedLink
	// TemplateRef identifies the template that produced Fields, recorded on the attempt, for
	// example "builtin:scan.completed:chat:en@<build>".
	TemplateRef string
}

// RenderedLink is one typed link of a RenderedMessage.
type RenderedLink struct {
	Label string
	URL   string
}

// FormattedMessage is a channel's wire payload.
type FormattedMessage struct {
	ContentType string
	Body        []byte
	// HTMLBody is the optional HTML alternative of an email message. It is produced from the same
	// rendered Markdown document as Body and is ignored by non-email drivers.
	HTMLBody []byte
	// Subject is the email subject, already safe for a header; empty for other channels.
	Subject string
}

// NotificationFormatter converts a RenderedMessage into the wire payload of one channel type and
// applies that channel's escaper. It sits behind a port so the API preview and the delivery
// driver produce the same bytes.
type NotificationFormatter interface {
	ChannelType() notification.ChannelType
	Format(RenderedMessage) (FormattedMessage, error)
}
