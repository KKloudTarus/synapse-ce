package messageformat

import (
	"encoding/json"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Pager formatters expose only the pager template's summary and the server-built links. Drivers
// place it in the provider's summary/message field and never forward event data as custom details.
type PagerDutyFormatter struct{}
type JSMFormatter struct{}

const (
	// PagerDuty documents a 1,024-character summary limit for Events API v2.
	PagerDutySummaryRunes = 1024
	// JSM Operations accepts a 130-character alert message.
	JSMMessageRunes = 130
	// Lifecycle notes retain bounded class-filtered facts beyond the alert title.
	JSMNoteRunes = 4096
)

var (
	_ ports.NotificationFormatter = PagerDutyFormatter{}
	_ ports.NotificationFormatter = JSMFormatter{}
)

func (PagerDutyFormatter) ChannelType() notification.ChannelType {
	return notification.ChannelPagerDuty
}
func (JSMFormatter) ChannelType() notification.ChannelType { return notification.ChannelJSM }
func (PagerDutyFormatter) Format(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	return pagerMessage(message, PagerDutySummaryRunes, false)
}
func (JSMFormatter) Format(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	return pagerMessage(message, JSMMessageRunes, true)
}

func pagerMessage(message ports.RenderedMessage, summaryRunes int, includeNote bool) (ports.FormattedMessage, error) {
	links, err := checkLinks(message.Links)
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	plainSummary := headerText(msgmarkdown.Parse(msgtemplate.Sanitize(message.Fields["summary"])))
	summary := truncateRunes(plainSummary, summaryRunes)
	if summary == "" {
		return ports.FormattedMessage{}, nil
	}
	// Keep trusted links in a small neutral representation that both pager drivers translate.
	linkValues := make([]map[string]string, len(links))
	for i, link := range links {
		linkValues[i] = map[string]string{"label": link.label, "url": link.url}
	}
	values := map[string]any{"summary": summary, "links": linkValues}
	if includeNote {
		values["note"] = truncateRunes(plainSummary, JSMNoteRunes)
	}
	payload, err := json.Marshal(values)
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	return ports.FormattedMessage{ContentType: "application/json", Body: payload}, nil
}
