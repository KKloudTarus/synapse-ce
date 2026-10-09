package notification

import (
	"encoding/json"
	"time"
)

// WebhookEnvelopeVersion is the explicit contract version for the default webhook body.
const WebhookEnvelopeVersion = "synapse.notification.v1"

// WebhookLink is a typed, server-built console route. The renderer supplies only routes emitted
// by consolelink.Builder; snapshots and custom templates cannot introduce a destination.
type WebhookLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// RenderWebhookEnvelope serializes the default webhook payload. Callers must provide a context
// already filtered to the channel's effective data class; raw event data is deliberately absent.
func RenderWebhookEnvelope(event Event, context TemplateContext) ([]byte, error) {
	return RenderWebhookEnvelopeWithLinks(event, context, nil)
}

// RenderWebhookEnvelopeWithLinks serializes the default webhook payload with optional trusted
// console routes. Callers must provide a context already filtered to the channel's effective data
// class; raw event data is deliberately absent.
func RenderWebhookEnvelopeWithLinks(event Event, context TemplateContext, links []WebhookLink) ([]byte, error) {
	vars := make(map[string]string, len(context.Vars))
	for key, value := range context.Vars {
		vars[key] = value
	}
	lists := make(map[string][]map[string]string, len(context.Lists))
	for name, items := range context.Lists {
		copied := make([]map[string]string, len(items))
		for i, item := range items {
			copied[i] = make(map[string]string, len(item))
			for key, value := range item {
				copied[i][key] = value
			}
		}
		lists[name] = copied
	}
	return json.Marshal(struct {
		Version string `json:"version"`
		Event   struct {
			ID            string    `json:"id"`
			Type          EventType `json:"type"`
			SchemaVersion int       `json:"schema_version"`
			OccurredAt    time.Time `json:"occurred_at"`
			Severity      string    `json:"severity,omitempty"`
		} `json:"event"`
		Data  TemplateContext `json:"data"`
		Links []WebhookLink   `json:"links,omitempty"`
	}{
		Version: WebhookEnvelopeVersion,
		Event: struct {
			ID            string    `json:"id"`
			Type          EventType `json:"type"`
			SchemaVersion int       `json:"schema_version"`
			OccurredAt    time.Time `json:"occurred_at"`
			Severity      string    `json:"severity,omitempty"`
		}{
			ID: event.ID.String(), Type: event.Type, SchemaVersion: event.SchemaVersion,
			OccurredAt: event.OccurredAt.UTC(), Severity: string(event.Severity),
		},
		Data: TemplateContext{Vars: vars, Lists: lists}, Links: append([]WebhookLink(nil), links...),
	})
}
