package notification

import (
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Custom JSON body for generic webhooks (#1376).
//
// The body of a webhook-family template is a JSON document whose string values may hold template
// expressions (domain.ParseWebhookBody). It is validated when a webhook template is saved or
// activated, and again when a channel opts into it with custom_body, so a body that no longer
// compiles is never bound.
//
// The send-time renderer (RenderMessage, #1365) resolves the template, renders the body with
// RenderCustomWebhookBody and passes the bytes to the webhook driver in
// NotificationWork.CustomWebhookBody. The driver sends exactly those bytes, signs
// them and sets X-Synapse-Body: custom.

// validateWebhookBody checks a webhook template's body: its JSON structure once, then every
// expression value against the schema of each event type the key can render.
func validateWebhookBody(eventType domain.EventType, source string, schemas []templateSchema) error {
	body, err := domain.ParseWebhookBody(source)
	if err != nil {
		var bodyErr *domain.WebhookBodyError
		if errors.As(err, &bodyErr) {
			return &TemplateValidationError{Field: "body", EventType: eventType, Code: msgtemplate.Code(bodyErr.Code), Line: bodyErr.Line, Path: bodyErr.Path, Detail: bodyErr.Detail}
		}
		return err
	}
	for _, candidate := range schemas {
		if _, err := domain.CompileWebhookBody(body, candidate.schema); err != nil {
			var compileErr *domain.WebhookBodyCompileError
			var rejection *msgtemplate.Error
			if errors.As(err, &compileErr) && errors.As(err, &rejection) && errors.Is(err, msgtemplate.ErrInvalidTemplate) {
				return &TemplateValidationError{Field: "body", EventType: candidate.eventType, Code: rejection.Code, Line: rejection.Line, Path: compileErr.Path, Detail: rejection.Detail}
			}
			return fmt.Errorf("compile notification webhook body: %w", err)
		}
	}
	return nil
}

// RenderCustomWebhookBody renders the custom body a resolution selected for a webhook channel. ok
// is false when there is no custom body to send: the resolution is not of the webhook family, did
// not pick a tenant template with a body, or the fallback applies; the driver then sends the event
// versioned filtered envelope. data is the event's already class-filtered scalar and bounded-list
// context.
//
// The template was validated when it was saved and bound, but the catalog may have changed since,
// so it is parsed and compiled again against the event's schema here.
func RenderCustomWebhookBody(resolution TemplateResolution, data msgtemplate.Data) (body []byte, ok bool, err error) {
	if resolution.Family != domain.FamilyWebhook {
		return nil, false, nil
	}
	var source string
	switch {
	case resolution.Version != nil:
		source = resolution.Version.Fields["body"]
	case resolution.Builtin != nil:
		source = resolution.Builtin.Fields["body"]
	}
	if source == "" {
		return nil, false, nil
	}
	schemas, err := templateSchemas(resolution.EventType)
	if err != nil {
		return nil, false, err
	}
	if len(schemas) != 1 {
		return nil, false, fmt.Errorf("%w: a custom body renders for one event type", shared.ErrValidation)
	}
	rendered, err := domain.RenderCustomWebhookBody(source, schemas[0].schema, data)
	if err != nil {
		return nil, false, err
	}
	return rendered, true, nil
}
