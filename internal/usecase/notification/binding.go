package notification

import (
	"context"
	"errors"
	"fmt"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Channel template binding (#1371).
//
// A channel binds at most one template, of the family its type renders, and optionally its own
// locale. Binding is configuration, not a destination change, so a caller with
// manage_integrations may bind or unbind; it goes through the channel create and PATCH, bumps the
// revision and is audited.
//
// Validation when the binding changes:
//   - the template exists in the tenant, has the channel's family and is active;
//   - its locale is "*" or one of the channel's locale chain (channel or tenant locale, then en);
//   - it is "*" or its event type is the event type of every rule that routes to the channel;
//   - with custom_body (webhook channels only, #1376), its active body is revalidated as a custom
//     JSON body against the current catalog.
//
// Rules are checked the other way on every rule save: a rule that routes an event type to a
// channel whose bound template does not cover it is refused with a validation error naming the
// channel and the template. Refusing, rather than warning, keeps resolution predictable: a bound
// channel never silently renders one of its events with a different tier. The check reads the
// template key, which never changes, whatever the template's status.

// applyBinding merges the binding fields of an update into the current binding. A nil field keeps
// the current value; an empty one clears it.
func applyBinding(current domain.TemplateBinding, in ChannelInput) domain.TemplateBinding {
	next := current
	if in.TemplateID != nil {
		next.TemplateID = *in.TemplateID
	}
	if in.Locale != nil {
		next.Locale = *in.Locale
	}
	if in.CustomBody != nil {
		next.CustomBody = *in.CustomBody
	}
	return next
}

// validateBinding checks channel's binding. rules are the tenant's rules, or nil for a new channel,
// which no rule routes to yet.
func (s *Service) validateBinding(ctx context.Context, tenant shared.ID, channel domain.Channel, rules []domain.Rule) error {
	if err := channel.TemplateBinding.Validate(channel.Type); err != nil {
		return err
	}
	if channel.TemplateID.IsZero() {
		return nil
	}
	if s.templates == nil {
		return fmt.Errorf("%w: notification templates are not configured", shared.ErrValidation)
	}
	head, err := s.templates.GetNotificationTemplate(ctx, tenant, channel.TemplateID)
	if errors.Is(err, shared.ErrNotFound) {
		return fmt.Errorf("%w: template %s does not exist", shared.ErrValidation, channel.TemplateID)
	}
	if err != nil {
		return err
	}
	family, _ := domain.FamilyForChannelType(channel.Type)
	if head.Family != family {
		return fmt.Errorf("%w: template %s is a %s template; a %s channel binds a %s template", shared.ErrValidation, head.ID, head.Family, channel.Type, family)
	}
	if head.Status != domain.TemplateActive {
		return fmt.Errorf("%w: template %s is %s; only an active template can be bound", shared.ErrValidation, head.ID, head.Status)
	}
	locale, _, err := s.requestedLocale(ctx, tenant, channel)
	if err != nil {
		return err
	}
	if !containsLocale(domain.LocaleChain(locale), head.Locale) {
		return fmt.Errorf("%w: template %s is for locale %s; the channel renders in %s", shared.ErrValidation, head.ID, head.Locale, locale)
	}
	if channel.CustomBody {
		if err := s.checkCustomBody(ctx, tenant, head); err != nil {
			return err
		}
	}
	if head.EventType == domain.AnyEventType {
		return nil
	}
	for _, rule := range rules {
		if containsChannel(rule.ChannelIDs, channel.ID) && !head.Covers(rule.EventType) {
			return fmt.Errorf("%w: template %s only covers %s, but rule %s routes %s to this channel; bind a \"*\" template or change the rule", shared.ErrValidation, head.ID, head.EventType, rule.ID, rule.EventType)
		}
	}
	return nil
}

// checkRuleBindings refuses a rule that routes its event type to a channel whose bound template
// does not cover it.
func (s *Service) checkRuleBindings(ctx context.Context, tenant shared.ID, rule domain.Rule) error {
	if s.templates == nil {
		return nil
	}
	channels, err := s.repo.ListChannels(ctx, tenant)
	if err != nil {
		return err
	}
	bound := make(map[shared.ID]shared.ID, len(channels))
	for _, channel := range channels {
		if !channel.TemplateID.IsZero() {
			bound[channel.ID] = channel.TemplateID
		}
	}
	for _, channelID := range rule.ChannelIDs {
		templateID, ok := bound[channelID]
		if !ok {
			continue
		}
		head, err := s.templates.GetNotificationTemplate(ctx, tenant, templateID)
		if errors.Is(err, shared.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if !head.Covers(rule.EventType) {
			return fmt.Errorf("%w: channel %s is bound to template %s, which only covers %s; unbind it or bind a \"*\" template to route %s there", shared.ErrValidation, channelID, head.ID, head.EventType, rule.EventType)
		}
	}
	return nil
}

// bindingAuditMetadata records a binding change on a channel audit entry: the template and locale
// after the change and, when they changed, before it. It never carries template content.
func bindingAuditMetadata(previous, next domain.TemplateBinding, extra map[string]string) map[string]string {
	if extra == nil {
		extra = map[string]string{}
	}
	changed := previous != next
	extra["binding_changed"] = fmt.Sprint(changed)
	extra["template_id"] = next.TemplateID.String()
	extra["locale"] = string(next.Locale)
	extra["custom_body"] = fmt.Sprint(next.CustomBody)
	if changed {
		extra["previous_template_id"] = previous.TemplateID.String()
		extra["previous_locale"] = string(previous.Locale)
		extra["previous_custom_body"] = fmt.Sprint(previous.CustomBody)
	}
	return extra
}

// checkCustomBody revalidates the active body of a webhook template a channel opts into (#1376):
// the catalog may have changed since the template was saved.
func (s *Service) checkCustomBody(ctx context.Context, tenant shared.ID, head domain.Template) error {
	version, err := s.templates.GetNotificationTemplateVersion(ctx, tenant, head.ID, head.ActiveVersion)
	if err != nil {
		return err
	}
	if version.Fields["body"] == "" {
		return fmt.Errorf("%w: template %s has no body to send as a custom body", shared.ErrValidation, head.ID)
	}
	return validateTemplateContent(head.TemplateKey, version.Fields)
}

func containsChannel(ids []shared.ID, id shared.ID) bool {
	for _, candidate := range ids {
		if candidate == id {
			return true
		}
	}
	return false
}
