package notification

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Send-time rendering (#1365). A delivery renders from the context snapshot stored with its event,
// filtered to the effective data class (#1360), with the template its first attempt pinned. The
// worker and the console preview (#1372) share RenderMessage, so a preview shows the bytes a send
// would.

// Template references recorded on deliveries and attempts. A built-in's reference is its own
// BuiltinRef ("builtin:<event>:<family>:<locale>@<build>").
const (
	// refFallback marks a delivery that renders the channel driver's built-in content: no template
	// applies, or the one that did failed to render.
	refFallback  = "fallback"
	refTenantTag = "tenant:"
	refDraftTag  = "draft:"
	// maxRenderedRunes bounds one rendered field; channel formatters apply their own, tighter limits.
	maxRenderedRunes = 8000
)

// RenderInput is one message to render.
type RenderInput struct {
	Channel domain.Channel
	// Event carries the #1344 context snapshot.
	Event domain.Event
	// Engagement is the event's engagement override (#1360).
	Engagement domain.EngagementNotifications
	// Pin is a template reference a previous attempt recorded; retries render with it. Empty
	// resolves.
	Pin string
	// Draft renders this version instead of resolving (console preview only).
	Draft *domain.TemplateVersion
}

// RenderResult is a rendered message.
type RenderResult struct {
	// Suppressed reports that the engagement allows no external notification; nothing else is set.
	Suppressed bool
	Resolution TemplateResolution
	// Message holds the rendered fields and the template reference to record. Its Fields are empty
	// when the fallback applies, and the driver then sends its built-in content.
	Message ports.RenderedMessage
	// Formatted is the channel's wire payload, when a formatter for the channel type is set and
	// fields were rendered.
	Formatted *ports.FormattedMessage
	// CustomBody is a webhook channel's rendered custom JSON body (#1376).
	CustomBody []byte
	// Fallback reports that a template applied but failed to render, so the built-in content is
	// sent instead (recorded as template_fallback).
	Fallback bool
}

// SetFormatters wires the channel formatters (#1364) so RenderMessage returns wire payloads.
func (s *Service) SetFormatters(formatters map[domain.ChannelType]ports.NotificationFormatter) {
	s.formatters = formatters
}

// RenderMessage renders one message: it applies the effective data class, presents time variables
// in the tenant's zone, resolves the template (or uses the pinned one or a draft), renders its
// fields and formats them for the channel. A template that fails to render is not an error: the
// result falls back to the driver's built-in content. Errors are store failures only.
func (s *Service) RenderMessage(ctx context.Context, in RenderInput) (RenderResult, error) {
	class, deliver := domain.EffectiveDataClass(in.Channel.Class(), in.Engagement)
	if !deliver {
		return RenderResult{Suppressed: true}, nil
	}
	spec, ok := domain.LookupEvent(in.Event.Type)
	if !ok {
		// No catalog entry, so no template schema: the driver's built-in content applies.
		return RenderResult{Message: ports.RenderedMessage{TemplateRef: refFallback}}, nil
	}
	resolution, err := s.renderResolution(ctx, in)
	if err != nil {
		return RenderResult{}, err
	}
	out := RenderResult{Resolution: resolution, Message: ports.RenderedMessage{TemplateRef: templateRef(resolution)}}
	fields := templateFields(resolution)
	if len(fields) == 0 {
		out.Message.TemplateRef = refFallback
		return out, nil
	}
	vars, err := s.renderVars(ctx, in, spec, class)
	if err != nil {
		return RenderResult{}, err
	}
	if resolution.Family == domain.FamilyWebhook {
		return s.renderWebhookBody(out, in.Channel, resolution, vars), nil
	}
	rendered, err := renderFields(resolution, fields, vars)
	if err != nil {
		return fallback(out), nil
	}
	out.Message.Fields = rendered
	if formatter, ok := s.formatters[in.Channel.Type]; ok {
		formatted, err := formatter.Format(out.Message)
		if err != nil {
			return fallback(out), nil
		}
		out.Formatted = &formatted
	}
	return out, nil
}

// renderResolution picks the template: the draft, the pinned one, or a fresh resolution. A pin
// that no longer loads (a store error aside) resolves again rather than failing the delivery.
func (s *Service) renderResolution(ctx context.Context, in RenderInput) (TemplateResolution, error) {
	tenant := in.Channel.TenantID
	if in.Draft != nil {
		family, _ := domain.FamilyForChannelType(in.Channel.Type)
		return TemplateResolution{Tier: TierTenantEvent, EventType: in.Event.Type, Family: family, Version: in.Draft}, nil
	}
	if in.Pin != "" {
		resolution, found, err := s.pinnedResolution(ctx, tenant, in.Channel, in.Event.Type, in.Pin)
		if err != nil || found {
			return resolution, err
		}
	}
	return s.resolveForChannel(ctx, tenant, in.Channel, in.Event.Type)
}

// pinnedResolution loads the template a reference names. found is false when it names nothing
// that still exists.
func (s *Service) pinnedResolution(ctx context.Context, tenant shared.ID, channel domain.Channel, eventType domain.EventType, ref string) (TemplateResolution, bool, error) {
	family, _ := domain.FamilyForChannelType(channel.Type)
	base := TemplateResolution{EventType: eventType, Family: family}
	switch {
	case ref == refFallback:
		base.Tier = TierFallback
		return base, true, nil
	case strings.HasPrefix(ref, refTenantTag):
		id, version, ok := parseTenantRef(strings.TrimPrefix(ref, refTenantTag))
		if !ok || s.templates == nil {
			return base, false, nil
		}
		v, err := s.templates.GetNotificationTemplateVersion(ctx, tenant, id, version)
		if errors.Is(err, shared.ErrNotFound) {
			return base, false, nil
		}
		if err != nil {
			return base, false, err
		}
		base.Tier, base.Version, base.ActiveVersion = TierTenantEvent, &v, version
		return base, true, nil
	}
	for _, builtin := range s.builtins.List() {
		if builtin.Ref == ref {
			b := builtin
			base.Tier, base.Builtin, base.BuiltinRef = TierBuiltin, &b, b.Ref
			return base, true, nil
		}
	}
	return base, false, nil
}

// templateRef is the reference a resolution records.
func templateRef(r TemplateResolution) string {
	switch {
	case r.Builtin != nil:
		return r.BuiltinRef
	case r.Version != nil:
		tag := refTenantTag
		if r.Template == nil && r.ActiveVersion == 0 {
			tag = refDraftTag
		}
		return tag + r.Version.TemplateID.String() + "@" + strconv.Itoa(r.Version.Version)
	}
	return refFallback
}

func parseTenantRef(v string) (shared.ID, int, bool) {
	id, version, ok := strings.Cut(v, "@")
	n, err := strconv.Atoi(version)
	if !ok || id == "" || err != nil || n < 1 {
		return "", 0, false
	}
	return shared.ID(id), n, true
}

// templateFields returns the source of each content field the resolution renders.
func templateFields(r TemplateResolution) map[string]string {
	switch {
	case r.Version != nil:
		return r.Version.Fields
	case r.Builtin != nil:
		return r.Builtin.Fields
	}
	return nil
}

// renderVars is the snapshot filtered to the effective class, with time variables shown in the
// tenant's zone.
func (s *Service) renderVars(ctx context.Context, in RenderInput, spec domain.EventSpec, class domain.DataClass) (map[string]string, error) {
	snapshot, err := domain.DecodeTemplateContext(in.Event.Context)
	if err != nil {
		return nil, err
	}
	vars := snapshot.Filter(spec, class).Vars
	location, err := s.tenantLocation(ctx, in.Channel.TenantID)
	if err != nil {
		return nil, err
	}
	for _, v := range spec.Variables {
		if value, ok := vars[v.Name]; ok && v.Format == domain.VariableFormatTime {
			vars[v.Name] = presentTime(value, location)
		}
	}
	return vars, nil
}

// tenantLocation is the tenant's time zone, UTC when it saved none or the zone no longer loads.
func (s *Service) tenantLocation(ctx context.Context, tenant shared.ID) (*time.Location, error) {
	if s.tenantSettings == nil {
		return time.UTC, nil
	}
	settings, found, err := s.tenantSettings.GetTenantSettings(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("read tenant time zone: %w", err)
	}
	zone := tenancy.DefaultTimeZone
	if found && settings.TimeZone != "" {
		zone = settings.TimeZone
	}
	location, err := time.LoadLocation(zone)
	if err != nil {
		return time.UTC, nil
	}
	return location, nil
}

// presentTime shows an RFC 3339 instant in loc with the zone's abbreviation. A value that does not
// parse is left as it is.
func presentTime(value string, loc *time.Location) string {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return t.In(loc).Format("2006-01-02 15:04 MST")
}

// renderFields renders every content field of the family.
func renderFields(r TemplateResolution, sources map[string]string, vars map[string]string) (map[string]string, error) {
	schemas, err := templateSchemas(r.EventType)
	if err != nil || len(schemas) != 1 {
		return nil, fmt.Errorf("%w: no template schema for %s", shared.ErrValidation, r.EventType)
	}
	out := map[string]string{}
	for _, field := range r.Family.Fields() {
		source := sources[field]
		if source == "" {
			continue
		}
		tmpl, err := msgtemplate.Compile(field, source, schemas[0].schema)
		if err != nil {
			return nil, err
		}
		rendered, err := tmpl.Render(msgtemplate.Data{Vars: vars}, maxRenderedRunes)
		if err != nil {
			return nil, err
		}
		out[field] = rendered.Text
	}
	return out, nil
}

// renderWebhookBody renders a webhook channel's custom body when it opted into one; otherwise the
// driver sends the event envelope, which is not a fallback.
func (s *Service) renderWebhookBody(out RenderResult, channel domain.Channel, r TemplateResolution, vars map[string]string) RenderResult {
	if !channel.CustomBody {
		out.Message.TemplateRef = refFallback
		return out
	}
	body, ok, err := RenderCustomWebhookBody(r, vars)
	if err != nil || !ok {
		return fallback(out)
	}
	out.CustomBody = body
	return out
}

func fallback(out RenderResult) RenderResult {
	out.Message.Fields, out.Formatted, out.CustomBody = nil, nil, nil
	out.Message.TemplateRef = refFallback
	out.Fallback = true
	return out
}
