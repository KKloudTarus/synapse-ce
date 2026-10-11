package notification

import (
	"context"
	"errors"
	"fmt"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ResolutionTier names where a delivery's template came from (#1371). The tiers are tried in this
// order and the first match wins; within every tier the locale is tried exactly, then "*", then en.
//
//  1. channel: the template bound to the channel, when it is active, covers the event type and its
//     locale is one of the locale chain.
//  2. tenant_event: the tenant's active template for (event type, family, locale).
//  3. tenant_wildcard: the tenant's active template for ("*", family, locale).
//  4. builtin: the template shipped with the build (#1366).
//  5. fallback: no template; the sender keeps its current raw rendering.
type ResolutionTier string

const (
	TierChannel        ResolutionTier = "channel"
	TierTenantEvent    ResolutionTier = "tenant_event"
	TierTenantWildcard ResolutionTier = "tenant_wildcard"
	TierBuiltin        ResolutionTier = "builtin"
	TierFallback       ResolutionTier = "fallback"
)

// LocaleSource names where the requested locale came from: the channel's own locale, the tenant's
// default_locale, or the product default (en) when neither is set.
type LocaleSource string

const (
	LocaleFromChannel LocaleSource = "channel"
	LocaleFromTenant  LocaleSource = "tenant"
	LocaleFromDefault LocaleSource = "default"
)

// BindingSkip explains why a channel's bound template did not render an event.
type BindingSkip string

const (
	BindingNotActive       BindingSkip = "template_not_active"
	BindingEventNotCovered BindingSkip = "event_not_covered"
	BindingLocaleMismatch  BindingSkip = "locale_not_covered"
	BindingFamilyMismatch  BindingSkip = "family_mismatch"
	BindingMissing         BindingSkip = "template_missing"
)

// TemplateResolution is the template chosen for one (channel, event type). The JSON form is the
// console preview: it names the template and version but never carries template source.
type TemplateResolution struct {
	Tier      ResolutionTier        `json:"tier"`
	EventType domain.EventType      `json:"event_type"`
	Family    domain.TemplateFamily `json:"family,omitempty"`
	// Locale is the language to render in: the requested locale, whichever tier matched.
	Locale       tenancy.Locale `json:"locale"`
	LocaleSource LocaleSource   `json:"locale_source"`
	// MatchedLocale is the locale key of the template that matched: Locale, "*" or en. Empty for
	// the fallback tier.
	MatchedLocale tenancy.Locale `json:"matched_locale,omitempty"`
	// Template and Version are set for the channel and tenant tiers. Version holds the content that
	// renders and is not serialized.
	Template      *domain.Template        `json:"template,omitempty"`
	Version       *domain.TemplateVersion `json:"-"`
	ActiveVersion int                     `json:"version,omitempty"`
	// Builtin is set for the builtin tier and is not serialized; BuiltinRef names it.
	Builtin    *ports.BuiltinTemplate `json:"-"`
	BuiltinRef string                 `json:"builtin_ref,omitempty"`
	// BindingSkipped is why a bound template did not apply, or empty.
	BindingSkipped BindingSkip `json:"binding_skipped,omitempty"`
}

// templateLookup returns the tenant's active template for exactly key.
type templateLookup func(ctx context.Context, key domain.TemplateKey) (domain.Template, domain.TemplateVersion, bool, error)

// boundTemplate is a channel's bound template as resolution sees it. Version is the active version
// and is nil when the template is not active.
type boundTemplate struct {
	Template domain.Template
	Version  *domain.TemplateVersion
}

// resolutionInput is everything resolution reads besides the tenant tiers and the built-ins.
type resolutionInput struct {
	EventType    domain.EventType
	Family       domain.TemplateFamily
	Locale       tenancy.Locale
	LocaleSource LocaleSource
	// Bound is the channel's bound template, or nil when the channel binds none. A binding whose
	// template no longer exists is passed as BoundMissing.
	Bound        *boundTemplate
	BoundMissing bool
}

// resolveTemplate walks the tiers in order. It performs no I/O of its own: lookup reads the tenant
// templates and builtins the shipped ones, so a table test covers every tier and locale step. A nil
// lookup skips the tenant tiers (no template store is wired).
func resolveTemplate(ctx context.Context, in resolutionInput, lookup templateLookup, builtins ports.BuiltinTemplates) (TemplateResolution, error) {
	out := TemplateResolution{EventType: in.EventType, Family: in.Family, Locale: in.Locale, LocaleSource: in.LocaleSource}
	if !in.Family.Valid() {
		out.Tier = TierFallback
		return out, nil
	}
	chain := domain.LocaleChain(in.Locale)

	switch {
	case in.BoundMissing:
		out.BindingSkipped = BindingMissing
	case in.Bound != nil:
		bound := in.Bound.Template
		switch {
		case bound.Family != in.Family:
			out.BindingSkipped = BindingFamilyMismatch
		case bound.Status != domain.TemplateActive || in.Bound.Version == nil:
			out.BindingSkipped = BindingNotActive
		case !bound.Covers(in.EventType):
			out.BindingSkipped = BindingEventNotCovered
		case !containsLocale(chain, bound.Locale):
			out.BindingSkipped = BindingLocaleMismatch
		default:
			template, version := bound, *in.Bound.Version
			out.Tier, out.MatchedLocale = TierChannel, bound.Locale
			out.Template, out.Version, out.ActiveVersion = &template, &version, version.Version
			return out, nil
		}
	}

	if lookup != nil {
		for _, tier := range []struct {
			tier      ResolutionTier
			eventType domain.EventType
		}{{TierTenantEvent, in.EventType}, {TierTenantWildcard, domain.AnyEventType}} {
			for _, locale := range chain {
				template, version, found, err := lookup(ctx, domain.TemplateKey{EventType: tier.eventType, Family: in.Family, Locale: locale})
				if err != nil {
					return TemplateResolution{}, err
				}
				if found {
					out.Tier, out.MatchedLocale = tier.tier, locale
					out.Template, out.Version, out.ActiveVersion = &template, &version, version.Version
					return out, nil
				}
			}
		}
	}

	if builtins != nil {
		for _, eventType := range []domain.EventType{in.EventType, domain.AnyEventType} {
			for _, locale := range chain {
				if builtin, found := builtins.Builtin(eventType, in.Family, locale); found {
					out.Tier, out.MatchedLocale = TierBuiltin, locale
					out.Builtin, out.BuiltinRef = &builtin, builtin.Ref
					return out, nil
				}
			}
		}
	}
	out.Tier = TierFallback
	return out, nil
}

func containsLocale(chain []tenancy.Locale, locale tenancy.Locale) bool {
	for _, candidate := range chain {
		if candidate == locale {
			return true
		}
	}
	return false
}

// SetBuiltinTemplates wires the built-in template catalog (#1366). Without it resolution has no
// builtin tier.
func (s *Service) SetBuiltinTemplates(builtins ports.BuiltinTemplates) { s.builtins = builtins }

// SetTenantSettings lets resolution read the tenant's default_locale (#1359). Without it the
// locale falls back from the channel's to en.
func (s *Service) SetTenantSettings(store ports.TenantSettingsStore) { s.tenantSettings = store }

// requestedLocale picks the locale a channel renders in: the channel's own, else the tenant's
// default_locale, else en.
func (s *Service) requestedLocale(ctx context.Context, tenant shared.ID, channel domain.Channel) (tenancy.Locale, LocaleSource, error) {
	if channel.Locale.Valid() {
		return channel.Locale, LocaleFromChannel, nil
	}
	if s.tenantSettings != nil {
		settings, found, err := s.tenantSettings.GetTenantSettings(ctx, tenant)
		if err != nil {
			return "", "", fmt.Errorf("read tenant locale: %w", err)
		}
		if found && settings.DefaultLocale.Valid() {
			return settings.DefaultLocale, LocaleFromTenant, nil
		}
	}
	return tenancy.DefaultLocale, LocaleFromDefault, nil
}

// ResolveTemplate picks the template one delivery renders with: the channel's bound template, the
// tenant's templates for the event type then for "*", the built-in, or the fallback, trying the
// requested locale, "*" then en in each tier. The locale is the channel's, the tenant's default or
// en.
//
// The send-time renderer (#1365) calls it through RenderMessage on a delivery's first attempt; the
// worker passes the tenant explicitly.
func (s *Service) ResolveTemplate(ctx context.Context, tenant, channelID shared.ID, eventType domain.EventType) (TemplateResolution, error) {
	if tenant.IsZero() {
		return TemplateResolution{}, fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	if !eventType.Valid() {
		return TemplateResolution{}, fmt.Errorf("%w: event_type must be a catalog event type", shared.ErrValidation)
	}
	channel, err := s.repo.GetChannel(ctx, tenant, channelID)
	if err != nil {
		return TemplateResolution{}, err
	}
	return s.resolveForChannel(ctx, tenant, channel, eventType)
}

// PreviewTemplateResolution is ResolveTemplate for the caller's tenant, served to the console so a
// rule form can show which template each channel will use.
func (s *Service) PreviewTemplateResolution(ctx context.Context, channelID shared.ID, eventType domain.EventType) (TemplateResolution, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return TemplateResolution{}, err
	}
	return s.ResolveTemplate(ctx, tenant, channelID, eventType)
}

func (s *Service) resolveForChannel(ctx context.Context, tenant shared.ID, channel domain.Channel, eventType domain.EventType) (TemplateResolution, error) {
	locale, source, err := s.requestedLocale(ctx, tenant, channel)
	if err != nil {
		return TemplateResolution{}, err
	}
	family, _ := domain.FamilyForChannelType(channel.Type)
	in := resolutionInput{EventType: eventType, Family: family, Locale: locale, LocaleSource: source}
	var lookup templateLookup
	if s.templates != nil {
		lookup = func(ctx context.Context, key domain.TemplateKey) (domain.Template, domain.TemplateVersion, bool, error) {
			return s.templates.ActiveNotificationTemplate(ctx, tenant, key)
		}
		if !channel.TemplateID.IsZero() {
			bound, err := s.loadBoundTemplate(ctx, tenant, channel.TemplateID)
			switch {
			case errors.Is(err, shared.ErrNotFound):
				in.BoundMissing = true
			case err != nil:
				return TemplateResolution{}, err
			default:
				in.Bound = &bound
			}
		}
	}
	return resolveTemplate(ctx, in, lookup, s.builtins)
}

// loadBoundTemplate reads a bound template and, when it is active, the version that renders.
func (s *Service) loadBoundTemplate(ctx context.Context, tenant, id shared.ID) (boundTemplate, error) {
	head, err := s.templates.GetNotificationTemplate(ctx, tenant, id)
	if err != nil {
		return boundTemplate{}, err
	}
	bound := boundTemplate{Template: head}
	if head.Status == domain.TemplateActive && head.ActiveVersion > 0 {
		version, err := s.templates.GetNotificationTemplateVersion(ctx, tenant, id, head.ActiveVersion)
		if err != nil {
			return boundTemplate{}, err
		}
		bound.Version = &version
	}
	return bound, nil
}
