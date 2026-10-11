package notification

import (
	"context"
	"errors"
	"fmt"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// tenantTemplates is a lookup over active tenant templates, keyed exactly.
type tenantTemplates map[domain.TemplateKey]domain.Template

func (m tenantTemplates) lookup(_ context.Context, key domain.TemplateKey) (domain.Template, domain.TemplateVersion, bool, error) {
	t, ok := m[key]
	if !ok {
		return domain.Template{}, domain.TemplateVersion{}, false, nil
	}
	return t, domain.TemplateVersion{TemplateID: t.ID, Version: t.ActiveVersion}, true, nil
}

type builtinSet map[domain.TemplateKey]bool

func (b builtinSet) Builtin(eventType domain.EventType, family domain.TemplateFamily, locale tenancy.Locale) (ports.BuiltinTemplate, bool) {
	key := domain.TemplateKey{EventType: eventType, Family: family, Locale: locale}
	if !b[key] {
		return ports.BuiltinTemplate{}, false
	}
	return ports.BuiltinTemplate{Ref: fmt.Sprintf("builtin:%s:%s:%s", eventType, family, locale), TemplateKey: key}, true
}

func (b builtinSet) List() []ports.BuiltinTemplate { return nil }

func activeTemplate(id string, key domain.TemplateKey) domain.Template {
	return domain.Template{TenantID: "tenant", ID: shared.ID(id), TemplateKey: key, Status: domain.TemplateActive, LatestVersion: 3, ActiveVersion: 2}
}

// A resolution world: which templates exist at which (tier, locale step).
type slot struct {
	tier ResolutionTier
	step int // index into the locale chain
}

var orderedTiers = []ResolutionTier{TierChannel, TierTenantEvent, TierTenantWildcard, TierBuiltin}

func buildWorld(family domain.TemplateFamily, event domain.EventType, chain []tenancy.Locale, slots []slot) (resolutionInput, tenantTemplates, builtinSet) {
	in := resolutionInput{EventType: event, Family: family, Locale: chain[0], LocaleSource: LocaleFromTenant}
	tenant, builtins := tenantTemplates{}, builtinSet{}
	for _, s := range slots {
		locale := chain[s.step]
		id := fmt.Sprintf("%s-%s", s.tier, locale)
		switch s.tier {
		case TierChannel:
			// A channel binds one template; the highest-priority step wins the slot.
			if in.Bound == nil {
				t := activeTemplate(id, domain.TemplateKey{EventType: event, Family: family, Locale: locale})
				in.Bound = &boundTemplate{Template: t, Version: &domain.TemplateVersion{TemplateID: t.ID, Version: t.ActiveVersion}}
			}
		case TierTenantEvent:
			key := domain.TemplateKey{EventType: event, Family: family, Locale: locale}
			tenant[key] = activeTemplate(id, key)
		case TierTenantWildcard:
			key := domain.TemplateKey{EventType: domain.AnyEventType, Family: family, Locale: locale}
			tenant[key] = activeTemplate(id, key)
		case TierBuiltin:
			builtins[domain.TemplateKey{EventType: event, Family: family, Locale: locale}] = true
		}
	}
	return in, tenant, builtins
}

// Every tier at every locale step, for a request whose locale chain has three distinct steps (vi:
// vi, *, en) and for one where it has two (en: en, *). For the expected (tier, step) the world also
// holds a template at every lower tier and every later step of the same tier, so the case proves
// both that the slot is found and that it beats everything below it.
func TestResolveTemplateTiersAndLocaleFallback(t *testing.T) {
	ctx := context.Background()
	for _, requested := range []tenancy.Locale{tenancy.LocaleVietnamese, tenancy.LocaleEnglish} {
		chain := domain.LocaleChain(requested)
		for ti, tier := range orderedTiers {
			for step := range chain {
				name := fmt.Sprintf("%s/%s/%s", requested, tier, chain[step])
				t.Run(name, func(t *testing.T) {
					slots := []slot{{tier, step}}
					for later := step + 1; later < len(chain); later++ {
						slots = append(slots, slot{tier, later})
					}
					for _, lower := range orderedTiers[ti+1:] {
						for s := range chain {
							slots = append(slots, slot{lower, s})
						}
					}
					in, tenant, builtins := buildWorld(domain.FamilyChat, domain.EventScanCompleted, chain, slots)
					got, err := resolveTemplate(ctx, in, tenant.lookup, builtins)
					if err != nil {
						t.Fatal(err)
					}
					if got.Tier != tier || got.MatchedLocale != chain[step] || got.Locale != requested || got.LocaleSource != LocaleFromTenant {
						t.Fatalf("got tier=%s matched=%s locale=%s, want tier=%s matched=%s locale=%s", got.Tier, got.MatchedLocale, got.Locale, tier, chain[step], requested)
					}
					switch tier {
					case TierBuiltin:
						if got.Builtin == nil || got.BuiltinRef == "" || got.Template != nil {
							t.Fatalf("builtin resolution = %+v", got)
						}
					default:
						wantID := fmt.Sprintf("%s-%s", tier, chain[step])
						if got.Template == nil || got.Template.ID.String() != wantID || got.Version == nil || got.ActiveVersion != 2 {
							t.Fatalf("template = %+v version=%+v, want %s at its active version", got.Template, got.Version, wantID)
						}
					}
				})
			}
		}
		t.Run(string(requested)+"/fallback", func(t *testing.T) {
			got, err := resolveTemplate(ctx, resolutionInput{EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: requested, LocaleSource: LocaleFromDefault}, tenantTemplates{}.lookup, builtinSet{})
			if err != nil || got.Tier != TierFallback || got.MatchedLocale != "" || got.Template != nil || got.Builtin != nil {
				t.Fatalf("fallback = %+v err=%v", got, err)
			}
		})
	}
}

// Templates of another family, another event type, or a locale outside the chain never match.
func TestResolveTemplateIgnoresOtherKeys(t *testing.T) {
	tenant := tenantTemplates{}
	for _, key := range []domain.TemplateKey{
		{EventType: domain.EventScanCompleted, Family: domain.FamilyEmail, Locale: "vi"},
		{EventType: domain.EventIncidentCreated, Family: domain.FamilyChat, Locale: "vi"},
		{EventType: domain.AnyEventType, Family: domain.FamilyWebhook, Locale: "*"},
	} {
		tenant[key] = activeTemplate("other", key)
	}
	// An English request never falls back to Vietnamese.
	tenant[domain.TemplateKey{EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "vi"}] = activeTemplate("vi-only", domain.TemplateKey{EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "vi"})
	got, err := resolveTemplate(context.Background(), resolutionInput{EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "en"}, tenant.lookup, builtinSet{})
	if err != nil || got.Tier != TierFallback {
		t.Fatalf("resolution = %+v err=%v", got, err)
	}
}

// A bound template that cannot render the event is skipped with a reason, and resolution falls
// through to the tenant tiers.
func TestResolveTemplateSkipsAnUnusableBinding(t *testing.T) {
	key := domain.TemplateKey{EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "vi"}
	usable := activeTemplate("bound", key)
	version := &domain.TemplateVersion{TemplateID: "bound", Version: 2}
	archived := usable
	archived.Status = domain.TemplateArchived
	otherEvent := activeTemplate("bound", domain.TemplateKey{EventType: domain.EventIncidentCreated, Family: domain.FamilyChat, Locale: "vi"})
	english := activeTemplate("bound", domain.TemplateKey{EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "en"})
	emailFamily := activeTemplate("bound", domain.TemplateKey{EventType: domain.EventScanCompleted, Family: domain.FamilyEmail, Locale: "vi"})
	for name, tc := range map[string]struct {
		in     resolutionInput
		reason BindingSkip
	}{
		"archived":     {resolutionInput{Bound: &boundTemplate{Template: archived}}, BindingNotActive},
		"no version":   {resolutionInput{Bound: &boundTemplate{Template: usable}}, BindingNotActive},
		"other event":  {resolutionInput{Bound: &boundTemplate{Template: otherEvent, Version: version}}, BindingEventNotCovered},
		"other family": {resolutionInput{Bound: &boundTemplate{Template: emailFamily, Version: version}}, BindingFamilyMismatch},
		"missing":      {resolutionInput{BoundMissing: true}, BindingMissing},
		// An English channel does not render a Vietnamese template, even a bound one.
		"locale": {resolutionInput{Bound: &boundTemplate{Template: usable, Version: version}, Locale: "en"}, BindingLocaleMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			in := tc.in
			in.EventType, in.Family = domain.EventScanCompleted, domain.FamilyChat
			if in.Locale == "" {
				in.Locale = "vi"
			}
			wildcard := domain.TemplateKey{EventType: domain.AnyEventType, Family: domain.FamilyChat, Locale: "*"}
			tenant := tenantTemplates{wildcard: activeTemplate("tenant-any", wildcard)}
			got, err := resolveTemplate(context.Background(), in, tenant.lookup, nil)
			if err != nil || got.BindingSkipped != tc.reason || got.Tier != TierTenantWildcard || got.Template.ID != "tenant-any" {
				t.Fatalf("resolution = %+v err=%v", got, err)
			}
		})
	}
	// A Vietnamese channel may render an English bound template: en is the last step of its chain.
	got, err := resolveTemplate(context.Background(), resolutionInput{EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "vi",
		Bound: &boundTemplate{Template: english, Version: version}}, nil, nil)
	if err != nil || got.Tier != TierChannel || got.MatchedLocale != "en" || got.Locale != "vi" {
		t.Fatalf("en binding for a vi channel = %+v err=%v", got, err)
	}
}

func TestResolveTemplateWithoutFamilyOrStore(t *testing.T) {
	got, err := resolveTemplate(context.Background(), resolutionInput{EventType: domain.EventScanCompleted, Locale: "en"}, tenantTemplates{}.lookup, builtinSet{})
	if err != nil || got.Tier != TierFallback {
		t.Fatalf("no family = %+v err=%v", got, err)
	}
	key := domain.TemplateKey{EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "en"}
	got, err = resolveTemplate(context.Background(), resolutionInput{EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "en"}, nil, builtinSet{key: true})
	if err != nil || got.Tier != TierBuiltin {
		t.Fatalf("no store = %+v err=%v", got, err)
	}
	boom := errors.New("store down")
	_, err = resolveTemplate(context.Background(), resolutionInput{EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "en"},
		func(context.Context, domain.TemplateKey) (domain.Template, domain.TemplateVersion, bool, error) {
			return domain.Template{}, domain.TemplateVersion{}, false, boom
		}, nil)
	if !errors.Is(err, boom) {
		t.Fatalf("store error = %v", err)
	}
}
