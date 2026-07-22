// Package qualityprofiles manages named, per-language quality profiles: built-in defaults generated
// from the rule catalog plus tenant-scoped custom copies, and their per-project assignment. It is the
// application layer over domain/qualityprofile — it never touches HTTP, the DB, or an LLM directly.
package qualityprofiles

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service coordinates quality-profile reads, mutations, and project assignment.
type Service struct {
	store    ports.QualityProfileStore
	catalog  ports.RuleCatalog
	projects ports.ProjectRepository
	audit    ports.AuditLogger
	clock    ports.Clock
}

// NewService wires the profile service. store persists custom profiles; catalog supplies built-ins and
// per-language rule sets; projects records the per-language assignment.
func NewService(store ports.QualityProfileStore, catalog ports.RuleCatalog, projects ports.ProjectRepository, audit ports.AuditLogger, clock ports.Clock) *Service {
	return &Service{store: store, catalog: catalog, projects: projects, audit: audit, clock: clock}
}

// catalogByLanguage groups every catalog rule by its language, returning the rules and their sorted
// rule keys per language.
func (s *Service) catalogByLanguage(ctx context.Context) (map[string][]rule.Rule, map[string][]rule.Key, error) {
	rules, err := s.catalog.List(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list rule catalog: %w", err)
	}
	byLang := map[string][]rule.Rule{}
	for _, r := range rules {
		byLang[r.Language] = append(byLang[r.Language], r)
	}
	keys := map[string][]rule.Key{}
	for lang, rs := range byLang {
		ks := make([]rule.Key, 0, len(rs))
		for _, r := range rs {
			ks = append(ks, r.Key)
		}
		sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
		keys[lang] = ks
	}
	return byLang, keys, nil
}

// builtIns returns the built-in default profile for every language in the catalog, plus a lookup by key.
func (s *Service) builtIns(ctx context.Context) ([]qualityprofile.Profile, map[string]qualityprofile.Profile, error) {
	byLang, _, err := s.catalogByLanguage(ctx)
	if err != nil {
		return nil, nil, err
	}
	out := make([]qualityprofile.Profile, 0, len(byLang))
	byKey := map[string]qualityprofile.Profile{}
	for lang, rs := range byLang {
		p, ok := qualityprofile.BuiltIn(lang, rs)
		if !ok {
			continue
		}
		out = append(out, p)
		byKey[p.Key] = p
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, byKey, nil
}

// List returns the built-in and custom profiles, optionally filtered to a single language.
func (s *Service) List(ctx context.Context, tenantID shared.ID, language string) ([]qualityprofile.Profile, error) {
	builtIns, _, err := s.builtIns(ctx)
	if err != nil {
		return nil, err
	}
	custom, err := s.store.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list custom profiles: %w", err)
	}
	all := append(builtIns, custom...)
	language = strings.TrimSpace(language)
	if language == "" {
		return all, nil
	}
	out := make([]qualityprofile.Profile, 0, len(all))
	for _, p := range all {
		if p.Language == language {
			out = append(out, p)
		}
	}
	return out, nil
}

// Get resolves a profile by key: a built-in (from the catalog) or a tenant custom profile.
func (s *Service) Get(ctx context.Context, tenantID shared.ID, key string) (qualityprofile.Profile, error) {
	key = strings.TrimSpace(key)
	_, byKey, err := s.builtIns(ctx)
	if err != nil {
		return qualityprofile.Profile{}, err
	}
	if p, ok := byKey[key]; ok {
		return p, nil
	}
	p, err := s.store.Get(ctx, tenantID, key)
	if err != nil {
		return qualityprofile.Profile{}, fmt.Errorf("get profile: %w", err)
	}
	return p, nil
}

func (s *Service) requireActor(actor string) error {
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	return nil
}

func (s *Service) record(ctx context.Context, actor, action, target string, meta map[string]string) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: target, Metadata: meta, At: s.clock.Now()})
}

// Copy creates a custom profile from a built-in or another custom profile.
func (s *Service) Copy(ctx context.Context, actor string, tenantID shared.ID, sourceKey, newKey, newName string) (qualityprofile.Profile, error) {
	if err := s.requireActor(actor); err != nil {
		return qualityprofile.Profile{}, err
	}
	source, err := s.Get(ctx, tenantID, sourceKey)
	if err != nil {
		return qualityprofile.Profile{}, err
	}
	copied, err := source.Copy(newKey, newName)
	if err != nil {
		return qualityprofile.Profile{}, err
	}
	if err := s.builtInConflict(ctx, copied.Key); err != nil {
		return qualityprofile.Profile{}, err
	}
	if err := s.store.Create(ctx, tenantID, copied); err != nil {
		return qualityprofile.Profile{}, fmt.Errorf("create profile: %w", err)
	}
	if err := s.record(ctx, actor, "quality_profile.copy", copied.Key, map[string]string{"profile": copied.Key, "parent": copied.Parent, "language": copied.Language}); err != nil {
		return qualityprofile.Profile{}, fmt.Errorf("audit quality_profile.copy: %w", err)
	}
	return copied, nil
}

// builtInConflict rejects a custom key that collides with a built-in profile key.
func (s *Service) builtInConflict(ctx context.Context, key string) error {
	_, byKey, err := s.builtIns(ctx)
	if err != nil {
		return err
	}
	if _, ok := byKey[key]; ok {
		return fmt.Errorf("%w: profile key %q is reserved by a built-in", shared.ErrValidation, key)
	}
	return nil
}

// mutateCustom loads a custom profile, applies fn, persists the result, and audits.
func (s *Service) mutateCustom(ctx context.Context, actor string, tenantID shared.ID, key, action string, meta map[string]string, fn func(qualityprofile.Profile) (qualityprofile.Profile, error)) (qualityprofile.Profile, error) {
	if err := s.requireActor(actor); err != nil {
		return qualityprofile.Profile{}, err
	}
	if _, byKey, err := s.builtIns(ctx); err != nil {
		return qualityprofile.Profile{}, err
	} else if _, ok := byKey[strings.TrimSpace(key)]; ok {
		return qualityprofile.Profile{}, fmt.Errorf("%w: built-in profiles cannot be modified", shared.ErrValidation)
	}
	current, err := s.store.Get(ctx, tenantID, strings.TrimSpace(key))
	if err != nil {
		return qualityprofile.Profile{}, fmt.Errorf("get profile: %w", err)
	}
	updated, err := fn(current)
	if err != nil {
		return qualityprofile.Profile{}, err
	}
	if err := s.store.Update(ctx, tenantID, updated); err != nil {
		return qualityprofile.Profile{}, fmt.Errorf("update profile: %w", err)
	}
	if err := s.record(ctx, actor, action, updated.Key, meta); err != nil {
		return qualityprofile.Profile{}, fmt.Errorf("audit %s: %w", action, err)
	}
	return updated, nil
}

// ActivateRule enables a rule in a custom profile (with an optional severity override).
func (s *Service) ActivateRule(ctx context.Context, actor string, tenantID shared.ID, key, ruleKey string, severity shared.Severity) (qualityprofile.Profile, error) {
	return s.mutateCustom(ctx, actor, tenantID, key, "quality_profile.activate_rule", map[string]string{"profile": key, "rule": ruleKey},
		func(p qualityprofile.Profile) (qualityprofile.Profile, error) { return p.Activate(ruleKey, severity) })
}

// DeactivateRule disables a rule in a custom profile.
func (s *Service) DeactivateRule(ctx context.Context, actor string, tenantID shared.ID, key, ruleKey string) (qualityprofile.Profile, error) {
	return s.mutateCustom(ctx, actor, tenantID, key, "quality_profile.deactivate_rule", map[string]string{"profile": key, "rule": ruleKey},
		func(p qualityprofile.Profile) (qualityprofile.Profile, error) { return p.Deactivate(ruleKey) })
}

// SetSeverity overrides the severity of an active rule in a custom profile.
func (s *Service) SetSeverity(ctx context.Context, actor string, tenantID shared.ID, key, ruleKey string, severity shared.Severity) (qualityprofile.Profile, error) {
	return s.mutateCustom(ctx, actor, tenantID, key, "quality_profile.set_severity", map[string]string{"profile": key, "rule": ruleKey, "severity": string(severity)},
		func(p qualityprofile.Profile) (qualityprofile.Profile, error) {
			return p.SetSeverity(ruleKey, severity)
		})
}

// Delete removes a custom profile. Built-in profiles cannot be deleted.
func (s *Service) Delete(ctx context.Context, actor string, tenantID shared.ID, key string) error {
	if err := s.requireActor(actor); err != nil {
		return err
	}
	key = strings.TrimSpace(key)
	if _, byKey, err := s.builtIns(ctx); err != nil {
		return err
	} else if _, ok := byKey[key]; ok {
		return fmt.Errorf("%w: built-in profiles cannot be deleted", shared.ErrValidation)
	}
	if err := s.store.Delete(ctx, tenantID, key); err != nil {
		return fmt.Errorf("delete profile: %w", err)
	}
	return s.record(ctx, actor, "quality_profile.delete", key, map[string]string{"profile": key})
}

// Assign sets (or clears, with an empty profileKey) the profile assigned to a language for a project.
// The profile must exist and match the language.
func (s *Service) Assign(ctx context.Context, actor string, tenantID shared.ID, projectKey, language, profileKey string) error {
	if err := s.requireActor(actor); err != nil {
		return err
	}
	language = strings.TrimSpace(language)
	if language == "" {
		return fmt.Errorf("%w: language is required", shared.ErrValidation)
	}
	profileKey = strings.TrimSpace(profileKey)
	if profileKey != "" {
		p, err := s.Get(ctx, tenantID, profileKey)
		if err != nil {
			return err
		}
		if p.Language != language {
			return fmt.Errorf("%w: profile %q is for language %q, not %q", shared.ErrValidation, profileKey, p.Language, language)
		}
	}
	if err := s.projects.AssignProfile(ctx, tenantID, strings.TrimSpace(projectKey), language, profileKey); err != nil {
		return fmt.Errorf("assign profile: %w", err)
	}
	return s.record(ctx, actor, "quality_profile.assign", projectKey, map[string]string{"project": projectKey, "language": language, "profile": profileKey})
}

// OverlayForProject builds the combined .synapse-rules.yaml-equivalent overlay a project's assigned
// profiles impose on findings: each assigned language profile deactivates its non-active rules and
// applies severity overrides. Languages with no assignment (or an assignment to their built-in default)
// contribute nothing, so findings pass through unchanged. Rule keys are language-disjoint, so the
// per-language overlays union cleanly. A missing/mismatched assignment is skipped (best-effort:
// analysis is never failed by a stale assignment).
func (s *Service) OverlayForProject(ctx context.Context, tenantID shared.ID, assigned map[string]string) (qualitygate.Profile, error) {
	overlay := qualitygate.Profile{Rules: map[string]qualitygate.RuleConfig{}}
	if len(assigned) == 0 {
		return overlay, nil
	}
	_, keysByLang, err := s.catalogByLanguage(ctx)
	if err != nil {
		return qualitygate.Profile{}, err
	}
	langs := make([]string, 0, len(assigned))
	for lang := range assigned {
		langs = append(langs, lang)
	}
	sort.Strings(langs) // deterministic overlay assembly
	for _, lang := range langs {
		profileKey := strings.TrimSpace(assigned[lang])
		if profileKey == "" || profileKey == qualityprofile.BuiltInKey(lang) {
			continue // no assignment, or the built-in default (activates everything) → no overlay
		}
		p, err := s.Get(ctx, tenantID, profileKey)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				continue // stale assignment: skip rather than fail the analysis
			}
			return qualitygate.Profile{}, err
		}
		if p.Language != lang {
			continue
		}
		for k, cfg := range p.ToOverlay(keysByLang[lang]).Rules {
			overlay.Rules[k] = cfg
		}
	}
	return overlay, nil
}
