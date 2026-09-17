package qualityprofiles

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeCatalog struct{ rules []rule.Rule }

func (c fakeCatalog) List(context.Context) ([]rule.Rule, error) { return c.rules, nil }
func (c fakeCatalog) Get(_ context.Context, key rule.Key) (rule.Rule, error) {
	for _, r := range c.rules {
		if r.Key == key {
			return r, nil
		}
	}
	return rule.Rule{}, shared.ErrNotFound
}

type nopClock struct{}

func (nopClock) Now() time.Time { return time.Unix(0, 0).UTC() }

type nopAudit struct{}

func (nopAudit) Record(context.Context, ports.AuditEntry) error { return nil }

func newTestService(t *testing.T) (*Service, *memory.ProjectRepository, shared.ID) {
	t.Helper()
	cat := fakeCatalog{rules: []rule.Rule{
		{Key: "go-a", Language: "Go", DefaultSeverity: shared.SeverityHigh},
		{Key: "go-b", Language: "Go", DefaultSeverity: shared.SeverityMedium},
		{Key: "py-a", Language: "Python", DefaultSeverity: shared.SeverityLow},
	}}
	projects := memory.NewProjectRepository()
	svc := NewService(memory.NewQualityProfileStore(), cat, projects, nopAudit{}, nopClock{})
	return svc, projects, shared.ID("tenant")
}

func TestServiceListBuiltInsPerLanguage(t *testing.T) {
	svc, _, tenant := newTestService(t)
	ctx := context.Background()

	all, err := svc.List(ctx, tenant, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 6 { // three presets (Synapse way, Recommended, Strict) per language (Go, Python)
		t.Fatalf("want 6 built-ins, got %d: %+v", len(all), all)
	}
	goOnly, err := svc.List(ctx, tenant, "Go")
	if err != nil {
		t.Fatal(err)
	}
	goKeys := map[string]qualityprofile.Profile{}
	for _, p := range goOnly {
		if !p.BuiltIn || p.Language != "Go" {
			t.Fatalf("Go filter returned a non-Go or non-built-in profile: %+v", p)
		}
		goKeys[p.Key] = p
	}
	if len(goKeys) != 3 || goKeys["synapse-way-go"].Key == "" || goKeys["recommended-go"].Key == "" || goKeys["strict-go"].Key == "" {
		t.Fatalf("Go presets = %+v, want synapse-way-go, recommended-go, strict-go", goOnly)
	}
	// Strict escalates severities one level: go-a (high) -> critical, go-b (medium) -> high.
	strict := goKeys["strict-go"]
	if strict.ActivatedRules["go-a"].Severity != shared.SeverityCritical || strict.ActivatedRules["go-b"].Severity != shared.SeverityHigh {
		t.Fatalf("strict-go severities = %+v, want go-a critical, go-b high", strict.ActivatedRules)
	}
	// The default (Synapse way) keeps default severities (no override).
	if sw := goKeys["synapse-way-go"]; sw.ActivatedRules["go-a"].Severity != "" {
		t.Fatalf("synapse-way-go must keep default severities, got %+v", sw.ActivatedRules)
	}
}

func TestServiceCopyToggleAndBuiltInImmutability(t *testing.T) {
	svc, _, tenant := newTestService(t)
	ctx := context.Background()

	// A built-in cannot be mutated or deleted.
	if _, err := svc.DeactivateRule(ctx, "alice", tenant, "synapse-way-go", "go-a"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("mutating a built-in must be rejected, got %v", err)
	}
	if err := svc.Delete(ctx, "alice", tenant, "synapse-way-go"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("deleting a built-in must be rejected, got %v", err)
	}
	// A custom key colliding with a built-in is rejected.
	if _, err := svc.Copy(ctx, "alice", tenant, "synapse-way-go", "synapse-way-go", "x"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("reserved key must be rejected, got %v", err)
	}

	custom, err := svc.Copy(ctx, "alice", tenant, "synapse-way-go", "team-go", "Team Go")
	if err != nil || custom.BuiltIn || custom.Parent != "synapse-way-go" || len(custom.ActivatedRules) != 2 {
		t.Fatalf("copy = %+v err=%v", custom, err)
	}
	if _, err := svc.DeactivateRule(ctx, "alice", tenant, "team-go", "go-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetSeverity(ctx, "alice", tenant, "team-go", "go-a", shared.SeverityCritical); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Get(ctx, tenant, "team-go")
	if err != nil || got.Active("go-b") || got.ActivatedRules["go-a"].Severity != shared.SeverityCritical {
		t.Fatalf("persisted custom = %+v err=%v", got, err)
	}
	if err := svc.Delete(ctx, "alice", tenant, "team-go"); err != nil {
		t.Fatalf("delete custom: %v", err)
	}
	if _, err := svc.Get(ctx, tenant, "team-go"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("deleted profile must be gone, got %v", err)
	}
}

func TestServiceAssignAndOverlay(t *testing.T) {
	svc, projects, tenant := newTestService(t)
	ctx := context.Background()
	p, err := project.New("p1", tenant, "Proj", "proj", project.SourceBinding{Kind: project.SourceGit, Value: "https://example.com/r.git"}, nil, "", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := projects.Create(ctx, p); err != nil {
		t.Fatal(err)
	}

	custom, _ := svc.Copy(ctx, "alice", tenant, "synapse-way-go", "team-go", "Team Go")
	custom, _ = svc.DeactivateRule(ctx, "alice", tenant, custom.Key, "go-b")
	custom, _ = svc.SetSeverity(ctx, "alice", tenant, custom.Key, "go-a", shared.SeverityLow)

	// Assigning a Python profile to the "Go" language is rejected (language mismatch).
	if err := svc.Assign(ctx, "alice", tenant, "proj", "Go", "synapse-way-python"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("language mismatch must be rejected, got %v", err)
	}
	if err := svc.Assign(ctx, "alice", tenant, "proj", "Go", "team-go"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	saved, _ := projects.GetByKey(ctx, tenant, "proj")
	if saved.DefaultProfileByLang["Go"] != "team-go" {
		t.Fatalf("assignment not persisted: %+v", saved.DefaultProfileByLang)
	}

	overlay, err := svc.OverlayForProject(ctx, tenant, saved.DefaultProfileByLang)
	if err != nil {
		t.Fatal(err)
	}
	if cfg := overlay.Rules["go-b"]; cfg.Enabled == nil || *cfg.Enabled {
		t.Errorf("go-b must be disabled by the assigned profile: %+v", cfg)
	}
	if overlay.Rules["go-a"].Severity != string(shared.SeverityLow) {
		t.Errorf("go-a must carry the severity override: %+v", overlay.Rules["go-a"])
	}

	// Assigning the built-in default contributes no overlay (everything active, no overrides).
	if err := svc.Assign(ctx, "alice", tenant, "proj", "Go", "synapse-way-go"); err != nil {
		t.Fatal(err)
	}
	saved, _ = projects.GetByKey(ctx, tenant, "proj")
	overlay, _ = svc.OverlayForProject(ctx, tenant, saved.DefaultProfileByLang)
	if len(overlay.Rules) != 0 {
		t.Errorf("built-in assignment must yield an empty overlay, got %+v", overlay.Rules)
	}

	// Clearing the assignment removes it.
	if err := svc.Assign(ctx, "alice", tenant, "proj", "Go", ""); err != nil {
		t.Fatal(err)
	}
	saved, _ = projects.GetByKey(ctx, tenant, "proj")
	if _, ok := saved.DefaultProfileByLang["Go"]; ok {
		t.Errorf("cleared assignment must be gone: %+v", saved.DefaultProfileByLang)
	}
}

func TestAssignStrictPresetAppliesEscalatedOverlay(t *testing.T) {
	svc, projects, tenant := newTestService(t)
	ctx := context.Background()
	p, err := project.New("p1", tenant, "Proj", "proj", project.SourceBinding{Kind: project.SourceGit, Value: "https://example.com/r.git"}, nil, "", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := projects.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	// A user selects the built-in Strict preset for the Go language.
	if err := svc.Assign(ctx, "alice", tenant, "proj", "Go", "strict-go"); err != nil {
		t.Fatalf("assign strict preset: %v", err)
	}
	saved, _ := projects.GetByKey(ctx, tenant, "proj")
	if saved.DefaultProfileByLang["Go"] != "strict-go" {
		t.Fatalf("preset assignment not persisted: %+v", saved.DefaultProfileByLang)
	}
	overlay, err := svc.OverlayForProject(ctx, tenant, saved.DefaultProfileByLang)
	if err != nil {
		t.Fatal(err)
	}
	// Strict escalates: go-a high -> critical, go-b medium -> high; both stay enabled.
	if overlay.Rules["go-a"].Severity != string(shared.SeverityCritical) || overlay.Rules["go-b"].Severity != string(shared.SeverityHigh) {
		t.Fatalf("strict overlay = %+v, want go-a critical, go-b high", overlay.Rules)
	}
	if overlay.Rules["go-a"].Enabled != nil || overlay.Rules["go-b"].Enabled != nil {
		t.Fatalf("strict keeps every rule enabled, got %+v", overlay.Rules)
	}
}

func TestPresetKeysDistinctAcrossCFamily(t *testing.T) {
	cat := fakeCatalog{rules: []rule.Rule{
		{Key: "c-a", Language: "C", DefaultSeverity: shared.SeverityHigh},
		{Key: "cs-a", Language: "C#", DefaultSeverity: shared.SeverityHigh},
		{Key: "cpp-a", Language: "C++", DefaultSeverity: shared.SeverityHigh},
	}}
	projects := memory.NewProjectRepository()
	svc := NewService(memory.NewQualityProfileStore(), cat, projects, nopAudit{}, nopClock{})
	ctx := context.Background()
	tenant := shared.ID("tenant")

	all, err := svc.List(ctx, tenant, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 9 { // three presets each for C, C#, C++
		t.Fatalf("want 9 presets, got %d", len(all))
	}
	keys := map[string]bool{}
	for _, p := range all {
		if keys[p.Key] {
			t.Fatalf("duplicate preset key %q (C-family slug collision)", p.Key)
		}
		keys[p.Key] = true
	}
	// The C# strict preset resolves to C# specifically, not whichever C-family language won a map race.
	csStrict, err := svc.Get(ctx, tenant, "strict-csharp")
	if err != nil || csStrict.Language != "C#" {
		t.Fatalf("strict-csharp = %+v err=%v, want language C#", csStrict, err)
	}
	// Assigning it to the C# language succeeds (no language-mismatch rejection from a collision).
	p, err := project.New("p1", tenant, "Proj", "proj", project.SourceBinding{Kind: project.SourceGit, Value: "https://example.com/r.git"}, nil, "", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := projects.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := svc.Assign(ctx, "alice", tenant, "proj", "C#", "strict-csharp"); err != nil {
		t.Fatalf("assign strict-csharp to C# must succeed, got %v", err)
	}
}

func TestPresetKeysAreReserved(t *testing.T) {
	svc, _, tenant := newTestService(t)
	ctx := context.Background()
	for _, key := range []string{"recommended-go", "strict-go"} {
		if _, err := svc.Copy(ctx, "alice", tenant, "synapse-way-go", key, "x"); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("preset key %q must be reserved against a custom copy, got %v", key, err)
		}
	}
}
