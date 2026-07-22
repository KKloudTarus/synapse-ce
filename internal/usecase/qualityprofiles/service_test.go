package qualityprofiles

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
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
	if len(all) != 2 { // one built-in per language (Go, Python)
		t.Fatalf("want 2 built-ins, got %d: %+v", len(all), all)
	}
	goOnly, err := svc.List(ctx, tenant, "Go")
	if err != nil || len(goOnly) != 1 || goOnly[0].Key != "synapse-way-go" || !goOnly[0].BuiltIn {
		t.Fatalf("Go filter = %+v err=%v", goOnly, err)
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
