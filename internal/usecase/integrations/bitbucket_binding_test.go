package integrations

import (
	"context"
	"errors"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"testing"
	"time"
)

func TestBitbucketBindingRequiresGitSourceAndSingleProject(t *testing.T) {
	clock := &integrationTestClock{now: time.Now().UTC()}
	ids := idgen.RandomID{}
	store := memory.NewIntegrationStore(memory.NewJobQueue(ids, clock.Now), nil, clock, &integrationTestAudit{})
	projects := memory.NewProjectRepository()
	ctx := shared.WithTenant(context.Background(), "tenant")
	item := integration.Integration{ID: "bitbucket-inbound", TenantID: "tenant", Provider: "bitbucket", Name: "Bitbucket", Endpoint: "https://bitbucket.example.com", Config: []byte(`{}`), PollInterval: time.Minute, Version: 1, CreatedAt: clock.Now(), UpdatedAt: clock.Now()}
	if err := store.CreateIntegration(ctx, item, ports.AuditEntry{Actor: "admin", Action: "integration.created", Target: item.ID.String(), At: clock.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, source := range []project.SourceBinding{{Kind: project.SourceLocal, Value: "/tmp/local"}, {Kind: project.SourceGit, Value: "https://bitbucket.example.com/trusted/app.git"}} {
		p, err := project.New(shared.ID(source.Kind), "tenant", source.Kind, source.Kind, source, nil, "", clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err = projects.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := NewService(store, integration.NewRegistry(), projects, integrationTestMatcher{}, ids, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.CreateBinding(ctx, "tenant", item.ID, "local", "/inbound/local", "Local", "admin"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("local source accepted: %v", err)
	}
	if _, err = svc.CreateBinding(ctx, "tenant", item.ID, "git", "/inbound/git", "Git", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.CreateBinding(ctx, "tenant", item.ID, "git", "/inbound/duplicate", "Duplicate", "admin"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second binding accepted: %v", err)
	}
}
