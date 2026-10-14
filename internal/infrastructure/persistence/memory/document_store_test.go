package memory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/testutil/docpublishconformance"
)

func docFixture() docpublishconformance.Fixture {
	return docpublishconformance.Fixture{
		Tenant: "doc-a", Other: "doc-b", Integration: "doc-integration-a",
		Engagement: "doc-engagement-a", Project: "doc-project-a",
		OtherEngagement: "doc-engagement-b", OtherProject: "doc-project-b",
	}
}

func seedDocumentParents(t *testing.T, engagements *EngagementRepository, projects *ProjectRepository, f docpublishconformance.Fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, row := range []struct {
		tenant, engagement, project shared.ID
		key                         string
	}{
		{f.Tenant, f.Engagement, f.Project, "doc-project-a"},
		{f.Other, f.OtherEngagement, f.OtherProject, "doc-project-b"},
	} {
		e, err := engagement.New(row.engagement, row.tenant, "Documents", "Synapse", now)
		if err != nil {
			t.Fatal(err)
		}
		if err = engagements.Create(shared.WithTenant(ctx, row.tenant), e); err != nil {
			t.Fatal(err)
		}
		p, err := project.New(row.project, row.tenant, "Documents", row.key,
			project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}, nil, "", now)
		if err != nil {
			t.Fatal(err)
		}
		if err = projects.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
}

func newDocumentStoreForTest(t *testing.T) (*DocumentStore, docpublishconformance.Fixture) {
	t.Helper()
	f := docFixture()
	engagements, projects := NewEngagementRepository(), NewProjectRepository()
	seedDocumentParents(t, engagements, projects, f)
	store, err := NewDocumentStore(engagements, projects)
	if err != nil {
		t.Fatal(err)
	}
	return store, f
}

func TestDocumentStoreConformance(t *testing.T) {
	store, f := newDocumentStoreForTest(t)
	docpublishconformance.Run(t, store, f)
	docpublishconformance.ConcurrentReplay(t, store, f)
	docpublishconformance.ConcurrentClaim(t, store, f)
	docpublishconformance.ConcurrentCompletionConflict(t, store, f)
	docpublishconformance.ConcurrentUpdateCompletion(t, store, f)
	docpublishconformance.CanceledContext(t, store, f)
}

func TestNewDocumentStoreRequiresParents(t *testing.T) {
	for name, parents := range map[string]struct {
		engagements *EngagementRepository
		projects    *ProjectRepository
	}{
		"engagements": {projects: NewProjectRepository()},
		"projects":    {engagements: NewEngagementRepository()},
	} {
		t.Run(name, func(t *testing.T) {
			if store, err := NewDocumentStore(parents.engagements, parents.projects); store != nil || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("store=%v err=%v", store, err)
			}
		})
	}
}

func TestDocumentStoreRequiresATenantOnEveryOperation(t *testing.T) {
	store, f := newDocumentStoreForTest(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	target := docpublish.Target{IntegrationID: f.Integration, SourceKind: docpublish.EngagementReport,
		SourceRef: "engagement-report", Scope: docpublish.Engagement, ScopeID: f.Engagement, Container: "SEC"}
	intent := docpublish.Intent{ID: "doc-no-tenant", Target: target, Action: docpublish.Create,
		RequestKey: "k", PayloadDigest: strings.Repeat("a", 64), ContentHash: strings.Repeat("b", 64),
		Marker: docpublish.MarkerFor("doc-no-tenant"), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	for name, run := range map[string]func() error{
		"get link":  func() error { _, err := store.GetLink(ctx, "", "l"); return err },
		"find link": func() error { _, err := store.FindLink(ctx, "", target); return err },
		"list links": func() error {
			_, err := store.ListLinks(ctx, "", docpublish.Engagement, f.Engagement, 10)
			return err
		},
		"create intent": func() error { _, _, err := store.CreateOrGetIntent(ctx, "", intent); return err },
		"get intent":    func() error { _, err := store.GetIntent(ctx, "", "i"); return err },
		"transition": func() error {
			_, err := store.TransitionIntent(ctx, "", "i", 1, docpublish.IntentTransition{Event: writeintent.Claim}, now)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("missing tenant: %v", err)
			}
		})
	}
}
