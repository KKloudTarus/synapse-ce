package projectuc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type mockIDGenFunc func() shared.ID

func (f mockIDGenFunc) NewID() shared.ID { return f() }

// testCursorKey is a stable 32-byte key used by all unit tests.
var testCursorKey = []byte("test-cursor-signing-secret-32byt")

func newTestService(projects ports.ProjectRepository, analyses ports.ProjectAnalysisStore) *Service {
	var idCounter int
	mockIDGen := func() shared.ID {
		idCounter++
		return shared.ID("id-" + string(rune(idCounter+96)))
	}
	svc := NewService(projects, memory.NewEngagementRepository(), fixedClock{}, mockIDGenFunc(mockIDGen), &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	if err := svc.SetCursorSecret(testCursorKey); err != nil {
		panic(err)
	}
	return svc
}

func TestGetMeasures(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := memory.NewProjectAnalysisStore()

	var idCounter int
	mockIDGen := func() shared.ID {
		idCounter++
		return shared.ID("id-" + string(rune(idCounter+96)))
	}
	svc := NewService(projects, memory.NewEngagementRepository(), fixedClock{}, mockIDGenFunc(mockIDGen), &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	if err := svc.SetCursorSecret(testCursorKey); err != nil {
		t.Fatal(err)
	}

	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}

	analysis := projectanalysis.Analysis{
		ID:        "a1",
		TenantID:  "tenant",
		ProjectID: string(p.ID),
		CreatedAt: time.Now(),
		Rating: rating.Report{
			Security:        "A",
			Reliability:     "B",
			Maintainability: "C",
		},
		Coverage: nil, // coverage not supplied
		Snapshot: measure.Snapshot{
			Nodes: []measure.Node{
				{Path: "", Kind: measure.NodeProject, Parent: "", IssueTypeAvailable: true, TechDebtAvailable: true, ComplexityAvailable: false, DuplicationAvailable: false},
				{Path: "src", Kind: measure.NodeDirectory, Parent: "", AttributionAvailable: true, TechDebtAvailable: true, IssueTypeAvailable: true},
				{Path: "src/a.go", Kind: measure.NodeFile, Parent: "src", AttributionAvailable: true, TechDebtAvailable: true, IssueTypeAvailable: true},
				{Path: "src/z-dir", Kind: measure.NodeDirectory, Parent: "src", AttributionAvailable: true, TechDebtAvailable: true, IssueTypeAvailable: true},
			},
		},
	}
	if err := analyses.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}

	t.Run("root all domains", func(t *testing.T) {
		res, err := svc.GetMeasures(ctx, "tenant", "project", "", nil, 50, "")
		if err != nil {
			t.Fatal(err)
		}
		if res.Node.Path != "" || len(res.Children.Items) != 1 || res.Children.Items[0].Path != "src" {
			t.Fatalf("root response=%+v", res)
		}
		if res.Node.Ratings == nil || *res.Node.Ratings.Security.Grade != "A" {
			t.Fatalf("expected ratings on root")
		}
		if len(res.IncludedDomains) != 7 {
			t.Fatalf("expected all 7 domains, got %d", len(res.IncludedDomains))
		}
	})

	t.Run("repeatable domain filtering and deduplication", func(t *testing.T) {
		res, err := svc.GetMeasures(ctx, "tenant", "project", "", []string{"size", "coverage", "size"}, 50, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.IncludedDomains) != 2 || res.IncludedDomains[0] != "size" || res.IncludedDomains[1] != "coverage" {
			t.Fatalf("domains=%v", res.IncludedDomains)
		}
	})

	t.Run("invalid domain", func(t *testing.T) {
		_, err := svc.GetMeasures(ctx, "tenant", "project", "", []string{"size", "foo"}, 50, "")
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("empty domain defaults to all", func(t *testing.T) {
		res, err := svc.GetMeasures(ctx, "tenant", "project", "", []string{}, 50, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.IncludedDomains) != 7 {
			t.Fatalf("domains=%v", res.IncludedDomains)
		}
	})

	t.Run("directory ordering pagination", func(t *testing.T) {
		res1, err := svc.GetMeasures(ctx, "tenant", "project", "src", nil, 1, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(res1.Children.Items) != 1 || res1.Children.Items[0].Path != "src/z-dir" {
			t.Fatalf("expected z-dir first, got %v", res1.Children.Items)
		}
		if res1.Children.NextCursor == nil {
			t.Fatalf("expected next cursor")
		}

		res2, err := svc.GetMeasures(ctx, "tenant", "project", "src", nil, 50, *res1.Children.NextCursor)
		if err != nil {
			t.Fatal(err)
		}
		if len(res2.Children.Items) != 1 || res2.Children.Items[0].Path != "src/a.go" {
			t.Fatalf("expected a.go second, got %v", res2.Children.Items)
		}
		if res2.Children.NextCursor != nil {
			t.Fatalf("expected no next cursor")
		}
	})

	t.Run("cursor mismatch", func(t *testing.T) {
		cursor := &MeasureCursor{Version: 1, AnalysisID: "a1", Path: "src", LastKindRank: 1, LastChildPath: "src/unknown"}
		_, err := svc.GetMeasures(ctx, "tenant", "project", "src", nil, 50, cursor.Encode(svc.cursorSecret))
		if err == nil {
			t.Fatalf("expected error for mismatch")
		}
	})

	t.Run("cross-project cursor rejection", func(t *testing.T) {
		cursor := &MeasureCursor{Version: 1, AnalysisID: "a2", Path: "src", LastKindRank: 1, LastChildPath: "src/unknown"}
		_, err := svc.GetMeasures(ctx, "tenant", "project", "src", nil, 50, cursor.Encode(svc.cursorSecret))
		if err == nil {
			t.Fatalf("expected error for cross-project cursor")
		}
	})

	t.Run("signed cursor tampering", func(t *testing.T) {
		cursor := &MeasureCursor{Version: 1, AnalysisID: "a1", Path: "src", LastKindRank: 1, LastChildPath: "src/z-dir"}
		encoded := cursor.Encode([]byte("fake-secret"))
		_, err := svc.GetMeasures(ctx, "tenant", "project", "src", nil, 50, encoded)
		if err == nil {
			t.Fatalf("expected error for tampered cursor")
		}
	})

	t.Run("canonical path rejection", func(t *testing.T) {
		_, err := svc.GetMeasures(ctx, "tenant", "project", "src/../src", nil, 50, "")
		if err == nil {
			t.Fatalf("expected error for non-canonical path")
		}
	})

	t.Run("file children always empty", func(t *testing.T) {
		res, err := svc.GetMeasures(ctx, "tenant", "project", "src/a.go", nil, 50, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Children.Items) != 0 {
			t.Fatalf("file children should be empty")
		}
	})

	t.Run("zero/unavailable complexity and duplication", func(t *testing.T) {
		res, err := svc.GetMeasures(ctx, "tenant", "project", "", []string{"complexity", "duplication"}, 50, "")
		if err != nil {
			t.Fatal(err)
		}
		if res.Node.Complexity.Cyclomatic.Availability != AvailabilityUnavailable || *res.Node.Complexity.Cyclomatic.Reason != "complexity_not_available" {
			t.Fatalf("complexity expected unavailable")
		}
		if res.Node.Duplication.DuplicatedLines.Availability != AvailabilityUnavailable || *res.Node.Duplication.DuplicatedLines.Reason != "duplication_not_available" {
			t.Fatalf("duplication expected unavailable")
		}
	})

	t.Run("no executable lines", func(t *testing.T) {
		p4, _ := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "P4", Key: "p4", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
		a4 := projectanalysis.Analysis{
			ID:        "a4",
			TenantID:  "tenant",
			ProjectID: string(p4.ID),
			CreatedAt: time.Now(),
			Coverage:  &measure.CoverageReport{},
			Snapshot: measure.Snapshot{
				Nodes: []measure.Node{
					{Path: "", Kind: measure.NodeProject, Parent: "", CoverageAvailable: true, Counters: measure.Counters{CoverableLines: 0}},
				},
			},
		}
		analyses.Save(ctx, a4)
		res, err := svc.GetMeasures(ctx, "tenant", "p4", "", []string{"coverage"}, 50, "")
		if err != nil {
			t.Fatal(err)
		}
		if *res.Node.Coverage.Coverage.Reason != "no_executable_lines" {
			t.Fatalf("expected no_executable_lines, got %v", *res.Node.Coverage.Coverage.Reason)
		}
	})

	t.Run("no commentable lines", func(t *testing.T) {
		p5, _ := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "P5", Key: "p5", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
		a5 := projectanalysis.Analysis{
			ID:        "a5",
			TenantID:  "tenant",
			ProjectID: string(p5.ID),
			CreatedAt: time.Now(),
			Snapshot: measure.Snapshot{
				Nodes: []measure.Node{
					{Path: "", Kind: measure.NodeProject, Parent: "", Counters: measure.Counters{CodeLines: 0, CommentLines: 0}},
				},
			},
		}
		analyses.Save(ctx, a5)
		res, err := svc.GetMeasures(ctx, "tenant", "p5", "", []string{"size"}, 50, "")
		if err != nil {
			t.Fatal(err)
		}
		if res.Node.Size.CommentDensity.Reason == nil || *res.Node.Size.CommentDensity.Reason != "no_commentable_lines" {
			t.Fatalf("expected no_commentable_lines, got %v", res.Node.Size.CommentDensity.Reason)
		}
	})

	t.Run("issue/debt root versus path availability", func(t *testing.T) {
		res, err := svc.GetMeasures(ctx, "tenant", "project", "src", []string{"issues", "debt"}, 50, "")
		if err != nil {
			t.Fatal(err)
		}
		// At src level, attribution is true so severity is available
		if res.Node.Issues.BySeverity["high"].Availability != AvailabilityAvailable {
			t.Fatalf("severity should be available at path level")
		}
	})

	t.Run("invalid persisted ratings", func(t *testing.T) {
		p6, _ := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "P6", Key: "p6", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
		a3 := projectanalysis.Analysis{
			ID:        "a3",
			TenantID:  "tenant",
			ProjectID: string(p6.ID),
			CreatedAt: time.Now(),
			Rating: rating.Report{
				Security: "Z",
			},
			Snapshot: measure.Snapshot{
				Nodes: []measure.Node{
					{Path: "", Kind: measure.NodeProject, Parent: ""},
				},
			},
		}
		analyses.Save(ctx, a3)
		_, err := svc.GetMeasures(ctx, "tenant", "p6", "", nil, 50, "")
		if err == nil {
			t.Fatalf("expected error for corrupt rating Z")
		}
	})

	t.Run("response internal-data leakage", func(t *testing.T) {
		res, err := svc.GetMeasures(ctx, "tenant", "project", "", nil, 50, "")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(res)
		s := string(b)
		if strings.Contains(s, "tenant") || strings.Contains(s, string(p.ID)) {
			t.Fatalf("response leaked tenant or project UUID: %s", s)
		}
	})

	t.Run("cursor pinned to original analysis", func(t *testing.T) {
		p7, _ := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "P7", Key: "p7", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})

		a1New := projectanalysis.Analysis{
			ID:        "a1-pinned",
			TenantID:  "tenant",
			ProjectID: string(p7.ID),
			CreatedAt: time.Now().Add(-1 * time.Hour),
			Snapshot: measure.Snapshot{
				Nodes: []measure.Node{
					{Path: "", Kind: measure.NodeProject, Parent: ""},
					{Path: "src", Kind: measure.NodeDirectory, Parent: ""},
					{Path: "src/unknown", Kind: measure.NodeFile, Parent: "src"},
				},
			},
		}
		analyses.Save(ctx, a1New)

		a2 := projectanalysis.Analysis{
			ID:        "a2-pinned",
			TenantID:  "tenant",
			ProjectID: string(p7.ID),
			CreatedAt: time.Now(),
			Snapshot: measure.Snapshot{
				Nodes: []measure.Node{
					{Path: "", Kind: measure.NodeProject, Parent: ""},
				},
			},
		}
		analyses.Save(ctx, a2)

		cursor := &MeasureCursor{Version: 1, AnalysisID: "a1-pinned", Path: "src", LastKindRank: 2, LastChildPath: "src/unknown"}
		res, err := svc.GetMeasures(ctx, "tenant", "p7", "src", nil, 50, cursor.Encode(svc.cursorSecret))
		if err != nil {
			t.Fatal(err)
		}
		if res.Analysis.ID != "a1-pinned" {
			t.Fatalf("expected pinned a1, got %s", res.Analysis.ID)
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := svc.GetMeasures(ctx, "tenant", "project", "missing", nil, 50, "")
		if err != shared.ErrNotFound {
			t.Fatalf("missing path err=%v, want ErrNotFound", err)
		}
	})

	t.Run("not analyzed", func(t *testing.T) {
		_, _ = svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "P2", Key: "p2", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo2"}})
		res, err := svc.GetMeasures(ctx, "tenant", "p2", "", nil, 50, "")
		if err != nil {
			t.Fatal(err)
		}
		if res.State != "not_analyzed" {
			t.Fatalf("expected not_analyzed, got %s", res.State)
		}
		if res.Analysis != nil {
			t.Fatalf("expected nil analysis")
		}
	})
}

func TestGetMeasures_Postgres(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Logf("SKIPPED: set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}

	t.Logf("RUN: PostgreSQL integration test")
	ctx := context.Background()
	if err := postgres.Migrate(ctx, dsn); err != nil {
		t.Logf("FAILED: %v", err)
		t.Fatal(err)
	}
	pool, err := postgres.Connect(ctx, dsn)
	if err != nil {
		t.Logf("FAILED: %v", err)
		t.Fatal(err)
	}
	defer pool.Close()

	tenant := "measure-pg-tenant"
	_, _ = pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant) })

	repo := postgres.NewProjectRepository(pool)
	analyses := postgres.NewProjectAnalysisStore(pool)

	proj, _ := project.New("pg-test-id", shared.ID(tenant), "Project PG", "project-pg", project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}, nil, "", time.Now())
	_ = repo.Create(ctx, proj)

	var idCounter int
	mockIDGen := func() shared.ID {
		idCounter++
		return shared.ID("id-pg-" + string(rune(idCounter+96)))
	}
	svc := NewService(repo, memory.NewEngagementRepository(), fixedClock{}, mockIDGenFunc(mockIDGen), &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	if err := svc.SetCursorSecret(testCursorKey); err != nil {
		t.Logf("FAILED: %v", err)
		t.Fatal(err)
	}

	a1 := projectanalysis.Analysis{
		ID:        "a1-pg",
		TenantID:  tenant,
		ProjectID: string(proj.ID),
		CreatedAt: time.Now(),
		Rating: rating.Report{
			Security: "A",
		},
		Snapshot: measure.Snapshot{
			Nodes: []measure.Node{
				{Path: "", Kind: measure.NodeProject, Parent: "", IssueTypeAvailable: true},
				{Path: "src", Kind: measure.NodeDirectory, Parent: "", IssueTypeAvailable: true},
			},
		},
	}
	if err := analyses.Save(ctx, a1); err != nil {
		t.Logf("FAILED: %v", err)
		t.Fatal(err)
	}

	res, err := svc.GetMeasures(ctx, tenant, "project-pg", "", nil, 50, "")
	if err != nil {
		t.Logf("FAILED: GetMeasures PG err: %v", err)
		t.Fatalf("GetMeasures PG err: %v", err)
	}
	if res.Node == nil || len(res.Children.Items) != 1 {
		t.Logf("FAILED: PG integration: %+v", res)
		t.Fatalf("PG integration failed: %+v", res)
	}
	t.Logf("RUN: PostgreSQL integration test PASSED")
}

func TestCursorSecretValidation(t *testing.T) {
	projects := memory.NewProjectRepository()
	analyses := memory.NewProjectAnalysisStore()

	makeService := func() *Service {
		var c int
		svc := NewService(projects, memory.NewEngagementRepository(), fixedClock{}, mockIDGenFunc(func() shared.ID {
			c++
			return shared.ID(string(rune(c + 96)))
		}), &captureAudit{}, true)
		svc.SetAnalysisStore(analyses)
		return svc
	}

	t.Run("empty key rejected", func(t *testing.T) {
		svc := makeService()
		if err := svc.SetCursorSecret(nil); err == nil {
			t.Fatal("expected error for nil key")
		}
	})

	t.Run("short key rejected", func(t *testing.T) {
		svc := makeService()
		if err := svc.SetCursorSecret([]byte("too-short")); err == nil {
			t.Fatal("expected error for 9-byte key")
		}
	})

	t.Run("exact 32 bytes accepted", func(t *testing.T) {
		svc := makeService()
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}
		if err := svc.SetCursorSecret(key); err != nil {
			t.Fatalf("expected 32-byte key to be accepted: %v", err)
		}
	})

	t.Run("caller mutation does not affect service", func(t *testing.T) {
		svc := makeService()
		key := []byte("test-cursor-signing-secret-32byt")
		if err := svc.SetCursorSecret(key); err != nil {
			t.Fatal(err)
		}
		// Mutate the caller's copy
		for i := range key {
			key[i] = 0
		}
		// Service key must still work
		cursor := &MeasureCursor{Version: 1, AnalysisID: "a1", Path: "src", LastKindRank: 2, LastChildPath: "src/file.go"}
		encoded := cursor.Encode(svc.cursorSecret)
		_, err := DecodeMeasureCursor(encoded, svc.cursorSecret)
		if err != nil {
			t.Fatalf("service key corrupted by caller mutation: %v", err)
		}
	})

	t.Run("token signed with different key fails", func(t *testing.T) {
		key1 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 32 bytes
		key2 := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") // 32 bytes
		cursor := &MeasureCursor{Version: 1, AnalysisID: "a1", Path: "", LastKindRank: 2, LastChildPath: "src"}
		encoded := cursor.Encode(key1)
		_, err := DecodeMeasureCursor(encoded, key2)
		if err == nil {
			t.Fatal("expected error for cross-key decode")
		}
	})

	t.Run("payload modification fails", func(t *testing.T) {
		key := []byte("cccccccccccccccccccccccccccccccc") // 32 bytes
		cursor := &MeasureCursor{Version: 1, AnalysisID: "a1", Path: "", LastKindRank: 2, LastChildPath: "src"}
		encoded := cursor.Encode(key)
		// Flip a character in the middle of the token to simulate tampering
		tampered := []byte(encoded)
		tampered[len(tampered)/2] ^= 0x01
		_, err := DecodeMeasureCursor(string(tampered), key)
		if err == nil {
			t.Fatal("expected error for tampered payload")
		}
	})

	t.Run("cursor valid across service instances with same key", func(t *testing.T) {
		ctx := context.Background()
		projects2 := memory.NewProjectRepository()
		analyses2 := memory.NewProjectAnalysisStore()
		svc1 := newTestService(projects2, analyses2)
		svc2 := newTestService(projects2, analyses2)
		// both svc1 and svc2 use testCursorKey

		p, err := svc1.Create(ctx, CreateInput{TenantID: "t", CreatedBy: "a", Name: "P", Key: "p",
			SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/r"}})
		if err != nil {
			t.Fatal(err)
		}

		analyses2.Save(ctx, projectanalysis.Analysis{
			ID: "ax", TenantID: "t", ProjectID: string(p.ID), CreatedAt: time.Now(),
			Snapshot: measure.Snapshot{Nodes: []measure.Node{
				{Path: "", Kind: measure.NodeProject, Parent: ""},
				{Path: "src", Kind: measure.NodeDirectory, Parent: ""},
				{Path: "src/b-dir", Kind: measure.NodeDirectory, Parent: "src"},
				{Path: "src/a.go", Kind: measure.NodeFile, Parent: "src"},
			}},
		})

		// svc1 generates a cursor
		res1, err := svc1.GetMeasures(ctx, "t", "p", "src", nil, 1, "")
		if err != nil || res1.Children.NextCursor == nil {
			t.Fatalf("svc1: %v %v", err, res1)
		}

		// svc2 (same key, fresh instance) can decode the cursor
		res2, err := svc2.GetMeasures(ctx, "t", "p", "src", nil, 50, *res1.Children.NextCursor)
		if err != nil {
			t.Fatalf("svc2 failed to use cursor from svc1: %v", err)
		}
		if len(res2.Children.Items) != 1 || res2.Children.Items[0].Path != "src/a.go" {
			t.Fatalf("unexpected items: %v", res2.Children.Items)
		}
	})
}

func TestGetMeasures_LimitValidation(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := memory.NewProjectAnalysisStore()
	svc := newTestService(projects, analyses)

	p, _ := svc.Create(ctx, CreateInput{TenantID: "t", CreatedBy: "a", Name: "P", Key: "p",
		SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/r"}})
	analyses.Save(ctx, projectanalysis.Analysis{
		ID: "a1", TenantID: "t", ProjectID: string(p.ID), CreatedAt: time.Now(),
		Snapshot: measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject, Parent: ""}}},
	})

	t.Run("limit 0 rejected", func(t *testing.T) {
		_, err := svc.GetMeasures(ctx, "t", "p", "", nil, 0, "")
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("limit -1 rejected", func(t *testing.T) {
		_, err := svc.GetMeasures(ctx, "t", "p", "", nil, -1, "")
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("limit 201 rejected", func(t *testing.T) {
		_, err := svc.GetMeasures(ctx, "t", "p", "", nil, 201, "")
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("limit 50 accepted", func(t *testing.T) {
		_, err := svc.GetMeasures(ctx, "t", "p", "", nil, 50, "")
		if err != nil {
			t.Fatalf("expected no error for limit 50: %v", err)
		}
	})

	t.Run("limit 200 accepted", func(t *testing.T) {
		_, err := svc.GetMeasures(ctx, "t", "p", "", nil, 200, "")
		if err != nil {
			t.Fatalf("expected no error for limit 200: %v", err)
		}
	})
}
