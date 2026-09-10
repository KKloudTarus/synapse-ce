package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMigration0157VisibleProjectBoundaryAndRollbackGuard(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 157); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES ('visible','Visible'),('other','Other')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	p, err := project.New("project", "visible", "Project", "project", project.SourceBinding{Kind: project.SourceGit, Value: "https://github.com/example/project"}, nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	projects := NewProjectRepository(pool)
	if err := projects.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	engagements := NewEngagementRepository(pool)
	root, err := engdom.New("assessment", "visible", "Visible assessment", "", now)
	if err != nil {
		t.Fatal(err)
	}
	root.AssessmentProjectID = p.ID
	if err := engagements.Create(ctx, root); err != nil {
		t.Fatal(err)
	}
	got, err := engagements.GetByIDInTenant(ctx, root.TenantID, root.ID)
	if err != nil || got.Internal() || got.AssessmentProjectID != p.ID {
		t.Fatalf("visible association: %+v err=%v", got, err)
	}
	cycles := NewAssessmentCycleRepository(pool)
	pending, total, err := cycles.ListMigrationPendingAssessments(ctx, ports.AssessmentCycleListQuery{TenantID: root.TenantID, Limit: 10, BoundaryKind: cycledom.BoundaryProject})
	if err != nil || total != 1 || len(pending) != 1 || pending[0].AssessmentID != root.ID || pending[0].BoundaryKind != cycledom.BoundaryProject {
		t.Fatalf("visible Project pending projection: %+v total=%d err=%v", pending, total, err)
	}
	service, err := cycleuc.NewService(cycles, engagements, nil, projects, NewTenantTransactionRunner(pool), idgen.RandomID{}, idgen.SystemClock{}, assessmentCycleNoopAudit{})
	if err != nil {
		t.Fatal(err)
	}
	cycle, _, err := service.CreateInitialCycle(ctx, cycleuc.CreateInitialCycleInput{TenantID: root.TenantID, Name: "Project cycle", BoundaryKind: cycledom.BoundaryProject, ProjectID: p.ID, RootAssessmentID: root.ID, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE engagements SET assessment_project_id=NULL WHERE id='assessment'`,
		`UPDATE engagements SET project_id='project',assessment_project_id=NULL WHERE id='assessment'`,
		`UPDATE assessment_cycles SET project_id=NULL,boundary_kind='standalone' WHERE id=$1`,
		`UPDATE assessment_cycles SET root_assessment_id='other' WHERE id=$1`,
	} {
		var err error
		if strings.Contains(statement, "$1") {
			_, err = pool.Exec(ctx, statement, cycle.ID.String())
		} else {
			_, err = pool.Exec(ctx, statement)
		}
		if err == nil {
			t.Fatalf("frozen boundary update accepted: %s", statement)
		}
	}
	wrong, err := engdom.New("wrong", "other", "Cross tenant", "", now)
	if err != nil {
		t.Fatal(err)
	}
	wrong.AssessmentProjectID = p.ID
	if err := engagements.Create(ctx, wrong); err == nil {
		t.Fatal("cross-tenant Project FK not enforced")
	}
	if err := goose.DownTo(db, ".", 156); err == nil || !strings.Contains(err.Error(), "associations exist") {
		t.Fatalf("unsafe rollback accepted: %v", err)
	}
}

func TestMigrations0157And0158EmptyRoundTrip(t *testing.T) {
	db, _ := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 158); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 156); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(db, ".", 158); err != nil {
		t.Fatal(err)
	}
}
