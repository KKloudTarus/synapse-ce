package projectuc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fixedIDs struct{}

func (fixedIDs) NewID() shared.ID { return "p1" }

type captureAudit struct{ entries []ports.AuditEntry }

func (a *captureAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

func TestServiceCRUDAndAudit(t *testing.T) {
	ctx := context.Background()
	audit := &captureAudit{}
	svc := NewService(memory.NewProjectRepository(), fixedClock{time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}, fixedIDs{}, audit)
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant-a", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Audit.CreatedBy != "alice" || len(audit.entries) != 1 || audit.entries[0].Action != "project.create" {
		t.Fatalf("create audit/owner: p=%+v audit=%+v", p, audit.entries)
	}
	if _, err := svc.Get(ctx, "tenant-b", "project"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant=%v, want not found", err)
	}
	list, err := svc.List(ctx, "tenant-a")
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	if err := svc.Delete(ctx, "alice", "tenant-a", "project"); err != nil {
		t.Fatal(err)
	}
	if len(audit.entries) != 2 || audit.entries[1].Action != "project.delete" {
		t.Fatalf("delete audit=%+v", audit.entries)
	}
}

func TestServiceRequiresActor(t *testing.T) {
	svc := NewService(memory.NewProjectRepository(), fixedClock{}, fixedIDs{}, &captureAudit{})
	if _, err := svc.Create(context.Background(), CreateInput{Name: "P", Key: "p", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("got %v, want validation", err)
	}
}
