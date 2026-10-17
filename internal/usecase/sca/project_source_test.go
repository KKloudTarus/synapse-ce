package sca

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type projectSourceEngRepo struct{ *fakeEngRepo }

func (r *projectSourceEngRepo) GetByProjectID(_ context.Context, tenantID, projectID shared.ID) (*engdom.Engagement, error) {
	if r.eng == nil || r.eng.TenantID != tenantID || r.eng.ProjectID != projectID {
		return nil, shared.ErrNotFound
	}
	return r.eng, nil
}

func TestQueuedProjectSourceScanPersistsServerSelectionAndPurpose(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "a")
	projects := memory.NewProjectRepository()
	p, err := project.New("project", "tenant", "Project", "project", project.SourceBinding{Kind: project.SourceLocal, Value: root}, nil, "", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := projects.Create(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	eng := engagementWithScope(t, child)
	eng.TenantID, eng.ProjectID = "tenant", p.ID
	queue := &deferredScanQueue{}
	jobs := memory.NewScanJobStore()
	svc := newAsyncSvc(&projectSourceEngRepo{fakeEngRepo: &fakeEngRepo{eng: eng}}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{}, jobs, &sequenceIDs{})
	svc.SetQueue(queue)
	svc.SetProjectSourceProjects(projects)
	ctx := shared.WithTenant(context.Background(), "tenant")
	req := ports.AcquireRequest{Kind: ports.TargetLocal, Value: child, ProjectSource: &ports.ProjectSourceSelection{ProjectID: p.ID, Root: root, Subdirectory: "a"}}
	job, err := svc.StartQueuedScanWithOptions(ctx, "operator", eng.ID, req, ScanOptions{Mode: ScanModeVulnerabilities})
	if err != nil {
		t.Fatalf("enqueue project source scan: %v", err)
	}
	if job.Purpose != ports.ScanPurposeProjectSource {
		t.Fatalf("job purpose = %q", job.Purpose)
	}
	if len(queue.payloads) != 1 {
		t.Fatalf("queue payloads = %d", len(queue.payloads))
	}
	var payload scaJobPayload
	if err := json.Unmarshal(queue.payloads[0], &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Req.ProjectSource == nil || payload.Req.ProjectSource.Root != root || payload.Req.Value != child || payload.Job.Purpose != ports.ScanPurposeProjectSource {
		t.Fatalf("queued source descriptor = %+v, job=%+v", payload.Req.ProjectSource, payload.Job)
	}
}

func TestQueuedProjectSourceScanRechecksHiddenContextBeforeAcquire(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "a")
	projects := memory.NewProjectRepository()
	p, err := project.New("project", "tenant", "Project", "project", project.SourceBinding{Kind: project.SourceLocal, Value: root}, nil, "", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := projects.Create(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	eng := engagementWithScope(t, child)
	eng.TenantID, eng.ProjectID = "tenant", p.ID
	queue, acquirer := &deferredScanQueue{}, &fakeAcquirer{dir: t.TempDir()}
	svc := newAsyncSvc(&projectSourceEngRepo{fakeEngRepo: &fakeEngRepo{eng: eng}}, fakeClock{t: time.Unix(0, 0).UTC()}, acquirer, &fakeAudit{}, &fakeDetector{}, memory.NewScanJobStore(), &sequenceIDs{})
	svc.SetQueue(queue)
	svc.SetProjectSourceProjects(projects)
	ctx := shared.WithTenant(context.Background(), "tenant")
	req := ports.AcquireRequest{Kind: ports.TargetLocal, Value: child, ProjectSource: &ports.ProjectSourceSelection{ProjectID: p.ID, Root: root, Subdirectory: "a"}}
	if _, err := svc.StartQueuedScanWithOptions(ctx, "operator", eng.ID, req, ScanOptions{Mode: ScanModeVulnerabilities}); err != nil {
		t.Fatal(err)
	}
	eng.ProjectID = "different"
	if err := svc.RunScanJob(ctx, queue.payloads[0]); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("changed hidden context execution = %v, want not found", err)
	}
	if acquirer.called {
		t.Fatal("changed project context reached acquisition")
	}
}
