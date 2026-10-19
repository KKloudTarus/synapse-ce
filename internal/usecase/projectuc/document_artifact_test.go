package projectuc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type documentProjectRepo struct {
	ports.ProjectRepository
	project *project.Project
}

func (s documentProjectRepo) GetByKey(_ context.Context, tenant shared.ID, key string) (*project.Project, error) {
	if s.project == nil || s.project.TenantID != tenant || s.project.Key != key {
		return nil, shared.ErrNotFound
	}
	return s.project, nil
}

func (s documentProjectRepo) GetByID(_ context.Context, tenant, id shared.ID) (*project.Project, error) {
	if s.project == nil || s.project.TenantID != tenant || s.project.ID != id {
		return nil, shared.ErrNotFound
	}
	return s.project, nil
}

func TestReadProjectQualitySummaryUsesSelectedStoredAnalysis(t *testing.T) {
	tenant, projectID := shared.ID("tenant-a"), shared.ID("project-a")
	created := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	manifest := projectanalysis.SourceManifest{}
	manifest.SetArtifactDigest()
	analysis := projectanalysis.Analysis{
		ID: "analysis-a", TenantID: tenant.String(), ProjectID: projectID.String(), ProjectKey: "payments-api", CreatedAt: created,
		SourceRef: "main", SourceCommit: "abc123",
		Rating:  rating.Report{Security: rating.GradeA, Reliability: rating.GradeB, Maintainability: rating.GradeA},
		NewCode: projectanalysis.NewCode{Counts: projectanalysis.Counts{Total: 2}, Rating: projectanalysis.NewCodeRating{Security: rating.GradeA, Reliability: rating.GradeB}},
		Gate:    qualitygate.Result{Passed: true}, SourceManifest: manifest,
	}
	repo := documentProjectRepo{project: &project.Project{ID: projectID, TenantID: tenant, Key: "payments-api", Name: "Payments API"}}
	svc := NewService(repo, nil, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(&overviewAnalysisStoreSpy{latest: map[shared.ID]projectanalysis.Analysis{projectID: analysis}})

	first, err := svc.ReadProjectQualitySummary(context.Background(), tenant, projectID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	second, err := svc.ReadProjectQualitySummary(context.Background(), tenant, projectID)
	if err != nil {
		t.Fatalf("repeat read: %v", err)
	}
	if !first.IntegrityVerified || first.EvidenceHead != "" || !strings.Contains(first.SourceRevision, "analysis:analysis-a:") || first.GeneratedAt != created {
		t.Fatalf("summary=%+v", first)
	}
	if len(first.Paragraphs) < 10 || strings.Contains(strings.Join(first.Paragraphs, "\n"), "model") {
		t.Fatalf("summary paragraphs=%v", first.Paragraphs)
	}
	if strings.Join(first.Paragraphs, "\n") != strings.Join(second.Paragraphs, "\n") || first.SourceRevision != second.SourceRevision {
		t.Fatalf("stored analysis projection must be deterministic\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestReadProjectQualitySummaryRejectsMissingManifestDigest(t *testing.T) {
	tenant, projectID := shared.ID("tenant-a"), shared.ID("project-a")
	analysis := projectanalysis.Analysis{
		ID: "analysis-a", TenantID: tenant.String(), ProjectID: projectID.String(), ProjectKey: "payments-api", CreatedAt: time.Unix(1, 0),
		Rating:  rating.Report{Security: rating.GradeA, Reliability: rating.GradeA, Maintainability: rating.GradeA},
		NewCode: projectanalysis.NewCode{Rating: projectanalysis.NewCodeRating{Security: rating.GradeA, Reliability: rating.GradeA}},
		Gate:    qualitygate.Result{Passed: true},
	}
	repo := documentProjectRepo{project: &project.Project{ID: projectID, TenantID: tenant, Key: "payments-api", Name: "Payments API"}}
	svc := NewService(repo, nil, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(&overviewAnalysisStoreSpy{latest: map[shared.ID]projectanalysis.Analysis{projectID: analysis}})
	_, err := svc.ReadProjectQualitySummary(context.Background(), tenant, projectID)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing source manifest digest must block summary, got %v", err)
	}
}

func TestReadProjectQualitySummaryRejectsTamperedManifest(t *testing.T) {
	tenant, projectID := shared.ID("tenant-a"), shared.ID("project-a")
	analysis := projectanalysis.Analysis{
		ID: "analysis-a", TenantID: tenant.String(), ProjectID: projectID.String(), ProjectKey: "payments-api", CreatedAt: time.Unix(1, 0),
		Rating:         rating.Report{Security: rating.GradeA, Reliability: rating.GradeA, Maintainability: rating.GradeA},
		NewCode:        projectanalysis.NewCode{Rating: projectanalysis.NewCodeRating{Security: rating.GradeA, Reliability: rating.GradeA}},
		Gate:           qualitygate.Result{Passed: true},
		SourceManifest: projectanalysis.SourceManifest{Digest: "sha256:tampered"},
	}
	repo := documentProjectRepo{project: &project.Project{ID: projectID, TenantID: tenant, Key: "payments-api", Name: "Payments API"}}
	svc := NewService(repo, nil, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(&overviewAnalysisStoreSpy{latest: map[shared.ID]projectanalysis.Analysis{projectID: analysis}})
	_, err := svc.ReadProjectQualitySummary(context.Background(), tenant, projectID)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tampered source manifest must block summary, got %v", err)
	}
}
