package sca

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	snapshotdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type uploadedCycleReader struct {
	ports.AssessmentCycleRepository
}

func (uploadedCycleReader) GetCycleByAssessment(_ context.Context, tenantID, assessmentID shared.ID) (*cycledom.AssessmentCycle, error) {
	if tenantID != "tenant" || assessmentID != "retest" {
		return nil, shared.ErrNotFound
	}
	return &cycledom.AssessmentCycle{ID: "cycle", TenantID: tenantID, RootAssessmentID: "root"}, nil
}

type uploadedSnapshotReader struct {
	snapshot *snapshotdom.Snapshot
	err      error
}

func (r uploadedSnapshotReader) GetDefault(_ context.Context, tenantID, assessmentID shared.ID) (*snapshotdom.Snapshot, ports.AssessmentSnapshotDefault, error) {
	if tenantID != "tenant" || assessmentID != "root" {
		return nil, ports.AssessmentSnapshotDefault{}, shared.ErrNotFound
	}
	return r.snapshot, ports.AssessmentSnapshotDefault{}, r.err
}

func TestUploadedRetestNamespaceUsesImmutableRootSnapshotNotNewRevision(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	rootTarget := sourcepackage.TargetPrefix + strings.Repeat("a", 64)
	newTarget := sourcepackage.TargetPrefix + strings.Repeat("b", 64)
	item, err := engdom.New("retest", "tenant", "Revision", "", now)
	if err != nil {
		t.Fatal(err)
	}
	item.Scope.InScope = []engdom.Target{{Kind: engdom.TargetRepo, Value: newTarget}}
	request := ports.AcquireRequest{Kind: ports.TargetUpload, Value: newTarget}
	result := &ScanResult{Target: newTarget, ReproDigest: strings.Repeat("c", 64), Completeness: ports.Completeness{Confident: true}, Manifest: ports.ScanManifest{ToolVersions: map[string]string{"scanner": "1.0"}}}
	lane, _, err := assessmentSCALane(item, "run", now, now.Add(time.Second), request, result, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	original := lane
	baseline := &snapshotdom.Snapshot{CycleID: "cycle", Provenance: snapshotdom.ProvenanceNative, Dimensions: []snapshotdom.Dimension{{Target: snapshotdom.Target{Kind: scanrun.TargetRepository, SchemaVersion: 1, Canonical: "managed-repository://sha256/" + strings.Repeat("e", 64)}, IncludedScope: []string{"repo:" + rootTarget}}}}
	service := &Service{assessmentCycles: uploadedCycleReader{}, assessmentSnapshots: uploadedSnapshotReader{snapshot: baseline}}
	if err := service.bindUploadedAssessmentSource(context.Background(), item, request, &lane); err != nil {
		t.Fatal(err)
	}
	if lane.Target.TargetIdentityCanonical != baseline.Dimensions[0].Target.Canonical || lane.Target.EvaluatedRevision != original.Target.EvaluatedRevision || lane.Target.EvaluatedRevision != strings.Repeat("d", 64) || lane.IncludedScope[0] != "repo:"+rootTarget {
		t.Fatalf("revision/identity binding=%+v", lane)
	}
	// A repository that was not an uploaded source cannot gain this namespace.
	unrelated := original
	unrelated.IncludedScope = []string{"repo:" + newTarget}
	baseline.Dimensions[0].IncludedScope = []string{"repo:https://example.com/unrelated.git"}
	if err := service.bindUploadedAssessmentSource(context.Background(), item, request, &unrelated); err != nil || unrelated.Target.TargetIdentityCanonical != original.Target.TargetIdentityCanonical {
		t.Fatalf("unrelated target remapped: %+v err=%v", unrelated.Target, err)
	}
	service.assessmentSnapshots = uploadedSnapshotReader{err: errors.New("unavailable")}
	if err := service.bindUploadedAssessmentSource(context.Background(), item, request, &lane); err == nil {
		t.Fatal("source lookup failure ignored")
	}
}

func TestUploadedScanUsesVerifiedContentDigestForCompleteCoverage(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	item, err := engdom.New("initial", "tenant", "Native upload", "", now)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	request := ports.AcquireRequest{Kind: ports.TargetUpload, Value: sourcepackage.TargetPrefix + digest}
	result := &ScanResult{Target: request.Value, ReproDigest: strings.Repeat("b", 64), Completeness: ports.Completeness{Confident: true}, Manifest: ports.ScanManifest{ToolVersions: map[string]string{"scanner": "1"}}}
	lane, status, err := assessmentSCALane(item, "run", now, now.Add(time.Second), request, result, "")
	if err != nil || status != scanrun.StatusSucceeded || lane.Target.EvaluatedRevision != digest {
		t.Fatalf("native upload falsely partial: %+v status=%s err=%v", lane, status, err)
	}
	request.Kind = ports.TargetLocal
	_, status, err = assessmentSCALane(item, "untrusted-local", now, now.Add(time.Second), request, result, "")
	if err != nil || status != scanrun.StatusPartial {
		t.Fatalf("unverified locator trusted: status=%s err=%v", status, err)
	}
}

func TestAssessmentCoverageVersionsExcludeRiskOnlyEnrichment(t *testing.T) {
	versions := assessmentScanVersions(ports.ScanManifest{ToolVersions: map[string]string{
		"grype": "1", "epss-date": "2026-09-08", "kev-catalog": "2026.09.08",
	}, GrypeDBVersion: "db-v1"})
	if len(versions) != 4 { // Grype, detection DB, correlation, manifest schema.
		t.Fatalf("unexpected coverage versions: %+v", versions)
	}
	for _, version := range versions {
		if version.Name == "epss-date" || version.Name == "kev-catalog" || version.Name == "vulnerability-feed" {
			t.Fatalf("risk-only/unused feed changes coverage: %+v", version)
		}
	}
}
