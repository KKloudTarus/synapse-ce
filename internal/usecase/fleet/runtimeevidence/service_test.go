package runtimeevidence

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type fakeResolver struct {
	assetID shared.ID
	err     error
}

func (f fakeResolver) ResolveTelemetryAsset(context.Context, shared.ID) (shared.ID, error) {
	return f.assetID, f.err
}

type fakeEngagements struct {
	eng *engagement.Engagement
	err error
}

func (f fakeEngagements) GetByHostAssetID(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return f.eng, f.err
}

type fakeAttributor struct {
	minted    int
	err       error
	gotEngID  shared.ID
	gotLoads  int
	callCount int
}

func (f *fakeAttributor) Attribute(_ context.Context, engagementID shared.ID, _ *runtimereach.Ownership, loads []runtimereach.LoadEvent) (int, error) {
	f.callCount++
	f.gotEngID = engagementID
	f.gotLoads = len(loads)
	return f.minted, f.err
}

func sampleReport() runtimereach.Report {
	return runtimereach.Report{
		PackageFiles: []runtimereach.PackageFiles{{
			Package: runtimereach.PackageRef{Name: "libssl3", Version: "3.0.13"},
			Files:   []runtimereach.OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: runtimereach.FileID{Device: 64, Inode: 111}}},
		}},
		Loads: []runtimereach.LoadEvent{{Path: "/usr/lib/libssl.so.3", ID: runtimereach.FileID{Device: 64, Inode: 111}}},
	}
}

func TestIngestMintsForBoundHostWithEngagement(t *testing.T) {
	attr := &fakeAttributor{minted: 1}
	svc, err := NewService(fakeResolver{assetID: "asset-1"}, fakeEngagements{eng: &engagement.Engagement{ID: "eng-1"}}, attr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.Ingest(context.Background(), "tenant-1", "agent-1", sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	if res.AssetID != "asset-1" || res.EngagementID != "eng-1" || res.Minted != 1 || res.Pending {
		t.Fatalf("result = %+v", res)
	}
	if attr.gotEngID != "eng-1" || attr.gotLoads != 1 {
		t.Fatalf("attributor called wrong: engID=%s loads=%d", attr.gotEngID, attr.gotLoads)
	}
}

func TestIngestPendingWhenNoEngagementYet(t *testing.T) {
	attr := &fakeAttributor{}
	svc, _ := NewService(fakeResolver{assetID: "asset-1"}, fakeEngagements{err: shared.ErrNotFound}, attr)
	res, err := svc.Ingest(context.Background(), "tenant-1", "agent-1", sampleReport())
	if err != nil {
		t.Fatalf("a host without an engagement yet must not error: %v", err)
	}
	if !res.Pending || res.Minted != 0 || attr.callCount != 0 {
		t.Fatalf("expected pending, no attribution; got %+v callCount=%d", res, attr.callCount)
	}
}

func TestIngestErrorsWhenAgentHasNoBoundAsset(t *testing.T) {
	svc, _ := NewService(fakeResolver{assetID: ""}, fakeEngagements{eng: &engagement.Engagement{ID: "eng-1"}}, &fakeAttributor{})
	if _, err := svc.Ingest(context.Background(), "tenant-1", "agent-1", sampleReport()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unbound agent must be a validation error, got %v", err)
	}
}

func TestIngestRejectsInvalidReport(t *testing.T) {
	svc, _ := NewService(fakeResolver{assetID: "asset-1"}, fakeEngagements{eng: &engagement.Engagement{ID: "eng-1"}}, &fakeAttributor{})
	bad := sampleReport()
	bad.PackageFiles[0].Package.Name = "" // fails Validate
	if _, err := svc.Ingest(context.Background(), "tenant-1", "agent-1", bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid report must be rejected, got %v", err)
	}
}

func TestIngestEmptyReportMintsNothing(t *testing.T) {
	attr := &fakeAttributor{}
	svc, _ := NewService(fakeResolver{assetID: "asset-1"}, fakeEngagements{eng: &engagement.Engagement{ID: "eng-1"}}, attr)
	res, err := svc.Ingest(context.Background(), "tenant-1", "agent-1", runtimereach.Report{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Minted != 0 || attr.callCount != 0 || res.EngagementID != "eng-1" {
		t.Fatalf("empty report must mint nothing without calling the attributor; got %+v callCount=%d", res, attr.callCount)
	}
}

// TestIngestCarriesCoverageBack asserts a coverage-only report (sensor unavailable, unreadable package DB)
// is accepted, mints nothing, and carries its coverage back so the host's runtime-evidence gap is recorded
// rather than silently dropped.
func TestIngestCarriesCoverageBack(t *testing.T) {
	attr := &fakeAttributor{}
	svc, _ := NewService(fakeResolver{assetID: "asset-1"}, fakeEngagements{eng: &engagement.Engagement{ID: "eng-1"}}, attr)
	report := runtimereach.Report{Coverage: []runtimereach.CoverageReason{runtimereach.CoverageSensorUnavailable}}
	res, err := svc.Ingest(context.Background(), "tenant-1", "agent-1", report)
	if err != nil {
		t.Fatal(err)
	}
	if attr.callCount != 0 || res.Minted != 0 {
		t.Fatalf("a coverage-only report must mint nothing; got %+v callCount=%d", res, attr.callCount)
	}
	if len(res.Coverage) != 1 || res.Coverage[0] != runtimereach.CoverageSensorUnavailable {
		t.Fatalf("coverage must be carried back, got %+v", res.Coverage)
	}
}

// TestIngestCarriesCoverageBackWhenPending asserts the coverage gap is preserved even when the host has no
// engagement yet, so a brand-new host's sensor-unavailable report is still recorded.
func TestIngestCarriesCoverageBackWhenPending(t *testing.T) {
	svc, _ := NewService(fakeResolver{assetID: "asset-1"}, fakeEngagements{err: shared.ErrNotFound}, &fakeAttributor{})
	report := runtimereach.Report{Coverage: []runtimereach.CoverageReason{runtimereach.CoverageUnreadablePackageDB}}
	res, err := svc.Ingest(context.Background(), "tenant-1", "agent-1", report)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Pending {
		t.Fatalf("a host with no engagement must be pending, got %+v", res)
	}
	if len(res.Coverage) != 1 || res.Coverage[0] != runtimereach.CoverageUnreadablePackageDB {
		t.Fatalf("coverage must be carried back even when pending, got %+v", res.Coverage)
	}
}

func TestIngestRequiresAgentID(t *testing.T) {
	svc, _ := NewService(fakeResolver{assetID: "a"}, fakeEngagements{eng: &engagement.Engagement{ID: "e"}}, &fakeAttributor{})
	if _, err := svc.Ingest(context.Background(), "tenant-1", "", sampleReport()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing agent id must error, got %v", err)
	}
}

func TestNewServiceValidatesDeps(t *testing.T) {
	if _, err := NewService(nil, fakeEngagements{}, &fakeAttributor{}); err == nil {
		t.Fatal("nil resolver must error")
	}
}
