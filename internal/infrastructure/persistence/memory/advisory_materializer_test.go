package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityintel"
)

func TestAdvisoryRevisionSyncRunProvenanceIsTenantScoped(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctxA := shared.WithTenant(context.Background(), "tenant-a")
	record := observationRecord("osv", "CVE-1", "CVE-2026-5140", "summary")
	record.SyncRunID = "run-a"
	if _, err := store.Materialize(ctxA, []advisory.ObservationRecord{record}); err != nil {
		t.Fatal(err)
	}
	revisions, err := store.ListVulnerabilityAdvisoryRevisions(ctxA, vulnerabilityintel.AdvisoryRevisionQuery{AdvisoryID: "CVE-2026-5140", Limit: 10})
	if err != nil || len(revisions.Items) != 1 || len(revisions.Items[0].SyncRunIDs) != 1 || revisions.Items[0].SyncRunIDs[0] != "run-a" {
		t.Fatalf("revisions=%+v err=%v", revisions, err)
	}
	links, err := store.ListVulnerabilitySyncRunRevisions(ctxA, []shared.ID{"run-a"}, 10)
	if err != nil || len(links["run-a"].Items) != 1 || links["run-a"].Items[0].AdvisoryID != "CVE-2026-5140" {
		t.Fatalf("links=%+v err=%v", links, err)
	}
	links, err = store.ListVulnerabilitySyncRunRevisions(shared.WithTenant(context.Background(), "tenant-b"), []shared.ID{"run-a"}, 10)
	if err != nil || len(links["run-a"].Items) != 0 {
		t.Fatalf("cross-tenant links=%+v err=%v", links, err)
	}
}

func TestAdvisoryMaterializerRejectsSyncRunWithoutTenant(t *testing.T) {
	store := NewAdvisoryMaterializer()
	record := observationRecord("osv", "CVE-1", "CVE-2026-5141", "summary")
	record.SyncRunID = "run-a"
	if _, err := store.Materialize(context.Background(), []advisory.ObservationRecord{record}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant error=%v", err)
	}
	if _, err := store.GetCanonical(context.Background(), "CVE-2026-5141"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rejected materialization wrote canonical: %v", err)
	}
}

func observationRecord(source, record, id, summary string) advisory.ObservationRecord {
	return advisory.ObservationRecord{Observation: advisory.Observation{
		SourceType: source,
		SourceID:   source,
		RecordID:   record,
		Status:     advisory.StatusActive,
		Advisory:   advisory.Advisory{ID: id, Summary: summary},
	}}
}

func TestAdvisoryMaterializerIsIdempotentAndKeepsHistory(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := context.Background()
	record := observationRecord("osv", "CVE-1", "CVE-2026-0001", "old")
	first, err := store.Materialize(ctx, []advisory.ObservationRecord{record})
	if err != nil || !first.CreatedRevision || first.Revision != 1 {
		t.Fatalf("first materialization=%+v err=%v", first, err)
	}
	replay, err := store.Materialize(ctx, []advisory.ObservationRecord{record})
	if err != nil || replay.CreatedRevision || replay.Revision != 1 {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	changed := observationRecord("osv", "CVE-1", "CVE-2026-0001", "new")
	second, err := store.Materialize(ctx, []advisory.ObservationRecord{changed})
	if err != nil || !second.CreatedRevision || second.Revision != 2 || len(second.ChangedFields) != 1 || second.ChangedFields[0] != advisory.ChangedSummary {
		t.Fatalf("changed materialization=%+v err=%v", second, err)
	}
	back, err := store.Materialize(ctx, []advisory.ObservationRecord{record})
	if err != nil || !back.CreatedRevision || back.Revision != 3 {
		t.Fatalf("reverted materialization=%+v err=%v", back, err)
	}
}

func TestAdvisoryMaterializerRejectsAliasConflictWithoutPartialWrite(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := context.Background()
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{
		observationRecord("nvd", "one", "CVE-2026-0001", "one"),
	}); err != nil {
		t.Fatal(err)
	}
	conflict := observationRecord("vendor", "two", "VENDOR-2", "two")
	conflict.Observation.Advisory.ID = "CVE-2026-0002"
	conflict.Observation.Advisory.Aliases = []string{"GHSA-SHARED"}
	first := observationRecord("vendor", "one-alias", "CVE-2026-0001", "one alias")
	first.Observation.Advisory.Aliases = []string{"GHSA-SHARED"}
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{first}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{conflict}); !errors.Is(err, advisory.ErrAliasConflict) {
		t.Fatalf("conflict error=%v", err)
	}
	if _, err := store.GetCanonical(ctx, "VENDOR-2"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("failed transaction exposed conflicting canonical: %v", err)
	}
	if _, err := store.GetCanonical(ctx, "CVE-2026-0001"); err != nil {
		t.Fatalf("existing canonical lost after conflict: %v", err)
	}
}
