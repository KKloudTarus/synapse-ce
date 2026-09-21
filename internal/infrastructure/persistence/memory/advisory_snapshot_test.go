package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAdvisoryMaterializerSourceSnapshotRollsBackEveryRecordOnInvalidIdentity(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := context.Background()
	previous := observationRecord("oval", "CVE-2026-0001", "CVE-2026-0001", "old summary")
	previous.Observation.SourceID = "oval-source"
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{previous}); err != nil {
		t.Fatal(err)
	}
	conflicting := observationRecord("other-source", "other-record", "CVE-2026-9999", "other summary")
	conflicting.Observation.Advisory.Aliases = []string{"CVE-2026-ALIAS"}
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{conflicting}); err != nil {
		t.Fatal(err)
	}

	changed := observationRecord("oval", "CVE-2026-0001", "CVE-2026-0001", "new summary")
	changed.Observation.SourceID = "oval-source"
	invalid := observationRecord("oval", "CVE-2026-0002", "CVE-2026-0002", "invalid summary")
	invalid.Observation.SourceID = "oval-source"
	invalid.Observation.Advisory.Aliases = []string{"CVE-2026-ALIAS"}
	if _, err := store.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{changed, invalid}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("snapshot error=%v", err)
	}

	current, err := store.GetCanonical(ctx, "CVE-2026-0001")
	if err != nil || current.Advisory.Summary != "old summary" {
		t.Fatalf("current=%+v err=%v", current, err)
	}
	if revision, err := store.CurrentRevision(ctx, "CVE-2026-0001"); err != nil || revision != 1 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
	if _, err := store.GetCanonical(ctx, "CVE-2026-0002"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("invalid record became current: %v", err)
	}
}

func TestAdvisoryMaterializerPublishedSourceSnapshotPreservesRecoveryReceipt(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	record := observationRecord("oval", "CVE-2026-0001", "CVE-2026-0001", "initial")
	record.Observation.SourceID = "oval-source"
	record.SyncRunID = "run-a"
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{record}); err != nil {
		t.Fatal(err)
	}
	changed := record
	changed.Observation.Advisory.Summary = "changed"
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{changed}); err != nil {
		t.Fatal(err)
	}
	snapshot := changed
	snapshot.Observation.Advisory.Summary = "snapshot"
	results, err := store.PublishSourceSnapshot(ctx, ports.SourceSnapshotPublication{
		SyncRunID: "run-a", NextCheckpoint: []byte(`{"complete":true,"documents":1}`),
	}, []advisory.ObservationRecord{snapshot})
	if err != nil || len(results) != 1 || !results[0].CreatedRevision || results[0].Revision != 3 {
		t.Fatalf("publish results=%+v err=%v", results, err)
	}
	published, found, err := store.PublishedSourceSnapshot(ctx, "run-a")
	if err != nil || !found || published.SourceID != "oval-source" || published.AdapterType != "oval" || string(published.NextCheckpoint) != `{"complete":true,"documents":1}` || len(published.Results) != 1 || !published.Results[0].CreatedRevision || published.Results[0].Revision != 3 || published.Results[0].Canonical.Advisory.Summary != "snapshot" {
		t.Fatalf("published=%+v found=%t err=%v", published, found, err)
	}
	if _, err := store.PublishSourceSnapshot(ctx, ports.SourceSnapshotPublication{SyncRunID: "run-a", NextCheckpoint: []byte(`{"complete":true,"documents":1}`)}, []advisory.ObservationRecord{snapshot}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate publication error=%v", err)
	}
}

func TestAdvisoryMaterializerPublishedSourceSnapshotRetainsUnchangedResult(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	record := observationRecord("oval", "CVE-2026-0001", "CVE-2026-0001", "summary")
	record.Observation.SourceID = "oval-source"
	record.SyncRunID = "prior-run"
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{record}); err != nil {
		t.Fatal(err)
	}
	record.SyncRunID = "snapshot-run"
	results, err := store.PublishSourceSnapshot(ctx, ports.SourceSnapshotPublication{
		SyncRunID: "snapshot-run", NextCheckpoint: []byte(`{"complete":true}`),
	}, []advisory.ObservationRecord{record})
	if err != nil || len(results) != 1 || results[0].CreatedRevision || results[0].Revision != 1 {
		t.Fatalf("publish results=%+v err=%v", results, err)
	}
	published, found, err := store.PublishedSourceSnapshot(ctx, "snapshot-run")
	if err != nil || !found || len(published.Results) != 1 || published.Results[0].CreatedRevision || published.Results[0].Revision != 1 {
		t.Fatalf("published=%+v found=%t err=%v", published, found, err)
	}
}

func TestAdvisoryMaterializerSourceSnapshotCancellationLeavesCurrentStateUntouched(t *testing.T) {
	store := NewAdvisoryMaterializer()
	previous := observationRecord("oval", "CVE-2026-0001", "CVE-2026-0001", "old summary")
	previous.Observation.SourceID = "oval-source"
	if _, err := store.Materialize(context.Background(), []advisory.ObservationRecord{previous}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	changed := observationRecord("oval", "CVE-2026-0001", "CVE-2026-0001", "new summary")
	changed.Observation.SourceID = "oval-source"
	if _, err := store.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{changed}); !errors.Is(err, context.Canceled) {
		t.Fatalf("snapshot cancellation error=%v", err)
	}
	current, err := store.GetCanonical(context.Background(), "CVE-2026-0001")
	if err != nil || current.Advisory.Summary != "old summary" {
		t.Fatalf("current=%+v err=%v", current, err)
	}
}

func TestAdvisoryMaterializerSourceSnapshotRejectsAliasedOVALHistory(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := context.Background()
	previous := observationRecord("oval", "CVE-2026-0001", "CVE-2026-0001", "old summary")
	previous.Observation.SourceID = "oval-source"
	previous.Observation.Advisory.Aliases = []string{"GHSA-0000-0000-0000"}
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{previous}); err != nil {
		t.Fatal(err)
	}
	empty := observationRecord("oval", "CVE-2026-0001", "CVE-2026-0001", "")
	empty.Observation.SourceID = "oval-source"
	if _, err := store.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{empty}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("aliased OVAL history error=%v", err)
	}
	current, err := store.GetCanonical(ctx, "CVE-2026-0001")
	if err != nil || len(current.Advisory.Aliases) != 1 || current.Advisory.Aliases[0] != "GHSA-0000-0000-0000" {
		t.Fatalf("current=%+v err=%v", current, err)
	}
}

func TestAdvisoryMaterializerSourceSnapshotRejectsMismatchedSourceHistory(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := context.Background()
	previous := observationRecord("csaf", "CVE-2026-0001", "CVE-2026-0001", "old summary")
	previous.Observation.SourceID = "oval-source"
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{previous}); err != nil {
		t.Fatal(err)
	}
	replacement := observationRecord("oval", "CVE-2026-0001", "CVE-2026-0001", "")
	replacement.Observation.SourceID = "oval-source"
	if _, err := store.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{replacement}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("mismatched source history error=%v", err)
	}
	current, err := store.GetCanonical(ctx, "CVE-2026-0001")
	if err != nil || current.Advisory.Summary != "old summary" {
		t.Fatalf("current=%+v err=%v", current, err)
	}
}

func TestAdvisoryMaterializerSourceSnapshotAcceptsCSAFAndRetiresMissingRecord(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := context.Background()
	present := observationRecord("csaf", "CVE-2026-0001", "CVE-2026-0001", "affected")
	present.Observation.SourceID = "csaf-source"
	removed := observationRecord("csaf", "CVE-2026-0002", "CVE-2026-0002", "affected")
	removed.Observation.SourceID = "csaf-source"
	if _, err := store.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{present, removed}); err != nil {
		t.Fatalf("seed CSAF snapshot: %v", err)
	}

	replacement := present
	replacement.Observation.Advisory.Summary = "fixed"
	absence := removed
	absence.Observation.Advisory.Summary = ""
	absence.Observation.Advisory.Affected = nil
	absence.Observation.AbsenceRetirement = true
	if _, err := store.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{replacement, absence}); err != nil {
		t.Fatalf("replace CSAF snapshot: %v", err)
	}
	current, err := store.GetCanonical(ctx, "CVE-2026-0002")
	if err != nil || len(current.Advisory.Affected) != 0 || current.Status != advisory.StatusActive {
		t.Fatalf("retired CSAF canonical=%+v err=%v", current, err)
	}
	var active []string
	if err := store.CurrentSourceRecordIDsBounded(ctx, "csaf-source", 3, func(recordID string) error {
		active = append(active, recordID)
		return nil
	}); err != nil || len(active) != 1 || active[0] != "CVE-2026-0001" {
		t.Fatalf("active CSAF records=%v err=%v", active, err)
	}
}

func TestAdvisoryMaterializerSourceSnapshotRejectsAliasedCSAFHistory(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := context.Background()
	previous := observationRecord("csaf", "CVE-2026-0001", "CVE-2026-0001", "old summary")
	previous.Observation.SourceID = "csaf-source"
	previous.Observation.Advisory.Aliases = []string{"RHSA-2026:0001"}
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{previous}); err != nil {
		t.Fatal(err)
	}
	replacement := observationRecord("csaf", "CVE-2026-0001", "CVE-2026-0001", "new summary")
	replacement.Observation.SourceID = "csaf-source"
	if _, err := store.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{replacement}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("aliased CSAF history error=%v", err)
	}
	current, err := store.GetCanonical(ctx, "CVE-2026-0001")
	if err != nil || current.Advisory.Summary != "old summary" || len(current.Advisory.Aliases) != 1 {
		t.Fatalf("current=%+v err=%v", current, err)
	}
}

func TestAdvisoryMaterializerSourceSnapshotRejectsUnsupportedAdapter(t *testing.T) {
	store := NewAdvisoryMaterializer()
	record := observationRecord("osv", "CVE-2026-0001", "CVE-2026-0001", "summary")
	record.Observation.SourceID = "osv-source"
	if _, err := store.MaterializeSourceSnapshot(context.Background(), []advisory.ObservationRecord{record}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsupported authoritative adapter error=%v", err)
	}
}

func TestAdvisoryMaterializerBoundedSourceMembershipUsesActiveIndex(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := context.Background()
	present := observationRecord("oval", "CVE-2026-0001", "CVE-2026-0001", "present")
	present.Observation.SourceID = "oval-source"
	retired := observationRecord("oval", "CVE-2026-0002", "CVE-2026-0002", "")
	retired.Observation.SourceID = "oval-source"
	retired.Observation.AbsenceRetirement = true
	if _, err := store.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{present, retired}); err != nil {
		t.Fatal(err)
	}

	if got := len(store.sourceIndex["oval-source"]); got != 2 {
		t.Fatalf("all current source records=%d, want 2", got)
	}
	if got := len(store.activeSourceIndex["oval-source"]); got != 1 {
		t.Fatalf("active source records=%d, want 1", got)
	}
	var recordIDs []string
	if err := store.CurrentSourceRecordIDsBounded(ctx, "oval-source", advisory.MaxSourceSnapshotRecords+1, func(recordID string) error {
		recordIDs = append(recordIDs, recordID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(recordIDs) != 1 || recordIDs[0] != "CVE-2026-0001" {
		t.Fatalf("active source records=%v", recordIDs)
	}
}

func TestAdvisoryMaterializerSourceSnapshotRejectsMalformedAbsence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*advisory.ObservationRecord)
	}{
		{name: "inactive", mutate: func(record *advisory.ObservationRecord) { record.Observation.Status = advisory.StatusRejected }},
		{name: "affected", mutate: func(record *advisory.ObservationRecord) {
			record.Observation.Advisory.Affected = []advisory.AffectedPackage{{Ecosystem: "Go", Package: "example.com/package"}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewAdvisoryMaterializer()
			absence := observationRecord("oval", "CVE-2026-0001", "CVE-2026-0001", "")
			absence.Observation.SourceID = "oval-source"
			absence.Observation.AbsenceRetirement = true
			test.mutate(&absence)
			if _, err := store.MaterializeSourceSnapshot(context.Background(), []advisory.ObservationRecord{absence}); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("snapshot error=%v", err)
			}
		})
	}
}
