package privacyexport

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/legalhold"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeDetections struct{ recs []detection.Record }

func (f fakeDetections) ListDetections(context.Context, shared.ID) ([]detection.Record, error) {
	return f.recs, nil
}

type fakeHolds struct{ holds []legalhold.Hold }

func (f fakeHolds) ListActive(context.Context) ([]legalhold.Hold, error) { return f.holds, nil }

type fakeAudit struct{ n int }

func (f *fakeAudit) Record(context.Context, ports.AuditEntry) error { f.n++; return nil }

func TestExportBundlesDetectionsAndHolds(t *testing.T) {
	dets := fakeDetections{recs: []detection.Record{{ID: "d1", EngagementID: "eng-1"}, {ID: "d2", EngagementID: "eng-1"}}}
	holds := fakeHolds{holds: []legalhold.Hold{{EngagementID: "eng-1", Reason: "hold"}, {EngagementID: "eng-2", Reason: "other"}}}
	audit := &fakeAudit{}
	svc, err := NewService(dets, holds, audit, func() time.Time { return time.Unix(0, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.Export(context.Background(), "dpo", "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if b.Count != 2 || len(b.Detections) != 2 {
		t.Fatalf("must bundle the engagement's detections: %+v", b)
	}
	// Only eng-1's hold is included (eng-2's is filtered out).
	if len(b.LegalHolds) != 1 || b.LegalHolds[0].EngagementID != "eng-1" {
		t.Fatalf("must include only this engagement's holds: %+v", b.LegalHolds)
	}
	if audit.n != 1 {
		t.Fatalf("the export must be audited once, got %d", audit.n)
	}
}

func TestExportRequiresActorAndEngagement(t *testing.T) {
	svc, _ := NewService(fakeDetections{}, nil, &fakeAudit{}, func() time.Time { return time.Now() })
	if _, err := svc.Export(context.Background(), "", "eng-1"); err == nil {
		t.Fatal("export without an actor must be rejected")
	}
	if _, err := svc.Export(context.Background(), "dpo", ""); err == nil {
		t.Fatal("export without an engagement id must be rejected")
	}
}
