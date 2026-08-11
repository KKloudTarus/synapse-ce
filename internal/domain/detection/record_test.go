package detection

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func recDetection(t *testing.T, comm string) Detection {
	t.Helper()
	r, ok := Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("expected det.process_enumeration")
	}
	ev := Event{Class: ClassProcess, At: time.Unix(1, 0), Host: "h", Process: &ProcessEvent{PID: 1, Comm: comm, Path: "/usr/bin/" + comm}}
	d, err := NewDetection(r, "host-1", "agent:1", []Event{ev}, time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func validRecord(t *testing.T) Record {
	t.Helper()
	return Record{
		ID: "rec-1", TenantID: "t1", EngagementID: "e1", AssetID: "asset-1", AgentID: "agent:1",
		Detection: recDetection(t, "ps"), EvidenceID: "ev-1", BatchSeq: 1, RecordedAt: time.Unix(1000, 0),
	}
}

func TestRecordValidate(t *testing.T) {
	good := validRecord(t)
	if err := good.Validate(); err != nil {
		t.Fatalf("a well-formed record must validate: %v", err)
	}
	mut := map[string]func(*Record){
		"no id":         func(r *Record) { r.ID = "" },
		"no tenant":     func(r *Record) { r.TenantID = "" },
		"no engagement": func(r *Record) { r.EngagementID = "" },
		"no asset":      func(r *Record) { r.AssetID = "" },
		"no evidence":   func(r *Record) { r.EvidenceID = "" },
		"no agent":      func(r *Record) { r.AgentID = "" },
	}
	for name, m := range mut {
		t.Run(name, func(t *testing.T) {
			r := validRecord(t)
			m(&r)
			if err := r.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestRecordExpired(t *testing.T) {
	r := validRecord(t)
	if r.Expired(time.Unix(9999, 0)) {
		t.Error("a record with no ExpiresAt must never expire")
	}
	r.ExpiresAt = time.Unix(2000, 0)
	if r.Expired(time.Unix(1999, 0)) {
		t.Error("not yet at the cutoff")
	}
	if !r.Expired(time.Unix(2000, 0)) {
		t.Error("at the cutoff it is expired")
	}
}

// TestRollupPreservesUnderlyingDetections is #423 requirement 6: the incident rollup dedups repeated
// detections but never loses the individual attributable records beneath it.
func TestRollupPreservesUnderlyingDetections(t *testing.T) {
	mk := func(id, asset, comm string, sev shared.Severity, at time.Time) Record {
		d := recDetection(t, comm)
		d.Severity = sev
		d.Observed = at
		return Record{ID: shared.ID(id), TenantID: "t1", EngagementID: "e1", AssetID: shared.ID(asset),
			AgentID: "agent:1", Detection: d, EvidenceID: shared.ID("ev-" + id), BatchSeq: 1, RecordedAt: at}
	}
	// Two detections of the same rule on asset-A (fold into one incident), one on asset-B.
	recs := []Record{
		mk("r1", "asset-A", "ps", shared.SeverityLow, time.Unix(100, 0)),
		mk("r2", "asset-A", "ps", shared.SeverityHigh, time.Unix(300, 0)),
		mk("r3", "asset-B", "ps", shared.SeverityLow, time.Unix(200, 0)),
	}
	inc := Rollup(recs)
	if len(inc) != 2 {
		t.Fatalf("want 2 incidents (asset-A folded, asset-B separate), got %d", len(inc))
	}
	// Deterministic order by key (rule+asset): asset-A before asset-B.
	a := inc[0]
	if a.AssetID != "asset-A" || a.Count != 2 {
		t.Fatalf("asset-A incident wrong: %+v", a)
	}
	if len(a.DetectionIDs) != 2 || a.DetectionIDs[0] != "r1" || a.DetectionIDs[1] != "r2" {
		t.Fatalf("underlying detections must be preserved: %v", a.DetectionIDs)
	}
	if a.Severity != shared.SeverityHigh {
		t.Fatalf("incident severity must be the max of its members, got %s", a.Severity)
	}
	if !a.First.Equal(time.Unix(100, 0)) || !a.Last.Equal(time.Unix(300, 0)) {
		t.Fatalf("incident first/last wrong: %v..%v", a.First, a.Last)
	}
	if inc[1].AssetID != "asset-B" || inc[1].Count != 1 {
		t.Fatalf("asset-B incident wrong: %+v", inc[1])
	}
}
