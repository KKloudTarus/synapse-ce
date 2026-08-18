package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func drDetection(t *testing.T) detection.Detection {
	t.Helper()
	r, ok := detection.Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("expected det.process_enumeration")
	}
	ev := detection.Event{Class: detection.ClassProcess, At: time.Unix(1, 0), Host: "h",
		Process: &detection.ProcessEvent{PID: 1, Comm: "ps", Path: "/usr/bin/ps"}}
	d, err := detection.NewDetection(r, "host-1", "agent:1", []detection.Event{ev}, time.Unix(500, 0))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func drRecord(t *testing.T, id, tenant, eng, agent string, seq uint64, exp time.Time) detection.Record {
	return detection.Record{ID: shared.ID(id), TenantID: shared.ID(tenant), EngagementID: shared.ID(eng),
		AssetID: "asset-1", AgentID: shared.ID(agent), Detection: drDetection(t), EvidenceID: shared.ID("ev-" + id),
		BatchSeq: seq, RecordedAt: time.Unix(1000, 0), ExpiresAt: exp}
}

func ctxT(tenant string) context.Context {
	return shared.WithTenant(context.Background(), shared.ID(tenant))
}

func TestDetectionStoreTenantIsolation(t *testing.T) {
	s := NewDetectionRecordStore()
	if err := s.AppendDetection(ctxT("t1"), drRecord(t, "r1", "t1", "e1", "agent:1", 1, time.Time{})); err != nil {
		t.Fatal(err)
	}
	// Same-tenant read sees it.
	if got, _ := s.ListDetections(ctxT("t1"), "e1"); len(got) != 1 {
		t.Fatalf("tenant t1 must see its own record, got %d", len(got))
	}
	// Cross-tenant read sees NOTHING.
	if got, _ := s.ListDetections(ctxT("t2"), "e1"); len(got) != 0 {
		t.Fatalf("tenant t2 must not see tenant t1's records, got %d", len(got))
	}
}

func TestDetectionStoreEngagementScopedKey(t *testing.T) {
	s := NewDetectionRecordStore()
	// The SAME detection id under two engagements of one tenant: two distinct rows, not an overwrite
	// (matches the Postgres (tenant_id, engagement_id, id) key). drRecord binds EvidenceID to "ev-"+id, so
	// both would collide on id alone.
	a := drRecord(t, "dupe", "t1", "e1", "agent:1", 1, time.Time{})
	a.EvidenceID = "ev-a"
	b := drRecord(t, "dupe", "t1", "e2", "agent:1", 1, time.Time{})
	b.EvidenceID = "ev-b"
	if err := s.AppendDetection(ctxT("t1"), a); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendDetection(ctxT("t1"), b); err != nil {
		t.Fatal(err)
	}
	// A re-delivery in e1 is idempotent (first-writer-wins, like ON CONFLICT DO NOTHING): the immutable
	// row is kept, a swapped-evidence replay does NOT overwrite it.
	replay := a
	replay.EvidenceID = "ev-tampered"
	if err := s.AppendDetection(ctxT("t1"), replay); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListDetections(ctxT("t1"), "e1"); len(got) != 1 || got[0].EvidenceID != "ev-a" {
		t.Fatalf("e1 must keep its own immutable row bound to ev-a, got %+v", got)
	}
	if got, _ := s.ListDetections(ctxT("t1"), "e2"); len(got) != 1 || got[0].EvidenceID != "ev-b" {
		t.Fatalf("e2 must retain its distinct row bound to ev-b, got %+v", got)
	}
}

func TestDetectionStoreLastBatchSequence(t *testing.T) {
	s := NewDetectionRecordStore()
	_ = s.AppendDetection(ctxT("t1"), drRecord(t, "r1", "t1", "e1", "agent:1", 2, time.Time{}))
	_ = s.AppendDetection(ctxT("t1"), drRecord(t, "r2", "t1", "e1", "agent:1", 5, time.Time{}))
	_ = s.AppendDetection(ctxT("t1"), drRecord(t, "r3", "t1", "e1", "agent:2", 9, time.Time{}))
	if seq, _ := s.LastBatchSequence(ctxT("t1"), "agent:1"); seq != 5 {
		t.Fatalf("want max seq 5 for agent:1, got %d", seq)
	}
	// A different tenant sees no sequence for that agent.
	if seq, _ := s.LastBatchSequence(ctxT("t2"), "agent:1"); seq != 0 {
		t.Fatalf("cross-tenant sequence must be 0, got %d", seq)
	}
}

func TestDetectionStoreExpire(t *testing.T) {
	s := NewDetectionRecordStore()
	s.SetClock(func() time.Time { return time.Unix(3000, 0) })                                             // deterministic expiry-on-read
	_ = s.AppendDetection(ctxT("t1"), drRecord(t, "keep", "t1", "e1", "agent:1", 1, time.Time{}))          // no expiry
	_ = s.AppendDetection(ctxT("t1"), drRecord(t, "future", "t1", "e1", "agent:1", 2, time.Unix(5000, 0))) // not yet
	_ = s.AppendDetection(ctxT("t1"), drRecord(t, "old", "t1", "e1", "agent:1", 3, time.Unix(2000, 0)))    // expired

	// ListDetections hides the already-expired "old" row even before ExpireDetections runs (mirrors the
	// Postgres `expires_at > now()` predicate).
	if got, _ := s.ListDetections(ctxT("t1"), "e1"); len(got) != 2 {
		t.Fatalf("list must hide the expired row, got %d", len(got))
	}
	expired, err := s.ExpireDetections(ctxT("t1"), "e1", time.Unix(3000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0] != "old" {
		t.Fatalf("only the past-retention record must expire, got %v", expired)
	}
	got, _ := s.ListDetections(ctxT("t1"), "e1")
	if len(got) != 2 {
		t.Fatalf("the no-expiry and future records must remain, got %d", len(got))
	}
}

func TestDetectionStoreHasDetection(t *testing.T) {
	s := NewDetectionRecordStore()
	_ = s.AppendDetection(ctxT("t1"), drRecord(t, "r1", "t1", "e1", "agent:1", 1, time.Time{}))
	if ok, _ := s.HasDetection(ctxT("t1"), "e1", "r1"); !ok {
		t.Error("t1 must see its own record via HasDetection")
	}
	if ok, _ := s.HasDetection(ctxT("t1"), "e1", "missing"); ok {
		t.Error("HasDetection must be false for an unknown id")
	}
	// Engagement-scoped: the same id in a DIFFERENT engagement is a distinct detection, not a match —
	// so a tenant-wide skip cannot silently drop it (the D3 cross-engagement loss vector).
	if ok, _ := s.HasDetection(ctxT("t1"), "e2", "r1"); ok {
		t.Error("HasDetection must be engagement-scoped")
	}
	// Cross-tenant: t2 must not observe t1's record.
	if ok, _ := s.HasDetection(ctxT("t2"), "e1", "r1"); ok {
		t.Error("HasDetection must be tenant-scoped")
	}
}
