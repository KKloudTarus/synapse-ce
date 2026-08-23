package endpoint

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

func hasChange(d EndpointDiff, kind EntityKind, id shared.ID, ck ChangeKind) bool {
	for _, c := range d.Changes {
		if c.EntityKind == kind && c.EntityID == id && c.Change == ck {
			return true
		}
	}
	return false
}

func TestDiffDetectsAddedRemovedChangedAcrossKinds(t *testing.T) {
	before := mustState(t)
	after := mustState(t)
	pA, pB, pC := procEntityID(1, 1), procEntityID(2, 1), procEntityID(3, 1)
	proc := pA

	// before: process A (/a), B (/b); a flow; a file; a container.
	mustObserve(t, before, procEnv("e1", base, pA, "", 1, 0, "exec", "a", "/a"))
	mustObserve(t, before, procEnv("e2", base, pB, "", 2, 0, "exec", "b", "/b"))
	mustObserve(t, before, netEnv("n1", base, proc, "tcp", "egress", "10.0.0.1", 1000, "1.2.3.4", 443))
	mustObserve(t, before, fileEnv("fl1", base, proc, "open", "/x", 1, 2, ""))
	mustObserve(t, before, procEnvRC("rc1", base, procEntityID(9, 1), 9, telemetry.ResourceContext{ContainerID: "c1", ImageDigest: "img1"}))

	// after: process A image changed (/a2), C added (B removed); same flow; same file gains a write op; a
	// different container.
	mustObserve(t, after, procEnv("e3", base.Add(time.Second), pA, "", 1, 0, "exec", "a", "/a2"))
	mustObserve(t, after, procEnv("e4", base, pC, "", 3, 0, "exec", "c", "/c"))
	mustObserve(t, after, netEnv("n2", base, proc, "tcp", "egress", "10.0.0.1", 1000, "1.2.3.4", 443))
	mustObserve(t, after, fileEnv("fl2", base, proc, "write", "/x", 1, 2, ""))
	mustObserve(t, after, procEnvRC("rc2", base, procEntityID(9, 1), 9, telemetry.ResourceContext{ContainerID: "c2", ImageDigest: "img2"}))

	d := Diff(before, after)
	connID := ConnectionID(testAsset, proc, "tcp", "egress", "10.0.0.1", 1000, "1.2.3.4", 443)
	fileID := telemetry.FileTargetID("/x", 1, 2, "")
	c1 := telemetry.ContainerTargetID("c1", 0, "", "img1")
	c2 := telemetry.ContainerTargetID("c2", 0, "", "img2")

	want := []struct {
		kind EntityKind
		id   shared.ID
		ck   ChangeKind
	}{
		{EntityProcess, pA, ChangeChanged},  // image /a -> /a2
		{EntityProcess, pB, ChangeRemoved},  // gone in after
		{EntityProcess, pC, ChangeAdded},    // new in after
		{EntityFile, fileID, ChangeChanged}, // op open -> write
		{EntityContainer, c1, ChangeRemoved},
		{EntityContainer, c2, ChangeAdded},
	}
	for _, w := range want {
		if !hasChange(d, w.kind, w.id, w.ck) {
			t.Fatalf("missing change %s %s %s in %+v", w.kind, w.id, w.ck, d.Changes)
		}
	}
	// The flow is unchanged (same tuple) and must NOT appear.
	if hasChange(d, EntityNetwork, connID, ChangeChanged) {
		t.Fatal("an unchanged flow must not be reported as changed")
	}
	if len(d.Changes) != len(want) {
		t.Fatalf("unexpected extra changes: got %d want %d: %+v", len(d.Changes), len(want), d.Changes)
	}
}

func TestDiffIgnoresSeenWindowMovement(t *testing.T) {
	before := mustState(t)
	after := mustState(t)
	p := procEntityID(1, 1)
	// Same material descriptors, different event times (so StartedAt/LastSeenAt differ).
	mustObserve(t, before, procEnv("e1", base, p, "", 1, 0, "exec", "a", "/a"))
	mustObserve(t, after, procEnv("e2", base.Add(time.Hour), p, "", 1, 0, "exec", "a", "/a"))
	if d := Diff(before, after); len(d.Changes) != 0 {
		t.Fatalf("a moved seen-window is not a material change: %+v", d.Changes)
	}
}

func TestDiffReportsProcessAttributionResolution(t *testing.T) {
	before := mustState(t)
	after := mustState(t)
	proc := procEntityID(44, 1)
	flow := netEnv("n1", base, proc, "tcp", "egress", "10.0.0.1", 4000, "1.2.3.4", 443)
	mustObserve(t, before, flow)
	mustObserve(t, after, flow)
	mustObserve(t, after, procEnv("p1", base.Add(time.Second), proc, "", 44, 1, "exec", "app", "/app"))

	connID := ConnectionID(testAsset, proc, "tcp", "egress", "10.0.0.1", 4000, "1.2.3.4", 443)
	d := Diff(before, after)
	if len(d.Changes) != 2 || !hasChange(d, EntityNetwork, connID, ChangeChanged) {
		// The process itself is also added; the connection resolution must be the other material change.
		t.Fatalf("attribution resolution must be reported as a changed connection: %+v", d.Changes)
	}
}

func TestDiffOfIdenticalIsEmptyAndDeterministicallyOrdered(t *testing.T) {
	build := func() *EndpointState {
		s := mustState(t)
		mustObserve(t, s, procEnv("e1", base, procEntityID(2, 1), "", 2, 0, "exec", "b", "/b"))
		mustObserve(t, s, procEnv("e2", base, procEntityID(1, 1), "", 1, 0, "exec", "a", "/a"))
		return s
	}
	if d := Diff(build(), build()); len(d.Changes) != 0 {
		t.Fatalf("identical snapshots must diff empty, got %+v", d.Changes)
	}
	// From empty: two additions, ordered by entity id.
	d := Diff(mustState(t), build())
	if len(d.Changes) != 2 {
		t.Fatalf("two additions expected, got %+v", d.Changes)
	}
	if !(d.Changes[0].EntityID < d.Changes[1].EntityID) {
		t.Fatalf("changes must be deterministically ordered by id: %+v", d.Changes)
	}
}

func mustObserve(t *testing.T, s *EndpointState, env telemetry.TelemetryEnvelope) {
	t.Helper()
	if _, err := s.Observe(env); err != nil {
		t.Fatalf("observe %s: %v", env.EventID, err)
	}
}
