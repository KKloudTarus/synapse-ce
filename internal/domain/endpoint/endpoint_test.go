package endpoint

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

const (
	testTenant = shared.ID("tenant-b")
	testAsset  = shared.ID("asset-b")
	testBoot   = shared.ID("boot-b")
)

var base = time.Unix(1_800_000_000, 0).UTC()

// procEntityID mirrors A1's derivation so tests build lineage with the real ids.
func procEntityID(pid int, startNanos uint64) shared.ID {
	return telemetry.ProcessEntityID(testAsset, testBoot, pid, startNanos)
}

const testAgent = shared.ID("agent-b")

func procEnv(eventID string, occ time.Time, entityID, parentID shared.ID, pid, ppid int, kind, comm, path string, args ...string) telemetry.TelemetryEnvelope {
	return telemetry.TelemetryEnvelope{
		SchemaVersion: telemetry.SchemaVersion,
		EventID:       shared.ID(eventID),
		EventType:     "process." + kind,
		EventClass:    detection.ClassProcess,
		AgentID:       testAgent,
		AssetID:       testAsset,
		BootID:        testBoot,
		OccurredAt:    occ,
		ObservedAt:    occ,
		Event: telemetry.TelemetryEvent{
			Class: detection.ClassProcess,
			Process: &telemetry.ProcessObservation{
				Kind: kind, PID: pid, PPID: ppid,
				EntityID: entityID, ParentEntityID: parentID,
				Comm: comm, Path: path, Args: args, UID: 0,
			},
		},
	}
}

func netEnv(eventID string, occ time.Time, procEntity shared.ID, proto, dir, laddr string, lport int, raddr string, rport int) telemetry.TelemetryEnvelope {
	return telemetry.TelemetryEnvelope{
		SchemaVersion: telemetry.SchemaVersion,
		EventID:       shared.ID(eventID),
		EventType:     "network.connect",
		EventClass:    detection.ClassNetwork,
		AgentID:       testAgent,
		AssetID:       testAsset,
		BootID:        testBoot,
		OccurredAt:    occ,
		ObservedAt:    occ,
		Event: telemetry.TelemetryEvent{
			Class: detection.ClassNetwork,
			Network: &telemetry.NetworkObservation{
				Kind: "connect", Proto: proto, Direction: dir,
				LocalAddr: laddr, LocalPort: lport, RemoteAddr: raddr, RemotePort: rport,
				ProcessEntityID: procEntity, Comm: "app",
			},
		},
	}
}

func mustState(t *testing.T) *EndpointState {
	t.Helper()
	s, err := NewEndpointState(testTenant, testAsset)
	if err != nil {
		t.Fatalf("new endpoint state: %v", err)
	}
	return s
}

func TestNewEndpointStateValidatesIDs(t *testing.T) {
	if _, err := NewEndpointState("", testAsset); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant: got %v", err)
	}
	if _, err := NewEndpointState(testTenant, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing asset: got %v", err)
	}
}

func TestObserveRejectsWrongAssetAndMissingEventID(t *testing.T) {
	s := mustState(t)
	e := procEnv("e1", base, procEntityID(10, 1), "", 10, 1, "exec", "app", "/usr/bin/app")
	e.AssetID = shared.ID("other-asset")
	if _, err := s.Observe(e); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("wrong-asset envelope must be rejected, got %v", err)
	}
	e2 := procEnv("", base, procEntityID(10, 1), "", 10, 1, "exec", "app", "/usr/bin/app")
	if _, err := s.Observe(e2); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing event id must be rejected, got %v", err)
	}
}

func TestObserveIsIdempotentByEventID(t *testing.T) {
	s := mustState(t)
	e := procEnv("e1", base, procEntityID(10, 5), "", 10, 1, "exec", "app", "/usr/bin/app")
	entries, err := s.Observe(e)
	if err != nil || len(entries) != 1 {
		t.Fatalf("first observe: entries=%d err=%v", len(entries), err)
	}
	entries2, err := s.Observe(e)
	if err != nil || len(entries2) != 0 {
		t.Fatalf("re-observe must be a no-op: entries=%d err=%v", len(entries2), err)
	}
	if got := len(s.Timeline()); got != 1 {
		t.Fatalf("timeline must hold exactly one entry after a duplicate, got %d", got)
	}
	if got := len(s.Processes()); got != 1 {
		t.Fatalf("processes must hold exactly one entity, got %d", got)
	}
}

// --- B1 process ---

func TestForkThenExecTransitionsOneEntity(t *testing.T) {
	s := mustState(t)
	id := procEntityID(100, 7)
	if _, err := s.Observe(procEnv("e1", base, id, "", 100, 1, "fork", "sh", "")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observe(procEnv("e2", base.Add(time.Millisecond), id, "", 100, 1, "exec", "curl", "/usr/bin/curl", "curl", "http://x")); err != nil {
		t.Fatal(err)
	}
	procs := s.Processes()
	if len(procs) != 1 {
		t.Fatalf("fork then exec of one pid must be one entity, got %d", len(procs))
	}
	pe := procs[0]
	if pe.Path != "/usr/bin/curl" || pe.Comm != "curl" || !pe.IsRunning() {
		t.Fatalf("exec must replace the image: %+v", pe)
	}
	tl := s.Timeline()
	if len(tl) != 2 || tl[0].Kind != TimelineProcessStart || tl[1].Kind != TimelineProcessExec {
		t.Fatalf("timeline must be [start, exec], got %+v", tl)
	}
}

func TestPIDReuseYieldsDistinctEntities(t *testing.T) {
	s := mustState(t)
	first := procEntityID(200, 10)
	second := procEntityID(200, 99) // same pid, different start time
	if first == second {
		t.Fatal("distinct start times must yield distinct entity ids")
	}
	if _, err := s.Observe(procEnv("e1", base, first, "", 200, 1, "exec", "a", "/a")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observe(procEnv("e2", base.Add(time.Second), second, "", 200, 1, "exec", "b", "/b")); err != nil {
		t.Fatal(err)
	}
	if got := len(s.Processes()); got != 2 {
		t.Fatalf("PID reuse must yield two distinct entities, got %d", got)
	}
}

func TestAncestorsWalksLineageAndStubsUnknownParent(t *testing.T) {
	s := mustState(t)
	gpID := procEntityID(1, 1)
	parentID := procEntityID(50, 2)
	childID := procEntityID(500, 3)
	// grandparent, then parent (child of grandparent), then child (child of parent).
	if _, err := s.Observe(procEnv("e1", base, gpID, "", 1, 0, "exec", "init", "/sbin/init")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observe(procEnv("e2", base.Add(time.Second), parentID, gpID, 50, 1, "exec", "sshd", "/usr/sbin/sshd")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observe(procEnv("e3", base.Add(2*time.Second), childID, parentID, 500, 50, "exec", "bash", "/bin/bash")); err != nil {
		t.Fatal(err)
	}
	anc := s.Ancestors(childID)
	if len(anc) != 2 || anc[0].EntityID != parentID || anc[1].EntityID != gpID {
		t.Fatalf("ancestors must be [parent, grandparent], got %+v", anc)
	}

	// A child whose parent was never observed gets an explicit unknown stub, not a broken chain.
	orphanParent := procEntityID(77, 4)
	orphan := procEntityID(777, 5)
	if _, err := s.Observe(procEnv("e4", base.Add(3*time.Second), orphan, orphanParent, 777, 77, "exec", "x", "/x")); err != nil {
		t.Fatal(err)
	}
	stub, ok := s.Process(orphanParent)
	if !ok || stub.State != ProcessUnknown {
		t.Fatalf("unobserved parent must be a ProcessUnknown stub, got ok=%v %+v", ok, stub)
	}
	if anc := s.Ancestors(orphan); len(anc) != 1 || anc[0].State != ProcessUnknown {
		t.Fatalf("ancestors of orphan must be the unknown stub, got %+v", anc)
	}
}

func TestUnknownParentStubPromotedWhenObserved(t *testing.T) {
	s := mustState(t)
	parentID := procEntityID(60, 2)
	childID := procEntityID(600, 3)
	// Child arrives first, referencing an as-yet-unseen parent -> stub.
	if _, err := s.Observe(procEnv("e1", base.Add(time.Second), childID, parentID, 600, 60, "exec", "bash", "/bin/bash")); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Process(parentID); p.State != ProcessUnknown {
		t.Fatalf("parent must start as unknown stub, got %q", p.State)
	}
	// Parent's own observation arrives later -> promoted to running with a real start.
	if _, err := s.Observe(procEnv("e2", base.Add(2*time.Second), parentID, "", 60, 1, "exec", "sshd", "/usr/sbin/sshd")); err != nil {
		t.Fatal(err)
	}
	p, _ := s.Process(parentID)
	if p.State != ProcessRunning || p.Path != "/usr/sbin/sshd" || !p.StartedAt.Equal(base.Add(2*time.Second)) {
		t.Fatalf("stub must be promoted to running with real detail, got %+v", p)
	}
}

func TestApplyRejectsMissingOrInvalidPayload(t *testing.T) {
	s := mustState(t)
	// Class says process, but no process payload.
	nilProc := telemetry.TelemetryEnvelope{
		EventID: "p1", EventClass: detection.ClassProcess, AssetID: testAsset, OccurredAt: base,
		Event: telemetry.TelemetryEvent{Class: detection.ClassProcess},
	}
	if _, err := s.Observe(nilProc); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("process class without payload must be rejected, got %v", err)
	}
	// Invalid process observation (unknown kind).
	badProc := procEnv("p2", base, procEntityID(1, 1), "", 1, 0, "bogus", "x", "/x")
	if _, err := s.Observe(badProc); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid process observation must be rejected, got %v", err)
	}
	// Class says network, but no network payload.
	nilNet := telemetry.TelemetryEnvelope{
		EventID: "n1", EventClass: detection.ClassNetwork, AssetID: testAsset, OccurredAt: base,
		Event: telemetry.TelemetryEvent{Class: detection.ClassNetwork},
	}
	if _, err := s.Observe(nilNet); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("network class without payload must be rejected, got %v", err)
	}
	// A rejected envelope must leave no state and must not be marked processed.
	if len(s.Processes()) != 0 || len(s.Connections()) != 0 || s.timeline.Len() != 0 {
		t.Fatal("a rejected envelope must not mutate state")
	}
}

func TestProcessEntityValidate(t *testing.T) {
	exitedAt := base
	cases := map[string]struct {
		p  ProcessEntity
		ok bool
	}{
		"ok running":     {ProcessEntity{EntityID: "pe_a", AssetID: testAsset, State: ProcessRunning}, true},
		"no entity id":   {ProcessEntity{AssetID: testAsset, State: ProcessRunning}, false},
		"no asset id":    {ProcessEntity{EntityID: "pe_a", State: ProcessRunning}, false},
		"bad state":      {ProcessEntity{EntityID: "pe_a", AssetID: testAsset, State: "zombie"}, false},
		"exit w/o state": {ProcessEntity{EntityID: "pe_a", AssetID: testAsset, State: ProcessRunning, ExitedAt: &exitedAt}, false},
	}
	for name, tc := range cases {
		err := tc.p.Validate()
		if tc.ok && err != nil {
			t.Fatalf("%s: unexpected error %v", name, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
}

func TestAncestorsBoundsCycles(t *testing.T) {
	s := mustState(t)
	a := procEntityID(11, 1)
	b := procEntityID(22, 2)
	// A's parent is B; B's parent is A — a malformed cycle. The walk must terminate.
	if _, err := s.Observe(procEnv("e1", base, a, b, 11, 22, "exec", "a", "/a")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observe(procEnv("e2", base.Add(time.Second), b, a, 22, 11, "exec", "b", "/b")); err != nil {
		t.Fatal(err)
	}
	anc := s.Ancestors(a) // must not loop forever
	if len(anc) == 0 || len(anc) > maxAncestorWalk {
		t.Fatalf("cycle walk must be bounded and non-empty, got %d", len(anc))
	}
	if s.Ancestors(shared.ID("pe_missing")) != nil {
		t.Fatal("ancestors of an unknown entity must be nil")
	}
}

func TestFoldIsReorderInvariant(t *testing.T) {
	pid := procEntityID(400, 1)
	// Distinct event times so the only variable is FOLD order, not event time.
	envs := []telemetry.TelemetryEnvelope{
		procEnv("e1", base, pid, "", 400, 1, "fork", "sh", ""),
		procEnv("e2", base.Add(2*time.Second), pid, "", 400, 1, "exec", "curl", "/usr/bin/curl", "curl", "http://x"),
		netEnv("n1", base.Add(3*time.Second), pid, "tcp", "egress", "10.0.0.1", 5555, "1.2.3.4", 443),
		netEnv("n2", base.Add(1*time.Second), pid, "tcp", "egress", "10.0.0.1", 5555, "1.2.3.4", 443), // earlier repeat of the same flow
	}
	fold := func(order []int) *EndpointState {
		s := mustState(t)
		for _, i := range order {
			if _, err := s.Observe(envs[i]); err != nil {
				t.Fatalf("observe %d: %v", i, err)
			}
		}
		return s
	}
	fwd := fold([]int{0, 1, 2, 3})
	rev := fold([]int{3, 2, 1, 0})

	if !reflect.DeepEqual(fwd.Processes(), rev.Processes()) {
		t.Fatalf("processes differ by fold order:\nfwd=%+v\nrev=%+v", fwd.Processes(), rev.Processes())
	}
	if !reflect.DeepEqual(fwd.Connections(), rev.Connections()) {
		t.Fatalf("connections differ by fold order:\nfwd=%+v\nrev=%+v", fwd.Connections(), rev.Connections())
	}
	// The timeline is byte-identical (no insertion-order field remains); EventID is the tiebreak.
	if !reflect.DeepEqual(fwd.Timeline(), rev.Timeline()) {
		t.Fatalf("timeline differs by fold order:\nfwd=%+v\nrev=%+v", fwd.Timeline(), rev.Timeline())
	}

	// Sanity: descriptor is the exec image (latest event-time), started-at is the earliest event, and the
	// connection window spans the two connects — none of which depend on fold order.
	pe, _ := fwd.Process(pid)
	if pe.Path != "/usr/bin/curl" || pe.Comm != "curl" || !pe.StartedAt.Equal(base) || !pe.LastSeenAt.Equal(base.Add(2*time.Second)) {
		t.Fatalf("descriptor/started not event-time resolved: %+v", pe)
	}
	c := fwd.Connections()[0]
	if !c.FirstSeenAt.Equal(base.Add(time.Second)) || !c.LastSeenAt.Equal(base.Add(3*time.Second)) {
		t.Fatalf("connection window not min/max: [%s,%s]", c.FirstSeenAt, c.LastSeenAt)
	}
	if c.ProcessAttribution != ProcessAttributionObserved {
		t.Fatalf("process attribution must resolve regardless of fold order, got %q", c.ProcessAttribution)
	}
}
