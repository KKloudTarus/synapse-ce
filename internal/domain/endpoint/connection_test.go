package endpoint

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestConnectionIDIsStableAndProcessAttributed(t *testing.T) {
	s := mustState(t)
	proc := procEntityID(300, 1)
	if _, err := s.Observe(netEnv("n1", base, proc, "tcp", "egress", "10.0.0.1", 4444, "1.2.3.4", 443)); err != nil {
		t.Fatal(err)
	}
	conns := s.Connections()
	if len(conns) != 1 {
		t.Fatalf("one flow expected, got %d", len(conns))
	}
	c := conns[0]
	if c.ProcessEntityID != proc {
		t.Fatalf("connection must be attributed to its process entity, got %s", c.ProcessEntityID)
	}
	if c.ProcessAttribution != ProcessAttributionUnknown {
		t.Fatalf("unobserved process attribution must be explicit, got %q", c.ProcessAttribution)
	}
	want := ConnectionID(testAsset, proc, "tcp", "egress", "10.0.0.1", 4444, "1.2.3.4", 443)
	if c.ConnectionID != want {
		t.Fatalf("connection id unstable: got %s want %s", c.ConnectionID, want)
	}
	if c.ConnectionID.IsZero() {
		t.Fatal("connection id must be non-zero")
	}
}

func TestReObservingFlowDedupesEntityButLogsEachEvent(t *testing.T) {
	s := mustState(t)
	proc := procEntityID(301, 1)
	if _, err := s.Observe(netEnv("n1", base, proc, "tcp", "egress", "10.0.0.1", 5555, "1.2.3.4", 443)); err != nil {
		t.Fatal(err)
	}
	// Same 5-tuple + process, later time, DIFFERENT event id (a repeat connect).
	entries, err := s.Observe(netEnv("n2", base.Add(30*time.Second), proc, "tcp", "egress", "10.0.0.1", 5555, "1.2.3.4", 443))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("each distinct connect event is a timeline transition, got %d", len(entries))
	}
	conns := s.Connections()
	if len(conns) != 1 {
		t.Fatalf("the connection ENTITY must dedupe the flow, got %d", len(conns))
	}
	if !conns[0].LastSeenAt.Equal(base.Add(30*time.Second)) || !conns[0].FirstSeenAt.Equal(base) {
		t.Fatalf("entity window must span [first,last], got [%s,%s]", conns[0].FirstSeenAt, conns[0].LastSeenAt)
	}
	if got := len(s.Timeline()); got != 2 {
		t.Fatalf("timeline must log each connect event, got %d", got)
	}
	// Re-applying the SAME event id is idempotent (no third entry).
	again, err := s.Observe(netEnv("n2", base.Add(30*time.Second), proc, "tcp", "egress", "10.0.0.1", 5555, "1.2.3.4", 443))
	if err != nil || len(again) != 0 || len(s.Timeline()) != 2 {
		t.Fatalf("same-event re-apply must be idempotent: entries=%d timeline=%d err=%v", len(again), len(s.Timeline()), err)
	}
}

func TestDistinctFlowsAreDistinctConnections(t *testing.T) {
	s := mustState(t)
	proc := procEntityID(302, 1)
	cases := []struct {
		id                       string
		proto, dir, laddr, raddr string
		lport, rport             int
	}{
		{"a", "tcp", "egress", "10.0.0.1", "1.2.3.4", 1000, 443},
		{"b", "udp", "egress", "10.0.0.1", "1.2.3.4", 1000, 443},  // different proto
		{"c", "tcp", "ingress", "10.0.0.1", "1.2.3.4", 1000, 443}, // different direction
		{"d", "tcp", "egress", "10.0.0.1", "9.9.9.9", 1000, 443},  // different remote
	}
	for _, tc := range cases {
		if _, err := s.Observe(netEnv(tc.id, base, proc, tc.proto, tc.dir, tc.laddr, tc.lport, tc.raddr, tc.rport)); err != nil {
			t.Fatalf("%s: %v", tc.id, err)
		}
	}
	if got := len(s.Connections()); got != len(cases) {
		t.Fatalf("each distinct flow must be its own connection: got %d want %d", got, len(cases))
	}
}

func TestNetworkConnectionValidate(t *testing.T) {
	good := NetworkConnection{
		ConnectionID: shared.ID("nc_x"), AssetID: testAsset, State: ConnectionObserved,
		ProcessAttribution: ProcessAttributionUnknown,
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid connection rejected: %v", err)
	}
	cases := map[string]NetworkConnection{
		"unknown state":       {ConnectionID: "nc_x", AssetID: testAsset, State: "bogus", ProcessAttribution: ProcessAttributionUnknown},
		"missing attribution": {ConnectionID: "nc_x", AssetID: testAsset, State: ConnectionObserved},
		"observed without id": {ConnectionID: "nc_x", AssetID: testAsset, State: ConnectionObserved, ProcessAttribution: ProcessAttributionObserved},
	}
	for name, bad := range cases {
		if bad.Validate() == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

func TestNetworkAttributionReconcilesAfterProcessObservation(t *testing.T) {
	s := mustState(t)
	proc := procEntityID(303, 1)
	mustObserve(t, s, netEnv("n1", base.Add(time.Second), proc, "tcp", "egress", "10.0.0.1", 6000, "1.2.3.4", 443))
	if got := s.Connections()[0].ProcessAttribution; got != ProcessAttributionUnknown {
		t.Fatalf("flow arriving before its process must be unknown, got %q", got)
	}

	mustObserve(t, s, procEnv("p1", base, proc, "", 303, 1, "exec", "app", "/usr/bin/app"))
	if got := s.Connections()[0].ProcessAttribution; got != ProcessAttributionObserved {
		t.Fatalf("direct process observation must reconcile attribution, got %q", got)
	}
}

func TestNetworkAttributionRequiresDirectProcessObservation(t *testing.T) {
	s := mustState(t)
	parent := procEntityID(304, 1)
	child := procEntityID(305, 2)

	// Observing the child creates an explicit ProcessUnknown parent stub. A stub proves only that the
	// lineage referenced the id; it must not upgrade a network attribution.
	mustObserve(t, s, procEnv("p-child", base, child, parent, 305, 304, "exec", "child", "/child"))
	mustObserve(t, s, netEnv("n-parent", base.Add(time.Second), parent, "tcp", "egress", "10.0.0.1", 6001, "1.2.3.4", 443))
	if got := s.Connections()[0].ProcessAttribution; got != ProcessAttributionUnknown {
		t.Fatalf("parent stub must not count as observed attribution, got %q", got)
	}

	mustObserve(t, s, procEnv("p-parent", base.Add(2*time.Second), parent, "", 304, 1, "exec", "parent", "/parent"))
	if got := s.Connections()[0].ProcessAttribution; got != ProcessAttributionObserved {
		t.Fatalf("directly observing the parent must resolve attribution, got %q", got)
	}
}

func TestNetworkAttributionWithoutProcessIDStaysUnknown(t *testing.T) {
	s := mustState(t)
	mustObserve(t, s, netEnv("n1", base, "", "udp", "egress", "", 0, "8.8.8.8", 53))
	mustObserve(t, s, procEnv("p1", base.Add(time.Second), procEntityID(306, 1), "", 306, 1, "exec", "dns", "/usr/bin/dns"))

	c := s.Connections()[0]
	if !c.ProcessEntityID.IsZero() || c.ProcessAttribution != ProcessAttributionUnknown {
		t.Fatalf("flow without a join identity must stay unknown, got %+v", c)
	}
}
