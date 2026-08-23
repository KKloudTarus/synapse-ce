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
	good := NetworkConnection{ConnectionID: shared.ID("nc_x"), AssetID: testAsset, State: ConnectionObserved}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid connection rejected: %v", err)
	}
	bad := NetworkConnection{ConnectionID: shared.ID("nc_x"), AssetID: testAsset, State: "bogus"}
	if bad.Validate() == nil {
		t.Fatal("unknown state must be rejected")
	}
}
