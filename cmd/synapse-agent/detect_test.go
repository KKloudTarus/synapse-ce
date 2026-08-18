package main

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

func TestParseDetectClasses(t *testing.T) {
	got, err := parseDetectClasses(" process , file ,network")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 || got[0] != detection.ClassProcess || got[1] != detection.ClassFile || got[2] != detection.ClassNetwork {
		t.Fatalf("wrong parse: %v", got)
	}
	// Empty → off, no error.
	if g, err := parseDetectClasses("  "); err != nil || len(g) != 0 {
		t.Fatalf("empty must be off with no error, got %v %v", g, err)
	}
	// Unknown class → error (the engine stays off rather than silently ignore a typo).
	if _, err := parseDetectClasses("process,telepathy"); err == nil {
		t.Fatal("an unknown class must be a configuration error")
	}
}

func TestParseCeiling(t *testing.T) {
	cases := map[string]float64{"": 0, "3": 3, "12.5": 12.5, "-1": 0, "abc": 0}
	for in, want := range cases {
		if got := parseCeiling(in); got != want {
			t.Errorf("parseCeiling(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFormatCoverageShowsGapsWithReason(t *testing.T) {
	cov := []detection.ClassCoverage{
		{Class: detection.ClassProcess, State: detection.StateActive},
		{Class: detection.ClassFile, State: detection.StateFailed, Reason: "load failed"},
	}
	s := formatCoverage(cov)
	if !strings.Contains(s, "process=active") {
		t.Errorf("active class missing: %q", s)
	}
	if !strings.Contains(s, "file=failed(load failed)") {
		t.Errorf("gap must show its reason: %q", s)
	}
}

// TestDetectionIdentityUsesCanonicalAgentID proves the D1 fix (#606): the detection engine's identity
// is the server-issued canonical AgentID from the enrolled credential, NOT the mutable display name.
func TestDetectionIdentityUsesCanonicalAgentID(t *testing.T) {
	cred := fleetclient.Credential{AgentID: "agt_01HCANONICAL", Token: "secret"}
	host, agent, ok := detectionIdentity(cred)
	if !ok {
		t.Fatalf("expected ok for a credential with an agent id")
	}
	if agent != shared.ID("agt_01HCANONICAL") {
		t.Errorf("agent identity = %q, want the canonical AgentID", agent)
	}
	if host != shared.ID("agt_01HCANONICAL") {
		t.Errorf("host identity = %q, want the canonical AgentID", host)
	}
	// The identity must not be derived from the old display-name form.
	if strings.HasPrefix(string(agent), "agent:") {
		t.Errorf("agent identity %q still uses the display-name form", agent)
	}
}

// TestDetectionIdentityFailsClosedWithoutAgentID proves detection does not start under an empty or
// whitespace-only identity — no fallback to a display name.
func TestDetectionIdentityFailsClosedWithoutAgentID(t *testing.T) {
	for _, id := range []string{"", "   ", "\t"} {
		if _, _, ok := detectionIdentity(fleetclient.Credential{AgentID: id}); ok {
			t.Errorf("expected fail-closed (ok=false) for AgentID %q", id)
		}
	}
}
