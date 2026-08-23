package endpoint

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// TestTimelineEntriesForMatchesObserve is the drift guard: the stateless persistence projection must emit
// exactly the timeline entries the live fold does, for every class — they share timelineEntryFor, and this
// proves they never diverge.
func TestTimelineEntriesForMatchesObserve(t *testing.T) {
	proc := procEntityID(10, 1)
	cases := map[string]telemetry.TelemetryEnvelope{
		"process":   procEnv("e1", base, proc, "", 10, 1, "exec", "app", "/usr/bin/app", "app", "-x"),
		"network":   netEnv("e2", base, proc, "tcp", "egress", "10.0.0.1", 1000, "1.2.3.4", 443),
		"file":      fileEnv("e3", base, proc, "write", "/etc/x", 1, 2, ""),
		"privilege": privEnv("e4", base, proc, "setuid", 1000, 0, ""),
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			s := mustState(t)
			observed, err := s.Observe(env)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			projected, err := TimelineEntriesFor(testTenant, env)
			if err != nil {
				t.Fatalf("project: %v", err)
			}
			if len(observed) != 1 || len(projected) != 1 {
				t.Fatalf("want one entry each, got observed=%d projected=%d", len(observed), len(projected))
			}
			if observed[0] != projected[0] {
				t.Fatalf("projection drifted from fold:\n fold=%+v\n proj=%+v", observed[0], projected[0])
			}
		})
	}
}

func TestTimelineEntriesForFailsClosed(t *testing.T) {
	proc := procEntityID(10, 1)
	valid := procEnv("e1", base, proc, "", 10, 1, "exec", "app", "/app")
	if _, err := TimelineEntriesFor("", valid); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant must be rejected, got %v", err)
	}
	// Malformed envelope (schema 0) is rejected before any entry is built.
	bad := valid
	bad.SchemaVersion = 0
	if _, err := TimelineEntriesFor(testTenant, bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("malformed envelope must be rejected, got %v", err)
	}
}

// A container-carrying event still projects its own class entry (container inventory is cross-cutting, not
// a class), so there is always exactly one entry for a valid envelope.
func TestTimelineEntriesForContainerContextStillProjectsClassEntry(t *testing.T) {
	env := procEnvRC("e1", base, procEntityID(1, 1), 1, telemetry.ResourceContext{ContainerID: "c1", ImageDigest: "img1"})
	entries, err := TimelineEntriesFor(testTenant, env)
	if err != nil || len(entries) != 1 || entries[0].EntityKind != EntityProcess {
		t.Fatalf("want one process entry, got %d err=%v", len(entries), err)
	}
	if entries[0].EntityKind == EntityContainer {
		t.Fatal("container context must not become a timeline entry")
	}
}
