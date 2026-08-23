package privacy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
)

func mkDetectionWithArgs(t *testing.T, args []string) detection.Detection {
	t.Helper()
	r, ok := detection.Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("expected det.process_enumeration rule")
	}
	ev := detection.Event{Class: detection.ClassProcess, At: time.Unix(1, 0).UTC(), Host: "host-1",
		Process: &detection.ProcessEvent{PID: 10, PPID: 1, Comm: "mysqldump", Path: "/usr/bin/mysqldump", Args: args, UID: 0}}
	d, err := detection.NewDetection(r, "host-1", "agent-1", []detection.Event{ev}, time.Unix(500, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestScrubDetectionRedactsEvidenceSecret is the detection-channel half of the #611 exit: a secret in the
// evidence argv must not survive into the serialized (persisted/shipped/sealed) detection, and the caller's
// detection must not be mutated.
func TestScrubDetectionRedactsEvidenceSecret(t *testing.T) {
	secret := "hunter2" + "SuperSecret"
	det := mkDetectionWithArgs(t, []string{"mysqldump", "--password=" + secret, "app_db"})
	out, rep, err := ScrubDetection(det, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), secret) {
		t.Fatalf("secret survived into the serialized detection: %s", blob)
	}
	if !rep.Changed() {
		t.Fatal("report must record the redaction")
	}
	// Non-mutating: the caller's detection still holds the secret (the engine keeps its raw copy).
	if !strings.Contains(det.Evidence[0].Process.Args[1], secret) {
		t.Fatal("ScrubDetection must not mutate its input")
	}
	// Non-secret argv context preserved.
	if out.Evidence[0].Process.Args[0] != "mysqldump" || out.Evidence[0].Process.Args[2] != "app_db" {
		t.Fatalf("forensic argv context lost: %#v", out.Evidence[0].Process.Args)
	}
	// Rule attribution intact.
	if out.RuleID != det.RuleID || out.AgentID != det.AgentID {
		t.Fatalf("detection attribution changed: %+v", out)
	}
}

func TestScrubDetectionDeterministicAndRejectsBadPolicy(t *testing.T) {
	det := mkDetectionWithArgs(t, []string{"app", "--token=abc.def", "run"})
	a, _, _ := ScrubDetection(det, DefaultPolicy())
	b, _, _ := ScrubDetection(det, DefaultPolicy())
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ab) != string(bb) {
		t.Fatal("ScrubDetection must be deterministic (stable spool id + commitment)")
	}
	if _, _, err := ScrubDetection(det, Policy{}); err == nil {
		t.Fatal("an invalid policy must be rejected, not fail open")
	}
}
