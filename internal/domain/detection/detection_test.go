package detection

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func sampleRule(t *testing.T) Rule {
	t.Helper()
	r, ok := Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("expected det.process_enumeration in the catalogue")
	}
	return r
}

func TestNewDetectionCarriesFullAttribution(t *testing.T) {
	r := sampleRule(t)
	ev := procEvent("ps", "-ef")
	now := time.Unix(1000, 0)

	d, err := NewDetection(r, "host-1", "agent:vm-9", []Event{ev}, now)
	if err != nil {
		t.Fatalf("new detection: %v", err)
	}
	if d.Truncated {
		t.Error("one evidence event should not be truncated")
	}
	if d.RuleID != r.ID || d.RuleVersion != r.Version || d.Class != r.Class || d.Severity != r.Severity {
		t.Errorf("detection did not inherit rule identity: %+v", d)
	}
	if d.HostID != "host-1" || d.AgentID != "agent:vm-9" {
		t.Errorf("detection is missing host/agent attribution: %+v", d)
	}
	if len(d.Evidence) != 1 || d.Observed.IsZero() {
		t.Errorf("detection must carry evidence and an observation time: %+v", d)
	}
	if err := d.Validate(); err != nil {
		t.Errorf("a well-formed detection must validate: %v", err)
	}
}

// TestNewDetectionDefensivelyCopiesEvidence: a caller mutating its evidence slice OR the payload the
// event points at — including the argv slice — after the fact must not alter the sealed detection.
func TestNewDetectionDefensivelyCopiesEvidence(t *testing.T) {
	r := sampleRule(t)
	orig := procEvent("ps", "-ef")
	ev := []Event{orig}
	d, err := NewDetection(r, "h", "a", ev, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the slice element, the pointed-at payload, and the argv backing array.
	ev[0] = procEvent("mutated")
	orig.Process.Comm = "mutated"
	orig.Process.Args[0] = "mutated"
	if d.Evidence[0].Process.Comm != "ps" {
		t.Fatal("mutating the caller's payload pointer changed the sealed evidence")
	}
	if d.Evidence[0].Process.Args[0] != "-ef" {
		t.Fatal("mutating the caller's argv slice changed the sealed evidence")
	}
}

func TestNewDetectionBoundsEvidenceAndReportsTruncation(t *testing.T) {
	r := sampleRule(t)
	many := make([]Event, MaxEvidence+10)
	for i := range many {
		many[i] = procEvent("ps")
	}
	// Tag the last event so we can confirm the TAIL (most recent) is kept.
	many[len(many)-1] = procEvent("trigger")

	d, err := NewDetection(r, "h", "a", many, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Truncated {
		t.Fatal("over-long evidence must report truncation, not silently drop")
	}
	if d.ObservedCount != len(many) {
		t.Errorf("ObservedCount must record the pre-truncation total: got %d, want %d", d.ObservedCount, len(many))
	}
	if len(d.Evidence) != MaxEvidence {
		t.Fatalf("evidence not bounded: %d, want %d", len(d.Evidence), MaxEvidence)
	}
	if d.Evidence[len(d.Evidence)-1].Process.Comm != "trigger" {
		t.Error("truncation kept the wrong window; the most recent events (the trigger) must survive")
	}
	// The truncation flag must survive a re-validation of a reconstructed record.
	if err := d.Validate(); err != nil {
		t.Errorf("a bounded, well-formed detection must validate: %v", err)
	}
}

func TestNewDetectionRefusesIncomplete(t *testing.T) {
	r := sampleRule(t)
	good := procEvent("ps")
	cases := map[string]func() (Detection, error){
		"no host":     func() (Detection, error) { return NewDetection(r, "", "a", []Event{good}, time.Unix(1, 0)) },
		"no agent":    func() (Detection, error) { return NewDetection(r, "h", "", []Event{good}, time.Unix(1, 0)) },
		"no time":     func() (Detection, error) { return NewDetection(r, "h", "a", []Event{good}, time.Time{}) },
		"no evidence": func() (Detection, error) { return NewDetection(r, "h", "a", nil, time.Unix(1, 0)) },
		"bad evidence": func() (Detection, error) {
			return NewDetection(r, "h", "a", []Event{{Class: ClassProcess, At: time.Unix(1, 0)}}, time.Unix(1, 0))
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := call(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestEventValidateRejectsAmbiguousPayload(t *testing.T) {
	// A process class carrying a network payload, or two payloads, is malformed — it must never match.
	mixed := Event{Class: ClassProcess, At: time.Unix(1, 0), Host: "h",
		Process: &ProcessEvent{Comm: "ps"}, Network: &NetworkEvent{Proto: "udp"}}
	if err := mixed.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an event with two payloads must be rejected, got %v", err)
	}
	none := Event{Class: ClassProcess, At: time.Unix(1, 0), Host: "h"}
	if err := none.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an event with no payload must be rejected, got %v", err)
	}
}
