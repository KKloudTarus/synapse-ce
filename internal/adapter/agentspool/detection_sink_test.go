package agentspool

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestDetectionSinkRedactsEvidenceSecretsAtSource proves A6 (#627) closes the detection channel: a secret
// in a detection's evidence argv must not enter the spool (and thus the shipped, permanently-sealed record).
func TestDetectionSinkRedactsEvidenceSecretsAtSource(t *testing.T) {
	secret := "topSecret" + "Value123"
	durable := &captureSpool{}
	sink, err := NewDetectionSink(durable)
	if err != nil {
		t.Fatal(err)
	}
	det := validDetection()
	det.Evidence = []detection.Event{{
		Class: detection.ClassProcess, At: adapterNow.Add(-time.Millisecond), Host: "asset-1",
		Process: &detection.ProcessEvent{PID: 10, PPID: 1, Comm: "mysql", Path: "/usr/bin/mysql",
			Args: []string{"mysql", "--password=" + secret, "app_db"}, UID: 1000},
	}}
	if err := sink.Emit(context.Background(), det); err != nil {
		t.Fatal(err)
	}
	item := durable.snapshot()[0]
	if strings.Contains(string(item.Payload), secret) {
		t.Fatalf("detection evidence secret entered the spool unredacted: %s", item.Payload)
	}
	// Caller's detection is not mutated (engine keeps its raw copy).
	if !strings.Contains(det.Evidence[0].Process.Args[1], secret) {
		t.Fatal("Emit must not mutate the caller's detection")
	}
}

func TestDetectionSinkPersistsP1AndDeterministicID(t *testing.T) {
	durable := &captureSpool{}
	sink, err := NewDetectionSink(durable)
	if err != nil {
		t.Fatal(err)
	}
	value := validDetection()
	if err := sink.Emit(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	items := durable.snapshot()
	if len(items) != 2 {
		t.Fatalf("items = %d", len(items))
	}
	if items[0].Priority != fleetagent.PriorityP1 || !items[0].MustNotShed || items[0].EventID.IsZero() {
		t.Fatalf("classification = %#v", items[0])
	}
	if items[0].EventID != items[1].EventID {
		t.Fatalf("same detection derived different ids: %s / %s", items[0].EventID, items[1].EventID)
	}
	var decoded detection.Detection
	if err := json.Unmarshal(items[0].Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("spooled detection invalid: %v", err)
	}
}

func TestDetectionSinkRejectsInvalidValueAndDependency(t *testing.T) {
	if _, err := NewDetectionSink(nil); err == nil {
		t.Fatal("nil spool accepted")
	}
	sink, _ := NewDetectionSink(&captureSpool{})
	if err := sink.Emit(context.Background(), detection.Detection{}); err == nil {
		t.Fatal("invalid detection accepted")
	}
}

func TestDetectionSinkBackpressuresUntilP1IsAccepted(t *testing.T) {
	durable := &captureSpool{errors: []error{ports.ErrTelemetrySpoolSaturated, nil}}
	sink, _ := NewDetectionSink(durable)
	if err := sink.Emit(context.Background(), validDetection()); err != nil {
		t.Fatal(err)
	}
	if durable.calls != 2 || len(durable.snapshot()) != 1 {
		t.Fatalf("calls=%d accepted=%d", durable.calls, len(durable.snapshot()))
	}

	failed := &captureSpool{errors: []error{errors.New("disk failed")}}
	sink, _ = NewDetectionSink(failed)
	if err := sink.Emit(context.Background(), validDetection()); err == nil {
		t.Fatal("non-saturation disk error swallowed")
	}
}

func validDetection() detection.Detection {
	event := processEvent()
	return detection.Detection{
		RuleID: "proc.curl", RuleVersion: 1, Class: detection.ClassProcess,
		Severity: shared.SeverityHigh, HostID: "asset-1", AgentID: "agent-1",
		Evidence: []detection.Event{event}, ObservedCount: 1, Observed: adapterNow,
	}
}
