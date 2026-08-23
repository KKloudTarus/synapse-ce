package telemetry

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func baseEnvelope() TelemetryEnvelope {
	occurred := time.Unix(1000, 0).UTC()
	observed := occurred.Add(2 * time.Millisecond)
	ev := TelemetryEvent{Class: detection.ClassProcess, Process: &ProcessObservation{Kind: "exec", PID: 10, EntityID: "pe_x", Comm: "sh", Path: "/bin/sh"}}
	return TelemetryEnvelope{
		SchemaVersion:  SchemaVersion,
		EventID:        "te_x",
		EventType:      ev.EventType(),
		EventClass:     detection.ClassProcess,
		AgentID:        "agent-1",
		AgentSessionID: "session-1",
		AssetID:        "asset-1",
		BootID:         "boot-1",
		StreamID:       "stream-1",
		OccurredAt:     occurred,
		ObservedAt:     observed,
		Event:          ev,
	}
}

func TestEnvelopeValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*TelemetryEnvelope)
		wantErr bool
	}{
		{"valid", func(*TelemetryEnvelope) {}, false},
		{"schema too low", func(e *TelemetryEnvelope) { e.SchemaVersion = SchemaMin - 1 }, true},
		{"schema too high", func(e *TelemetryEnvelope) { e.SchemaVersion = SchemaMax + 1 }, true},
		{"no event id", func(e *TelemetryEnvelope) { e.EventID = "" }, true},
		{"no agent id", func(e *TelemetryEnvelope) { e.AgentID = "" }, true},
		{"no asset id", func(e *TelemetryEnvelope) { e.AssetID = "" }, true},
		{"v2 no session", func(e *TelemetryEnvelope) { e.AgentSessionID = "" }, true},
		{"v2 no boot", func(e *TelemetryEnvelope) { e.BootID = "" }, true},
		{"v2 no stream", func(e *TelemetryEnvelope) { e.StreamID = "" }, true},
		{"class disagrees with payload", func(e *TelemetryEnvelope) { e.EventClass = detection.ClassNetwork }, true},
		{"type disagrees with payload", func(e *TelemetryEnvelope) { e.EventType = "process.fork" }, true},
		{"no occurred-at", func(e *TelemetryEnvelope) { e.OccurredAt = time.Time{} }, true},
		{"no observed-at", func(e *TelemetryEnvelope) { e.ObservedAt = time.Time{} }, true},
		{"occurred after observed", func(e *TelemetryEnvelope) { e.OccurredAt = e.ObservedAt.Add(time.Second) }, true},
		{"observed after received", func(e *TelemetryEnvelope) { e.ReceivedAt = e.ObservedAt.Add(-time.Second) }, true},
		{"received set and ordered", func(e *TelemetryEnvelope) { e.ReceivedAt = e.ObservedAt.Add(time.Second) }, false},
		{"invalid payload", func(e *TelemetryEnvelope) { e.Event.Process.PID = 0 }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := baseEnvelope()
			tt.mutate(&e)
			err := e.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%t", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("error must wrap shared.ErrValidation, got %v", err)
			}
		})
	}
}

func TestEnvelopeV1CompatibilityDoesNotRequireV2IncarnationFields(t *testing.T) {
	e := baseEnvelope()
	e.SchemaVersion = 1
	e.AgentSessionID = ""
	e.BootID = ""
	e.StreamID = ""
	if err := e.Validate(); err != nil {
		t.Fatalf("historical v1 envelope should remain readable without v2 incarnation fields: %v", err)
	}
}

func TestEnvelopeTimestampOrdering(t *testing.T) {
	e := baseEnvelope()
	if err := e.StampReceived(e.ObservedAt.Add(5 * time.Millisecond)); err != nil {
		t.Fatalf("stamp received: %v", err)
	}
	if !(e.OccurredAt.Before(e.ObservedAt) || e.OccurredAt.Equal(e.ObservedAt)) {
		t.Fatalf("occurred must be <= observed")
	}
	if !(e.ObservedAt.Before(e.ReceivedAt) || e.ObservedAt.Equal(e.ReceivedAt)) {
		t.Fatalf("observed must be <= received")
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate after stamp: %v", err)
	}
}

func TestStampReceivedRejectsOutOfOrder(t *testing.T) {
	e := baseEnvelope()
	if err := e.StampReceived(e.ObservedAt.Add(-time.Nanosecond)); err == nil {
		t.Fatalf("StampReceived must reject a time before observed-at")
	}
	if !e.ReceivedAt.IsZero() {
		t.Fatalf("a rejected stamp must not mutate ReceivedAt")
	}
	if err := e.StampReceived(time.Time{}); err == nil {
		t.Fatalf("StampReceived must reject a zero time")
	}
}

func TestEnvelopeCloneIsDeep(t *testing.T) {
	e := baseEnvelope()
	e.Event.Process.Args = []string{"a"}
	c := e.Clone()
	c.Event.Process.Comm = "changed"
	c.Event.Process.Args[0] = "MUTATED"
	if e.Event.Process.Comm != "sh" || e.Event.Process.Args[0] != "a" {
		t.Fatalf("Clone must deep-copy the payload; original was mutated")
	}
}

func TestDeriveEventIDDeterministic(t *testing.T) {
	a := DeriveEventID("asset-1", "boot-1", "stream-1", 7, detection.ClassProcess, 1234)
	b := DeriveEventID("asset-1", "boot-1", "stream-1", 7, detection.ClassProcess, 1234)
	if a != b {
		t.Fatalf("same coordinates must derive the same event id")
	}
	if a[:3] != "te_" {
		t.Fatalf("event id must be prefixed te_: %q", a)
	}
	if a == DeriveEventID("asset-1", "boot-1", "stream-1", 8, detection.ClassProcess, 1234) {
		t.Fatalf("a different sequence must derive a distinct id")
	}
	if a == DeriveEventID("asset-1", "boot-1", "stream-2", 7, detection.ClassProcess, 1234) {
		t.Fatalf("a different stream must derive a distinct id")
	}
}
