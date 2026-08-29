package ports

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var spoolTestTime = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

func validSpoolItem() SpoolItem {
	return SpoolItem{
		Kind: SpoolRecordTelemetry, Priority: fleetagent.PriorityP3, EventID: "event-1",
		EventClass: detection.ClassProcess, ContentType: "application/json", Payload: []byte("{}"),
		ObservedAt: spoolTestTime, SchemaVersion: 1,
	}
}

func TestSpoolItemValidation(t *testing.T) {
	if err := validSpoolItem().Validate(); err != nil {
		t.Fatalf("valid item: %v", err)
	}
	tests := []struct {
		name string
		edit func(*SpoolItem)
	}{
		{"kind", func(i *SpoolItem) { i.Kind = "future" }},
		{"priority", func(i *SpoolItem) { i.Priority = 9 }},
		{"event id", func(i *SpoolItem) { i.EventID = "" }},
		{"class", func(i *SpoolItem) { i.EventClass = "future" }},
		{"content type", func(i *SpoolItem) { i.ContentType = "" }},
		{"payload", func(i *SpoolItem) { i.Payload = nil }},
		{"observed", func(i *SpoolItem) { i.ObservedAt = time.Time{} }},
		{"schema", func(i *SpoolItem) { i.SchemaVersion = 0 }},
		{"P2 shed", func(i *SpoolItem) {
			i.Priority = fleetagent.PriorityP2
			i.EventClass = detection.ClassFile
			i.MustNotShed = false
		}},
		{"P3 no-shed", func(i *SpoolItem) { i.MustNotShed = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := validSpoolItem()
			tt.edit(&item)
			if err := item.Validate(); err == nil || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestMustNotShedRecordClassifiesEveryExistingRecordKind(t *testing.T) {
	tests := []struct {
		kind     SpoolRecordKind
		class    detection.Class
		want     bool
		wantErr  bool
		priority fleetagent.DeliveryPriority
	}{
		{SpoolRecordTelemetry, detection.ClassProcess, false, false, fleetagent.PriorityP3},
		{SpoolRecordTelemetry, detection.ClassFile, true, false, fleetagent.PriorityP2},
		{SpoolRecordDetection, "", true, false, fleetagent.PriorityP1},
		{SpoolRecordCoverage, "", true, false, fleetagent.PriorityP0},
		{SpoolRecordSensorState, "", true, false, fleetagent.PriorityP0},
		{SpoolRecordResponseVerification, "", true, false, fleetagent.PriorityP0},
		{"future", "", false, true, fleetagent.PriorityP0},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			got, err := MustNotShedRecord(tt.kind, tt.class)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("MustNotShedRecord(%q, %q) = %t, %v; want %t, error=%t", tt.kind, tt.class, got, err, tt.want, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			item := SpoolItem{Kind: tt.kind, Priority: tt.priority, EventID: "event-1", EventClass: tt.class, ContentType: "application/json", Payload: []byte("{}"), ObservedAt: spoolTestTime, MustNotShed: got, SchemaVersion: 1}
			if err := item.Validate(); err != nil {
				t.Fatalf("classified spool item does not validate: %v", err)
			}
		})
	}
}

func TestSpoolGapValidation(t *testing.T) {
	gap := SpoolGap{
		ID: "gap-1", Priority: fleetagent.PriorityP3, Epoch: 2,
		FromSequence: 4, ToSequence: 6, KnownSequence: true,
		Reason: SpoolGapQuotaEviction, Count: 3, OccurredAt: spoolTestTime,
	}
	if err := gap.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := gap
	bad.Count = 2
	if err := bad.Validate(); err == nil {
		t.Fatal("range/count mismatch accepted")
	}
	unknown := gap
	unknown.KnownSequence = false
	unknown.FromSequence, unknown.ToSequence, unknown.Count = 0, 0, 1
	unknown.Reason = SpoolGapQuotaBackpressure
	if err := unknown.Validate(); err != nil {
		t.Fatalf("valid unknown gap: %v", err)
	}
	unknown.FromSequence = 1
	if err := unknown.Validate(); err == nil {
		t.Fatal("unknown gap claimed a sequence")
	}
}

func TestSpoolACKValidation(t *testing.T) {
	if err := (SpoolACK{Priority: fleetagent.PriorityP1, Epoch: 2, Through: 9}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, ack := range []SpoolACK{
		{Priority: 7, Epoch: 1, Through: 1},
		{Priority: fleetagent.PriorityP1, Epoch: 0, Through: 1},
		{Priority: fleetagent.PriorityP1, Epoch: 1, Through: 0},
	} {
		if err := ack.Validate(); err == nil {
			t.Errorf("invalid ACK accepted: %#v", ack)
		}
	}
}
