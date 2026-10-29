package telemetryingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	filepersist "github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/file"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// admissionAuditFailure simulates a lost response on either side of the append.
// Initial admission writes deliberately use the historical strict operation.
type admissionAuditFailure struct {
	*filepersist.AuditLog
	fail        bool
	afterAppend bool
}

func (a *admissionAuditFailure) RecordOnce(ctx context.Context, entry ports.AuditEntry) error {
	if entry.Action != "fleet.telemetry.ingest" || !a.fail {
		return a.AuditLog.RecordOnce(ctx, entry)
	}
	a.fail = false
	if a.afterAppend {
		if err := a.AuditLog.RecordOnce(ctx, entry); err != nil {
			return err
		}
	}
	return errors.New("admission audit response unavailable")
}

func (a *admissionAuditFailure) RecordFirstObservation(ctx context.Context, entry ports.AuditEntry) error {
	return a.RecordOnce(ctx, entry)
}

func TestIngestRetryPreservesDurableAdmissionAcrossClockChanges(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fail        bool
		afterAppend bool
	}{
		{name: "existing admission"},
		{name: "append response lost", fail: true, afterAppend: true},
		{name: "admission delayed after batch commit", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			sink := &admissionAuditFailure{AuditLog: filepersist.NewAuditLog(path), fail: tc.fail, afterAppend: tc.afterAppend}
			svc, err := NewService(h.transport, h.svc.keys, h.svc.policies, sink, h.clock)
			if err != nil {
				t.Fatal(err)
			}
			batch := h.signedBatch(1, 1, 0, "e1")
			_, err = svc.Ingest(h.ctx, "agent-1", batch)
			if (err != nil) != tc.fail {
				t.Fatalf("first admission error = %v, want failure %v", err, tc.fail)
			}
			if tc.fail && !tc.afterAppend {
				h.clock.Set(h.now.Add(time.Minute))
				if _, err = svc.Ingest(h.ctx, "agent-1", batch); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// Reopen both service and real durable audit adapter over retained data.
			audit := filepersist.NewAuditLog(path)
			svc, err = NewService(h.transport, h.svc.keys, h.svc.policies, audit, h.clock)
			if err != nil {
				t.Fatal(err)
			}
			for _, delta := range []time.Duration{2 * time.Minute, -time.Minute} {
				h.clock.Set(h.now.Add(delta))
				got, err := svc.Ingest(h.ctx, "agent-1", batch)
				if err != nil {
					t.Fatalf("retry after clock delta %s: %v", delta, err)
				}
				if !got.Duplicate || got.Accepted || got.ACK != 1 {
					t.Fatalf("retry = %+v, want duplicate ACK 1", got)
				}
			}
			errs := make(chan error, 8)
			for range 8 {
				go func() {
					got, err := svc.Ingest(h.ctx, "agent-1", batch)
					if err == nil && (!got.Duplicate || got.Accepted || got.ACK != 1) {
						err = fmt.Errorf("concurrent retry = %+v, want duplicate ACK 1", got)
					}
					errs <- err
				}()
			}
			for range 8 {
				if err := <-errs; err != nil {
					t.Errorf("concurrent retry: %v", err)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("retry changed immutable audit history")
			}
			if n, err := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); err != nil || n != 1 {
				t.Fatalf("stored events = %d, %v; want one", n, err)
			}
			entries, err := audit.List(h.ctx, 10)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				changed := entry
				changed.At = changed.At.Add(time.Second)
				if err := audit.RecordOnce(h.ctx, changed); !errors.Is(err, shared.ErrConflict) {
					t.Fatalf("strict audit must still reject changed time: %v", err)
				}
			}
			if report, err := audit.Verify(h.ctx); err != nil || !report.Intact || report.Verified != 2 {
				t.Fatalf("audit chain = %+v, %v; want two intact entries", report, err)
			}
		})
	}
}

type strictOnlyAudit struct{ ports.IdempotentAuditLogger }

func TestNewServiceRequiresFirstObservationAudit(t *testing.T) {
	h := newHarness(t)
	if _, err := NewService(h.transport, h.svc.keys, h.svc.policies, strictOnlyAudit{h.audit}, h.clock); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing first-observation capability = %v, want validation", err)
	}
}
