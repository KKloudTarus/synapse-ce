package notification

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func validSourceRecord() SourceRecord {
	return SourceRecord{
		TenantID: "tenant-1", SourceKind: "scan_job", SourceID: "scan-1", EventType: EventScanCompleted,
		OccurredAt: time.Date(2026, 9, 28, 8, 0, 0, 0, time.FixedZone("ICT", 7*3600)),
		Data:       json.RawMessage(`{"title":"Scan completed"}`),
	}
}

func TestSourceRecordNormalizeFillsDefaults(t *testing.T) {
	record := validSourceRecord()
	record.SourceID = "  scan-1 "
	if err := record.Normalize(); err != nil {
		t.Fatal(err)
	}
	if record.SchemaVersion != 1 || string(record.Context) != "{}" || record.SourceID != "scan-1" || record.OccurredAt.Location() != time.UTC {
		t.Fatalf("normalized record = %+v", record)
	}
}

func TestSourceRecordValidation(t *testing.T) {
	cases := map[string]func(*SourceRecord){
		"missing tenant":          func(r *SourceRecord) { r.TenantID = "" },
		"dotted source kind":      func(r *SourceRecord) { r.SourceKind = "scan.job" },
		"upper-case source kind":  func(r *SourceRecord) { r.SourceKind = "ScanJob" },
		"missing source id":       func(r *SourceRecord) { r.SourceID = " " },
		"long source id":          func(r *SourceRecord) { r.SourceID = strings.Repeat("x", 513) },
		"event not in catalog":    func(r *SourceRecord) { r.EventType = "jira.issue_created" },
		"future schema version":   func(r *SourceRecord) { r.SchemaVersion = 99 },
		"negative schema version": func(r *SourceRecord) { r.SchemaVersion = -1 },
		"missing occurred time":   func(r *SourceRecord) { r.OccurredAt = time.Time{} },
		"dotted subject kind":     func(r *SourceRecord) { r.SubjectKind = "fleet.agent" },
		"long subject id":         func(r *SourceRecord) { r.SubjectID = strings.Repeat("x", 513) },
		"data not an object":      func(r *SourceRecord) { r.Data = json.RawMessage(`[]`) },
		"data missing":            func(r *SourceRecord) { r.Data = nil },
		"context not an object":   func(r *SourceRecord) { r.Context = json.RawMessage(`"text"`) },
		"context over 1 MiB":      func(r *SourceRecord) { r.Context = json.RawMessage(`{"v":"` + strings.Repeat("x", 1<<20) + `"}`) },
	}
	for name, mutate := range cases {
		record := validSourceRecord()
		mutate(&record)
		if err := record.Normalize(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
	record := validSourceRecord()
	record.SubjectKind, record.SubjectID, record.Context = "scan_job", "scan-1", json.RawMessage(`{"title":"x"}`)
	if err := record.Normalize(); err != nil {
		t.Fatalf("valid record with subject and context: %v", err)
	}
}

// A producer's business write must not fail because its notification payload is large; the
// projection bounds the event instead.
func TestSourceRecordDataIsNotSizeBounded(t *testing.T) {
	record := validSourceRecord()
	record.Data = json.RawMessage(`{"title":"` + strings.Repeat("x", 64<<10) + `"}`)
	if err := record.Normalize(); err != nil {
		t.Fatalf("large data refused: %v", err)
	}
}
