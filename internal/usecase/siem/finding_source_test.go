package siemuc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
)

func TestFindingsServiceAuditReachesValidatedExportWithoutHydration(t *testing.T) {
	svc, store, driver, _, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	sink, err := svc.Create(ctx, "ada", SinkInput{Name: "Findings", Provider: siem.ProviderSplunk, Origin: "https://splunk.example", Secret: "splunk-token"})
	if err != nil {
		t.Fatal(err)
	}
	repo := memory.NewFindingRepository()
	auditLog := &memAudit{}
	findings := findingsuc.NewService(repo, nil, nil, auditLog, clock, &seqIDs{})
	f, err := findings.Create(ctx, "ada", "eng1", finding.ManualInput{Title: "Lỗi xác thực", Description: "PRIVATE-DESCRIPTION", Severity: shared.SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	_, err = findings.UpdateStatus(ctx, "eng1", f.ID, finding.StatusRemediated, "PRIVATE-NOTE splunk-token", "ada", f.Version)
	if err != nil {
		t.Fatal(err)
	}
	previous := ""
	for i, entry := range auditLog.entries {
		row := chain(entry.Actor, entry.Action, entry.Target, previous, entry.At, entry.Metadata)
		row.ID = int64(i + 1)
		// Unhashed convenience fields must never override committed metadata.
		row.Title = "PRIVATE-HYDRATION"
		row.Severity = "critical"
		store.AddAudit("tenant-a", row, entry.Metadata)
		previous = row.Hash
	}
	before, problem, err := svc.prepareAudit(ctx, sink, siem.Checkpoint{})
	if err != nil || !problem.None() || len(before) != 2 {
		t.Fatalf("prepare: %d %+v %v", len(before), problem, err)
	}
	f.Title = "CHANGED-TITLE"
	f.Severity = shared.SeverityCritical
	if err := repo.Upsert(ctx, []finding.Finding{f}); err != nil {
		t.Fatal(err)
	}
	after, problem, err := svc.prepareAudit(ctx, sink, siem.Checkpoint{})
	if err != nil || !problem.None() || len(after) != len(before) {
		t.Fatalf("replay: %+v %v", problem, err)
	}
	for i, item := range before {
		if !bytes.Equal(item.export.Body, after[i].export.Body) || item.export.Digest != after[i].export.Digest || item.export.RecordID != after[i].export.RecordID {
			t.Fatal("replay used changed finding state")
		}
		if item.export.Format != siem.FormatDetectionFinding || item.export.Disposition != siem.ItemPending {
			t.Fatalf("not validated OCSF: %+v", item.export)
		}
		if err := svc.schema.Validate(item.export.Body); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"PRIVATE-DESCRIPTION", "PRIVATE-NOTE", "splunk-token", "PRIVATE-HYDRATION", "CHANGED-TITLE"} {
			if strings.Contains(string(item.export.Body), secret) {
				t.Fatalf("leaked %s", secret)
			}
		}
		var doc map[string]any
		if err := json.Unmarshal(item.export.Body, &doc); err != nil {
			t.Fatal(err)
		}
		wantSeverity := float64(4)
		if i == 1 {
			wantSeverity = 0
		}
		if doc["severity_id"] != wantSeverity {
			t.Fatalf("severity borrowed from current finding: %s", item.export.Body)
		}
	}
	other, _, _, err := store.ReadAudit(shared.WithTenant(context.Background(), "tenant-b"), 0, 100)
	if err != nil || len(other) != 0 {
		t.Fatalf("cross-tenant audit read: %+v %v", other, err)
	}
	if _, err := svc.Tick(ctx, "worker", TickBudget{MaxPartitions: 3}); err != nil {
		t.Fatal(err)
	}
	if len(driver.seen) != 2 {
		t.Fatalf("delivered %d records", len(driver.seen))
	}
	for i, body := range driver.seen {
		if !bytes.Equal(body, before[i].export.Body) {
			t.Fatal("tick payload differed from verified source")
		}
	}
}

type rejectingSchema struct{}

func (rejectingSchema) Validate([]byte) error { return fmt.Errorf("PRIVATE-SCHEMA-ERROR") }

func TestSchemaFailureQuarantinesWithoutSendingOrLeakingErrors(t *testing.T) {
	svc, store, driver, _, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	if _, err := svc.Create(ctx, "ada", SinkInput{Name: "Findings", Provider: siem.ProviderSplunk, Origin: "https://splunk.example", Secret: "splunk-token"}); err != nil {
		t.Fatal(err)
	}
	row := chain("ada", "finding.created", "f1", "", clock.now, nil)
	row.ID = 1
	store.AddAudit("tenant-a", row, nil)
	svc.schema = rejectingSchema{}
	if _, err := svc.Tick(ctx, "worker", TickBudget{MaxPartitions: 3}); err != nil {
		t.Fatal(err)
	}
	if driver.calls != 0 {
		t.Fatal("invalid OCSF was sent")
	}
	result := svc.validateExport(siem.ExportAudit("tenant-a", siem.AuditFact{ID: 1, Action: "finding.created", FindingID: "f1"}, siem.ClassSignal, nil, ""))
	if result.Disposition != siem.ItemQuarantined || result.Reason != "schema_validation" || len(result.Body) != 0 || result.Digest != "" {
		t.Fatalf("unsafe quarantine: %+v", result)
	}
}
