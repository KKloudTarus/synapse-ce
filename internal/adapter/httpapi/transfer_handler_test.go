package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	audituc "github.com/KKloudTarus/synapse-ce/internal/usecase/audit"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	transferuc "github.com/KKloudTarus/synapse-ce/internal/usecase/transfer"
)

type fakeAuditReader struct {
	entries []ports.AuditEntry
	report  audit.Report
}

func (f fakeAuditReader) List(context.Context, int) ([]ports.AuditEntry, error) {
	return f.entries, nil
}

func (f fakeAuditReader) Verify(context.Context) (audit.Report, error) {
	return f.report, nil
}

func newTransferRouter(t *testing.T) *Router {
	t.Helper()
	clock := fixedClock{t: time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)}
	ctx := context.Background()
	engRepo := memory.NewEngagementRepository()
	findRepo := memory.NewFindingRepository()
	commentRepo := memory.NewCommentRepository()
	ev, err := evidenceuc.NewService(memory.NewEvidenceStore(), blob.NewMemory(), &fakeAudit{}, clock, engIDs{})
	if err != nil {
		t.Fatal(err)
	}
	_ = engRepo.Create(ctx, &engdom.Engagement{
		ID: "e1", Name: "acme", Status: engdom.StatusActive,
		Scope: engdom.Scope{InScope: []engdom.Target{{Kind: engdom.TargetDomain, Value: "example.com"}}},
	})
	_ = findRepo.Upsert(ctx, []finding.Finding{{ID: "manual:1", EngagementID: "e1", Title: "XSS", Severity: shared.SeverityHigh, Status: finding.StatusOpen}})
	_, _ = ev.Seal(ctx, "e1", "scan", []byte("link one"), "alice")

	svc, err := transferuc.NewService(engRepo, findRepo, commentRepo, ev, &fakeAudit{}, clock, engIDs{})
	if err != nil {
		t.Fatal(err)
	}
	audit := fakeAuditReader{entries: []ports.AuditEntry{{Actor: "alice", Action: "sca.scan", Target: "example.com", At: clock.Now()}}}
	return &Router{log: discardLog(), transfer: svc, audit: auditSvc(t, audit)}
}

// auditSvc wraps a fake reader in the real audit use case (no signer) for handler tests.
func auditSvc(t *testing.T, reader ports.AuditReader) *audituc.Service {
	t.Helper()
	svc, err := audituc.NewService(reader)
	if err != nil {
		t.Fatalf("audit service: %v", err)
	}
	return svc
}

func exportBundleBytes(t *testing.T, rt *Router) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/e1/bundle", nil)
	req.SetPathValue("id", "e1")
	rec := httptest.NewRecorder()
	rt.exportBundle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export status %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	return rec.Body.Bytes()
}

func TestExportBundle(t *testing.T) {
	rt := newTransferRouter(t)
	data := exportBundleBytes(t, rt)
	var b transferuc.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if b.Version != transferuc.BundleVersionFramed || len(b.Findings) != 1 || len(b.Evidence) != 1 {
		t.Fatalf("unexpected bundle: version=%q findings=%d evidence=%d", b.Version, len(b.Findings), len(b.Evidence))
	}
}

func TestImportBundleRoundTrip(t *testing.T) {
	rt := newTransferRouter(t)
	data := exportBundleBytes(t, rt)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/import", bytes.NewReader(data))
	rec := httptest.NewRecorder()
	rt.importBundle(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("import status %d: %s", rec.Code, rec.Body.String())
	}
	var eng struct {
		ID string `json:"ID"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &eng); err != nil {
		t.Fatalf("decode imported engagement: %v", err)
	}
	if eng.ID == "" || eng.ID == "e1" {
		t.Errorf("import should create a new engagement id, got %q", eng.ID)
	}
}

func TestImportBundleRejectsTamperedChain(t *testing.T) {
	rt := newTransferRouter(t)
	data := exportBundleBytes(t, rt)
	var b transferuc.Bundle
	_ = json.Unmarshal(data, &b)
	b.Evidence[0].Content = []byte("tampered") // hash no longer matches
	tampered, _ := json.Marshal(b)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/import", bytes.NewReader(tampered))
	rec := httptest.NewRecorder()
	rt.importBundle(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a tampered chain must be rejected (400), got %d", rec.Code)
	}
}

func TestListAudit(t *testing.T) {
	rt := newTransferRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?limit=50", nil)
	rec := httptest.NewRecorder()
	rt.listAudit(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit status %d", rec.Code)
	}
	var entries []ports.AuditEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if len(entries) != 1 || entries[0].Action != "sca.scan" {
		t.Errorf("unexpected audit entries: %+v", entries)
	}
}

func TestVerifyAudit(t *testing.T) {
	rt := newTransferRouter(t)
	rt.audit = auditSvc(t, fakeAuditReader{report: audit.Report{Intact: true, Verified: 7, Head: "abc123"}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	rec := httptest.NewRecorder()
	rt.verifyAudit(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status %d", rec.Code)
	}
	var rep audit.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if !rep.Intact || rep.Verified != 7 || rep.Head != "abc123" {
		t.Errorf("unexpected verify report: %+v", rep)
	}
}
