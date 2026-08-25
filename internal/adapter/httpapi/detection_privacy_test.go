package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type detectionQueryReaderStub struct {
	records       []detection.Record
	incidents     []detection.Incident
	listCalls     int
	incidentCalls int
	order         *[]string
}

func (s *detectionQueryReaderStub) ListDetections(context.Context, shared.ID) ([]detection.Record, error) {
	s.listCalls++
	if s.order != nil {
		*s.order = append(*s.order, "read")
	}
	return s.records, nil
}

func (s *detectionQueryReaderStub) Incidents(context.Context, shared.ID) ([]detection.Incident, error) {
	s.incidentCalls++
	if s.order != nil {
		*s.order = append(*s.order, "read")
	}
	return s.incidents, nil
}

type detectionQueryAuditStub struct {
	entries []ports.AuditEntry
	err     error
	order   *[]string
}

func (s *detectionQueryAuditStub) Record(_ context.Context, entry ports.AuditEntry) error {
	if s.order != nil {
		*s.order = append(*s.order, "audit")
	}
	if s.err != nil {
		return s.err
	}
	s.entries = append(s.entries, entry)
	return nil
}

func sensitiveDetectionRecord(secret string) detection.Record {
	at := time.Unix(1_725_000_000, 0).UTC()
	return detection.Record{
		ID:           "det-1",
		TenantID:     "tenant-1",
		EngagementID: "eng-1",
		AssetID:      "asset-1",
		AgentID:      "agent-1",
		Detection: detection.Detection{
			RuleID:        "rule-1",
			RuleVersion:   1,
			Class:         detection.ClassProcess,
			Severity:      shared.SeverityHigh,
			HostID:        "host-1",
			AgentID:       "agent-1",
			ObservedCount: 3,
			Observed:      at,
			Evidence: []detection.Event{
				{Class: detection.ClassProcess, At: at, Host: "host-1", Process: &detection.ProcessEvent{
					PID: 101, PPID: 1, Comm: "worker", Path: "/srv/" + secret, Args: []string{"--credential", secret}, UID: 1000,
				}},
				{Class: detection.ClassNetwork, At: at, Host: "host-1", Network: &detection.NetworkEvent{
					Proto: "tcp", RemoteAddr: "203.0.113.7", RemotePort: 443, Direction: "outbound", PID: 101, Comm: "worker",
				}},
				{Class: detection.ClassFile, At: at, Host: "host-1", File: &detection.FileEvent{
					Path: "/tmp/" + secret, Op: "open", PID: 101, Comm: "worker",
				}},
			},
		},
		EvidenceID: "evidence-1",
		BatchSeq:   9,
		RecordedAt: at,
	}
}

func runDetectionQuery(t *testing.T, rt *Router, role, rawURL string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, rawURL, nil).WithContext(ctxAs(role))
	req.SetPathValue("id", "eng-1")
	rec := httptest.NewRecorder()
	rt.authz(userdom.PermView, rt.listDetections)(rec, req)
	return rec
}

func TestListDetectionsReadonlyStripsSensitiveFieldsAndAuditsFirst(t *testing.T) {
	secret := "fixture-" + "private-value"
	source := sensitiveDetectionRecord(secret)
	order := []string{}
	reader := &detectionQueryReaderStub{records: []detection.Record{source}, order: &order}
	audit := &detectionQueryAuditStub{order: &order}
	rt := &Router{log: discardLog(), detections: reader, vulnerabilityAudit: audit}

	rec := runDetectionQuery(t, rt, "readonly", "/api/v1/engagements/eng-1/detections")
	if rec.Code != http.StatusOK {
		t.Fatalf("readonly query: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(order) != 2 || order[0] != "audit" || order[1] != "read" {
		t.Fatalf("query must audit before data read, got order %v", order)
	}
	var response struct {
		Detections []detection.Record `json:"detections"`
		FieldScope string             `json:"field_scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.FieldScope != string(detectionFieldScopeRestricted) || len(response.Detections) != 1 {
		t.Fatalf("unexpected restricted response: scope=%q records=%d", response.FieldScope, len(response.Detections))
	}
	evidence := response.Detections[0].Detection.Evidence
	if evidence[0].Process.Path != "" || evidence[0].Process.Args != nil {
		t.Errorf("readonly process evidence leaked direct values: %+v", evidence[0].Process)
	}
	if evidence[1].Network.RemoteAddr != "" {
		t.Errorf("readonly network evidence leaked remote address %q", evidence[1].Network.RemoteAddr)
	}
	if evidence[2].File.Path != "" {
		t.Errorf("readonly file evidence leaked path %q", evidence[2].File.Path)
	}
	if evidence[0].Process.PID != 101 || evidence[0].Process.Comm != "worker" || evidence[1].Network.RemotePort != 443 {
		t.Errorf("restricted projection removed structural evidence unexpectedly: %+v", evidence)
	}

	// Projection is subtract-only and must never mutate the ledger-owned object returned by the reader.
	if got := reader.records[0].Detection.Evidence[0].Process.Path; got != "/srv/"+secret {
		t.Fatalf("projection mutated stored process path: %q", got)
	}
	if got := reader.records[0].Detection.Evidence[0].Process.Args[1]; got != secret {
		t.Fatalf("projection mutated stored argv: %q", got)
	}

	if len(audit.entries) != 1 {
		t.Fatalf("want one query audit entry, got %d", len(audit.entries))
	}
	entry := audit.entries[0]
	if entry.Actor != "p1" || entry.Action != "detection.query" || entry.Target != "eng-1" || entry.Metadata["view"] != "records" || entry.Metadata["field_scope"] != "restricted" {
		t.Fatalf("unexpected query audit entry: %+v", entry)
	}
	encodedAudit, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal audit entry: %v", err)
	}
	if strings.Contains(string(encodedAudit), secret) || strings.Contains(string(encodedAudit), "203.0.113.7") {
		t.Fatalf("query audit must contain metadata only, not sensitive evidence: %s", encodedAudit)
	}
}

func TestListDetectionsInvestigativeRolesRetainSourceRedactedEvidence(t *testing.T) {
	secret := "fixture-" + "visible-after-source-scrub"
	for _, role := range []string{"consultant", "reviewer", "admin"} {
		t.Run(role, func(t *testing.T) {
			reader := &detectionQueryReaderStub{records: []detection.Record{sensitiveDetectionRecord(secret)}}
			audit := &detectionQueryAuditStub{}
			rt := &Router{log: discardLog(), detections: reader, vulnerabilityAudit: audit}

			rec := runDetectionQuery(t, rt, role, "/api/v1/engagements/eng-1/detections")
			if rec.Code != http.StatusOK {
				t.Fatalf("query: want 200, got %d: %s", rec.Code, rec.Body.String())
			}
			var response struct {
				Detections []detection.Record `json:"detections"`
				FieldScope string             `json:"field_scope"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if response.FieldScope != string(detectionFieldScopeFull) {
				t.Fatalf("want full field scope, got %q", response.FieldScope)
			}
			process := response.Detections[0].Detection.Evidence[0].Process
			if process.Path != "/srv/"+secret || len(process.Args) != 2 || process.Args[1] != secret {
				t.Fatalf("full scope unexpectedly removed already-source-scrubbed evidence: %+v", process)
			}
			if len(audit.entries) != 1 || audit.entries[0].Metadata["field_scope"] != "full" {
				t.Fatalf("full-scope query not audited correctly: %+v", audit.entries)
			}
		})
	}
}

func TestListDetectionsAuditFailureFailsClosedBeforeRead(t *testing.T) {
	order := []string{}
	reader := &detectionQueryReaderStub{records: []detection.Record{sensitiveDetectionRecord("fixture-value")}, order: &order}
	audit := &detectionQueryAuditStub{err: errors.New("audit unavailable"), order: &order}
	rt := &Router{log: discardLog(), detections: reader, vulnerabilityAudit: audit}

	rec := runDetectionQuery(t, rt, "consultant", "/api/v1/engagements/eng-1/detections")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit failure: want 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if reader.listCalls != 0 {
		t.Fatalf("audit failure must stop before reader, list calls=%d", reader.listCalls)
	}
	if len(order) != 1 || order[0] != "audit" {
		t.Fatalf("audit failure touched data path: order=%v", order)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("saturated audit failure should carry Retry-After")
	}
}

func TestDetectionIncidentViewIsSummaryScopedAndAudited(t *testing.T) {
	reader := &detectionQueryReaderStub{incidents: []detection.Incident{{Key: "rule\x00asset", RuleID: "rule", AssetID: "asset-1", Count: 1}}}
	audit := &detectionQueryAuditStub{}
	rt := &Router{log: discardLog(), detections: reader, vulnerabilityAudit: audit}

	rec := runDetectionQuery(t, rt, "readonly", "/api/v1/engagements/eng-1/detections?view=incidents")
	if rec.Code != http.StatusOK {
		t.Fatalf("incident query: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if reader.incidentCalls != 1 || reader.listCalls != 0 {
		t.Fatalf("unexpected reader calls: incidents=%d records=%d", reader.incidentCalls, reader.listCalls)
	}
	var response struct {
		Incidents  []detection.Incident `json:"incidents"`
		FieldScope string               `json:"field_scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.FieldScope != string(detectionFieldScopeSummary) || len(response.Incidents) != 1 {
		t.Fatalf("unexpected incident response: scope=%q incidents=%d", response.FieldScope, len(response.Incidents))
	}
	if len(audit.entries) != 1 || audit.entries[0].Metadata["view"] != "incidents" || audit.entries[0].Metadata["field_scope"] != "summary" {
		t.Fatalf("incident query audit mismatch: %+v", audit.entries)
	}
}
