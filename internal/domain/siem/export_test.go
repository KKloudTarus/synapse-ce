package siem

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExportSignalOmitsSummaryFieldsAndScrubsSecrets(t *testing.T) {
	fact := AuditFact{
		ID: 7, Action: "user.login", Severity: "low", AtUnixMicro: 1_700_000_000_000_000,
		Hash: "abc", HashVersion: 2, Title: "password=hunter2", Actor: "ada", Host: "db.internal",
		AdvisoryID: "CVE-2024-1234",
	}
	got := ExportAudit("tenant-a", fact, ClassSignal, []string{"hunter2"}, "https://console.example")
	if got.Disposition != ItemPending || got.Format != FormatAuditEnvelope {
		t.Fatalf("export = %+v", got)
	}
	var doc map[string]any
	if err := json.Unmarshal(got.Body, &doc); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"title", "actor", "target_host", "advisory_id"} {
		if _, ok := doc[forbidden]; ok {
			t.Fatalf("signal carried %s: %s", forbidden, got.Body)
		}
	}
	if doc["action"] != "user.login" || doc["severity"] != "low" {
		t.Fatalf("signal body = %s", got.Body)
	}
	source := doc["source"].(map[string]any)
	if source["source_hash"] != "abc" {
		t.Fatal("source hash reference missing")
	}
	if strings.Contains(string(got.Body), got.Digest) {
		t.Fatal("payload digest was stored under the source hash name")
	}
}

func TestExportFallsBackToEnvelopeForIncompleteOCSFAndKeepsUnicode(t *testing.T) {
	vuln := AuditFact{ID: 3, Action: "vulnerability.created", AtUnixMicro: 1_700_000_000_000_000, HashVersion: 2, AdvisoryID: "GHSA-aaaa-bbbb-cccc"}
	got := ExportAudit("tenant-a", vuln, ClassDetail, nil, "")
	if got.Disposition != ItemPending || got.Format != FormatAuditEnvelope {
		t.Fatalf("non-CVE advisory was not safely exported: %+v", got)
	}
	cve := vuln
	cve.AdvisoryID = "CVE-2024-9999"
	cve.Title = "Lỗi xác thực tiếng Việt"
	got = ExportAudit("tenant-a", cve, ClassDetail, nil, "")
	if got.Disposition != ItemPending || got.Format != FormatVulnerabilityFinding {
		t.Fatalf("cve export = %+v", got)
	}
	if !strings.Contains(string(got.Body), "Lỗi xác thực tiếng Việt") {
		t.Fatalf("unicode title dropped: %s", got.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(got.Body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["class_uid"] != float64(2002) || doc["type_uid"] != float64(200201) {
		t.Fatalf("type identity = %v %v", doc["class_uid"], doc["type_uid"])
	}
	secret := ExportAudit("tenant-a", AuditFact{
		ID: 8, Action: "detection.created", AtUnixMicro: 1_700_000_000_000_000,
		Title: "token=abcdEFGH1234", FindingID: "f1",
	}, ClassSummary, nil, "")
	if secret.Disposition != ItemPending {
		t.Fatal(secret)
	}
	if !strings.Contains(string(secret.Body), "[redacted]") || strings.Contains(string(secret.Body), "abcdEFGH1234") {
		t.Fatalf("pattern scrubber missed the token: %s", secret.Body)
	}
}

func TestIncidentFindingRequiresOwnerAndEventStatus(t *testing.T) {
	base := IncidentFact{StreamSeq: 1, Phase: PhaseLive, IncidentID: "inc-1", EventSeq: 1, Kind: "created", AtUnixMicro: 1_700_000_000_000_000, Severity: "high", Title: "Phát hiện"}
	if got := ExportIncident("t", base, ClassSummary, nil, ""); got.Disposition != ItemPending || got.Format != FormatIncidentEnvelope || strings.Contains(string(got.Body), "assignee") {
		t.Fatalf("ownerless incident was not safely exported: %+v", got)
	}
	base.Owner = "ada"
	got := ExportIncident("t", base, ClassSummary, nil, "https://console.example")
	if got.Format != FormatIncidentFinding || !strings.Contains(string(got.Body), "Phát hiện") {
		t.Fatalf("incident finding = %s %+v", got.Body, got)
	}
	if strings.Contains(string(got.Body), "comment") {
		t.Fatal("summary included a comment field")
	}
	base.Kind = "analyst_commented"
	base.Comment = "password=hunter2 note"
	got = ExportIncident("t", base, ClassDetail, nil, "")
	if got.Format != FormatIncidentEnvelope || strings.Contains(string(got.Body), "hunter2") {
		t.Fatalf("comment export = %s", got.Body)
	}
	if got.Disposition == ItemSuppressed {
		t.Fatal("detail comment was suppressed")
	}
	none := ExportIncident("t", base, ClassNone, nil, "")
	if none.Disposition != ItemSuppressed {
		t.Fatalf("none = %+v", none)
	}
}

func TestOCSFDocumentRejectsFabricatedSeverity(t *testing.T) {
	body := ExportAudit("t", AuditFact{
		ID: 1, Action: "detection.created", AtUnixMicro: 1_700_000_000_000_000, FindingID: "f",
	}, ClassSignal, nil, "").Body
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["severity_id"] != float64(0) {
		t.Fatalf("missing severity was invented as %v", doc["severity_id"])
	}
	if err := ValidateOCSF(doc); err != nil {
		t.Fatal(err)
	}
	doc["severity_id"] = float64(99)
	if err := ValidateOCSF(doc); err == nil {
		t.Fatal("severity 99 passed")
	}
	doc["severity_id"] = float64(0)
	doc["type_uid"] = float64(1)
	if err := ValidateOCSF(doc); err == nil {
		t.Fatal("broken type_uid passed")
	}
}
