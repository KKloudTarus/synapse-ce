package siem

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestFindingAuditMapsStoredLifecycle(t *testing.T) {
	for _, tc := range []struct {
		action, status string
		activity       int
		format         string
	}{
		{"finding.created", "", 1, FormatDetectionFinding},
		{"finding.status", "triage", 2, FormatDetectionFinding},
		{"finding.status", "false_positive", 3, FormatDetectionFinding},
		{"finding.status", "remediated", 3, FormatDetectionFinding},
		{"finding.retest", "open", 2, FormatDetectionFinding},
		{"finding.retest", "remediated", 3, FormatDetectionFinding},
		{"finding.assigned", "", 2, FormatDetectionFinding},
		{"finding.writeup_applied", "", 2, FormatDetectionFinding},
		{"finding.threat_promoted", "", 2, FormatDetectionFinding},
		{"finding.sast_promoted", "", 2, FormatDetectionFinding},
		{"finding.dast_promoted", "", 2, FormatDetectionFinding},
		{"finding.status", "future", 0, FormatAuditEnvelope},
		{"finding.retest", "", 0, FormatAuditEnvelope},
		{"finding.comment", "", 0, FormatAuditEnvelope},
		{"finding.future", "", 0, FormatAuditEnvelope},
	} {
		t.Run(tc.action+"/"+tc.status, func(t *testing.T) {
			fact := AuditWithMetadata(AuditFact{ID: 1, Target: "f1", Action: tc.action, AtUnixMicro: 1700000000000000}, map[string]string{"engagement": "eng1", "status": tc.status})
			got := ExportAudit("tenant-a", fact, ClassSignal, nil, "")
			if got.Format != tc.format || got.Disposition != ItemPending {
				t.Fatalf("export = %+v", got)
			}
			var doc map[string]any
			if err := json.Unmarshal(got.Body, &doc); err != nil {
				t.Fatal(err)
			}
			if tc.activity > 0 {
				if doc["activity_id"] != float64(tc.activity) || doc["severity_id"] != float64(0) {
					t.Fatalf("invented activity/severity: %s", got.Body)
				}
				if err := ValidateOCSF(doc); err != nil {
					t.Fatal(err)
				}
			} else if got.Reason == "" || doc["fallback_reason"] == nil {
				t.Fatalf("unexplained fallback: %+v", got)
			}
		})
	}
}

func TestFindingAuditAllowlistReplayAndPrivacy(t *testing.T) {
	meta := map[string]string{"engagement": "eng1", "severity": "high", "title": "Lỗi token=abcdEFGH1234", "advisory_id": "CVE-2024-1234", "finding_id": "f1", "asset_id": "asset1", "note": "PRIVATE-NOTE", "assignee": "PRIVATE-OWNER", "description": "PRIVATE-DESCRIPTION"}
	before := map[string]string{}
	for k, v := range meta {
		before[k] = v
	}
	row := AuditFact{ID: 1, Action: "finding.created", Target: "f1", AtUnixMicro: 1700000000000000}
	fact := AuditWithMetadata(row, meta)
	if !reflect.DeepEqual(meta, before) || row.Title != "" {
		t.Fatal("source was mutated")
	}
	detail := ExportAudit("tenant-a", fact, ClassDetail, []string{"abcdEFGH1234"}, "")
	if detail.Format != FormatVulnerabilityFinding {
		t.Fatalf("detail = %+v", detail)
	}
	for _, secret := range []string{"abcdEFGH1234", "PRIVATE-NOTE", "PRIVATE-OWNER", "PRIVATE-DESCRIPTION"} {
		if strings.Contains(string(detail.Body), secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	meta["title"] = "later projection"
	meta["severity"] = "critical"
	replay := ExportAudit("tenant-a", fact, ClassDetail, []string{"abcdEFGH1234"}, "")
	if !bytes.Equal(detail.Body, replay.Body) || detail.RecordID != replay.RecordID || detail.Digest != replay.Digest {
		t.Fatal("snapshot replay changed")
	}
	for _, class := range []DataClass{ClassSignal, ClassSummary, ClassDetail, ClassNone} {
		got := ExportAudit("tenant-a", fact, class, nil, "")
		if class == ClassNone {
			if len(got.Body) != 0 || got.Disposition != ItemSuppressed {
				t.Fatal(got)
			}
			continue
		}
		if class == ClassSignal && (strings.Contains(string(got.Body), "Lỗi") || strings.Contains(string(got.Body), "CVE-")) {
			t.Fatalf("signal leaked detail: %s", got.Body)
		}
		if class == ClassSummary && strings.Contains(string(got.Body), "CVE-") {
			t.Fatalf("summary leaked advisory: %s", got.Body)
		}
	}
	other := ExportAudit("tenant-b", fact, ClassDetail, nil, "")
	if detail.RecordID == other.RecordID {
		t.Fatal("cross-tenant identity collision")
	}
	missing := fact
	missing.FindingID = ""
	got := ExportAudit("tenant-a", missing, ClassDetail, nil, "")
	if got.Format != FormatAuditEnvelope || got.Reason != "missing_finding_id" {
		t.Fatalf("missing identity = %+v", got)
	}
	missing = fact
	missing.AdvisoryID = "GHSA-aaaa-bbbb-cccc"
	if got := ExportAudit("tenant-a", missing, ClassDetail, nil, ""); got.Format != FormatDetectionFinding {
		t.Fatalf("non-CVE finding = %+v", got)
	}
}

func TestExportScrubsSecretsInIdentifierFields(t *testing.T) {
	secret := "fixture-secret-value"
	fact := AuditFact{ID: 1, Action: "finding.comment", FindingID: secret, EngagementID: secret, AssetID: secret, AdvisoryID: secret, Severity: secret}
	got := ExportAudit("tenant", fact, ClassDetail, []string{secret}, "https://console.example")
	if strings.Contains(string(got.Body), secret) {
		t.Fatalf("identifier leaked a known secret: %s", got.Body)
	}
	incident := IncidentFact{IncidentID: secret, EventSeq: 1, Phase: PhaseLive, Kind: "commented", EngagementID: secret, AssetID: secret, DetectionID: secret, ToStatus: secret}
	got = ExportIncident("tenant", incident, ClassDetail, []string{secret}, "https://console.example")
	if strings.Contains(string(got.Body), secret) {
		t.Fatalf("incident identifier leaked a known secret: %s", got.Body)
	}
}
