package ocsf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
)

func TestSchemasValidateEveryExportedClass(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatal(err)
	}
	exports := []siem.Exported{
		siem.ExportAudit("t", siem.AuditFact{ID: 1, Action: "finding.created", FindingID: "f", AtUnixMicro: 1700000000000000}, siem.ClassSignal, nil, ""),
		siem.ExportAudit("t", siem.AuditFact{ID: 2, Action: "finding.created", FindingID: "v", AdvisoryID: "CVE-2024-1234", Title: "Lỗi xác thực", AtUnixMicro: 1700000000000000}, siem.ClassDetail, nil, ""),
		siem.ExportIncident("t", siem.IncidentFact{IncidentID: "i", EventSeq: 1, StreamSeq: 1, Phase: siem.PhaseLive, Kind: "created", Owner: "ada", AtUnixMicro: 1700000000000000}, siem.ClassSummary, nil, ""),
	}
	for _, export := range exports {
		t.Run(export.Format, func(t *testing.T) {
			if err := v.Validate(export.Body); err != nil {
				t.Fatalf("%v: %s", err, export.Body)
			}
		})
	}
}

func TestSchemaRejectsNestedAndUnexpectedData(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing uid", func(d map[string]any) { delete(d["finding_info"].(map[string]any), "uid") }},
		{"wrong uid type", func(d map[string]any) { d["finding_info"].(map[string]any)["uid"] = 7 }},
		{"nested unknown property", func(d map[string]any) { d["finding_info"].(map[string]any)["secret"] = "PRIVATE-DATA" }},
		{"top unknown property", func(d map[string]any) { d["secret"] = "PRIVATE-DATA" }},
		{"missing cve uid", func(d map[string]any) {
			delete(d["vulnerabilities"].([]any)[0].(map[string]any)["cve"].(map[string]any), "uid")
		}},
		{"wrong array item", func(d map[string]any) { d["vulnerabilities"] = []any{"PRIVATE-DATA"} }},
		{"wrong nested enum", func(d map[string]any) { d["vulnerabilities"].([]any)[0].(map[string]any)["fix_coverage_id"] = 73 }},
		{"exclusive vulnerability constraint", func(d map[string]any) {
			d["vulnerabilities"].([]any)[0].(map[string]any)["cwe"] = map[string]any{"uid": "CWE-79"}
		}},
		{"fractional time", func(d map[string]any) { d["time"] = 1.25 }},
		{"fractional severity", func(d map[string]any) { d["severity_id"] = 1.25 }},
		{"wrong schema version", func(d map[string]any) { d["metadata"].(map[string]any)["version"] = "1.6.0" }},
		{"unemitted profile", func(d map[string]any) { d["metadata"].(map[string]any)["profiles"] = []any{"cloud"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			export := siem.ExportAudit("t", siem.AuditFact{ID: 2, Action: "finding.created", FindingID: "v", AdvisoryID: "CVE-2024-1234", AtUnixMicro: 1700000000000000}, siem.ClassDetail, nil, "")
			var doc map[string]any
			if err := json.Unmarshal(export.Body, &doc); err != nil {
				t.Fatal(err)
			}
			tc.mutate(doc)
			body, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			err = v.Validate(body)
			if err == nil {
				t.Fatal("invalid document accepted")
			}
			if strings.Contains(err.Error(), "PRIVATE-DATA") {
				t.Fatal("validation error leaked source data")
			}
		})
	}
	if err := v.Validate([]byte(`null`)); err == nil {
		t.Fatal("null accepted")
	}
	if _, err := (offlineLoader{}).Load("https://example.com/schema"); err == nil {
		t.Fatal("external reference permitted")
	}
}

func TestVendoredSchemaProvenance(t *testing.T) {
	var manifest struct {
		Version string `json:"version"`
		Tag     string `json:"tag"`
		Commit  string `json:"commit"`
		Files   []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	body, err := os.ReadFile("schemas/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != siem.OCSFSchemaVersion || manifest.Tag != siem.OCSFSchemaTag || manifest.Commit != "78bf68a24b38c0d6441ddd13b9028c1b1eb53f07" || len(manifest.Files) != 3 {
		t.Fatal("schema pin drift")
	}
	for _, file := range manifest.Files {
		body, err := documents.ReadFile("schemas/" + file.Name)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(body)
		if hex.EncodeToString(hash[:]) != file.SHA256 {
			t.Fatalf("schema checksum drift: %s", file.Name)
		}
	}
}
