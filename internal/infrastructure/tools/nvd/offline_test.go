package nvd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

// api2 is a minimal NVD API-2.0 feed with a v3.1 metric and a v2-only CVE.
const api2 = `{"vulnerabilities":[
 {"cve":{"id":"CVE-2021-44228","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","baseScore":10.0}}],"cvssMetricV2":[{"cvssData":{"vectorString":"AV:N/AC:M/Au:N/C:C/I:C/A:C","baseScore":9.3}}]}}},
 {"cve":{"id":"CVE-2015-0001","metrics":{"cvssMetricV2":[{"cvssData":{"vectorString":"AV:L/AC:L/Au:N/C:N/I:N/A:C","baseScore":4.9}}]}}},
 {"cve":{"id":"CVE-9999-0000","metrics":{}}}
]}`

// legacy11 is a minimal legacy NVD 1.1 feed.
const legacy11 = `{"CVE_Items":[
 {"cve":{"CVE_data_meta":{"ID":"CVE-2018-1000"}},"impact":{"baseMetricV3":{"cvssV3":{"vectorString":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","baseScore":7.5}}}}
]}`

func TestBuildDBBothFormats(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "api2.json")
	f2 := filepath.Join(dir, "legacy.json")
	os.WriteFile(f1, []byte(api2), 0o600)
	os.WriteFile(f2, []byte(legacy11), 0o600)

	var buf bytes.Buffer
	n, err := BuildDB([]string{f1, f2}, &buf)
	if err != nil {
		t.Fatalf("BuildDB: %v", err)
	}
	// 2 from api2 (the empty-metrics CVE is skipped) + 1 from legacy = 3
	if n != 3 {
		t.Fatalf("want 3 entries, got %d\n%s", n, buf.String())
	}
	out := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte(`"id":"CVE-2021-44228"`)) || !bytes.Contains(buf.Bytes(), []byte(`CVSS:3.1/`)) {
		t.Errorf("expected v3.1 vector preferred for log4shell, got: %s", out)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"id":"CVE-2018-1000"`)) {
		t.Errorf("expected legacy 1.1 CVE ingested, got: %s", out)
	}
}

func TestOfflineEnrich(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.json")
	os.WriteFile(src, []byte(api2+"\n"), 0o600)
	dbPath := filepath.Join(dir, "cvss.jsonl")
	out, _ := os.Create(dbPath)
	if _, err := BuildDB([]string{src}, out); err != nil {
		t.Fatal(err)
	}
	out.Close()

	oe, err := LoadOffline(dbPath)
	if err != nil {
		t.Fatalf("LoadOffline: %v", err)
	}
	if oe.Size() != 2 {
		t.Fatalf("want 2 CVEs loaded, got %d", oe.Size())
	}

	vulns := []vulnerability.Vulnerability{
		{ID: "CVE-2021-44228", Severity: shared.SeverityHigh},                                 // known sev, no CVSS → fill vector, keep sev
		{ID: "CVE-2015-0001", Severity: shared.SeverityUnknown},                               // unknown sev → fill sev from score
		{ID: "CVE-2000-9999", Severity: shared.SeverityUnknown},                               // not in DB → untouched
		{ID: "CVE-2021-44228", Severity: shared.SeverityLow, CVSSVector: "CVSS:3.1/EXISTING"}, // already has CVSS → untouched
	}
	res := oe.Enrich(context.Background(), vulns)

	if vulns[0].CVSSVector == "" || vulns[0].Severity != shared.SeverityHigh {
		t.Errorf("v0: want CVSS filled + severity preserved, got vec=%q sev=%q", vulns[0].CVSSVector, vulns[0].Severity)
	}
	if vulns[1].Severity == shared.SeverityUnknown {
		t.Errorf("v1: unknown severity should be backfilled from CVSS score")
	}
	if vulns[2].CVSSVector != "" || vulns[2].Severity != shared.SeverityUnknown {
		t.Errorf("v2: absent CVE must be untouched, got vec=%q sev=%q", vulns[2].CVSSVector, vulns[2].Severity)
	}
	if vulns[3].CVSSVector != "CVSS:3.1/EXISTING" || vulns[3].Severity != shared.SeverityLow {
		t.Errorf("v3: existing CVSS/severity must be preserved, got vec=%q sev=%q", vulns[3].CVSSVector, vulns[3].Severity)
	}
	if res.Matches < 2 {
		t.Errorf("want >=2 matches, got %d", res.Matches)
	}
	if res.Source != "nvd-offline" {
		t.Errorf("want source nvd-offline, got %q", res.Source)
	}
}
