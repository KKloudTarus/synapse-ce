package ownadvisory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

// TestParseRockyOSV parses a real (trimmed) RESF/Apollo OSV list fixture: an RLSA is expanded into one
// advisory per upstream CVE, keyed by CVE (not the RLSA id) and by the OSV "Rocky Linux:<major>" ecosystem.
func TestParseRockyOSV(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "rocky-apollo-osv.json"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseRockyOSV(data)
	if err != nil {
		t.Fatalf("ParseRockyOSV: %v", err)
	}
	if len(advs) == 0 {
		t.Fatal("no Rocky advisories parsed")
	}
	for _, a := range advs {
		if !strings.HasPrefix(a.ID, "CVE-") {
			t.Errorf("advisory id %q must be a CVE (not the RLSA)", a.ID)
		}
		for _, ap := range a.Affected {
			if !strings.HasPrefix(ap.Ecosystem, "Rocky Linux:") {
				t.Errorf("%s: ecosystem = %q, want Rocky Linux:*", a.ID, ap.Ecosystem)
			}
			if ap.Ranges[0].Type != "ECOSYSTEM" {
				t.Errorf("%s: range type = %q, want ECOSYSTEM", a.ID, ap.Ranges[0].Type)
			}
		}
	}
}

// TestParseRockyOSVMatchesViaDomainMatcher proves a Rocky advisory matches by CVE through the rpm comparator.
func TestParseRockyOSVMatchesViaDomainMatcher(t *testing.T) {
	data, _ := os.ReadFile(filepath.Join("testdata", "rocky-apollo-osv.json"))
	advs, err := ParseRockyOSV(data)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's first RLSA fixes kernel-rt at 0:4.18.0-553.162.1.rt7.503.el8_10 on Rocky Linux:8.
	var kernel advisory.Advisory
	for _, a := range advs {
		for _, ap := range a.Affected {
			if ap.Package == "kernel-rt" && ap.Ecosystem == "Rocky Linux:8" {
				kernel = a
			}
		}
	}
	if kernel.ID == "" {
		t.Fatal("kernel-rt / Rocky Linux:8 advisory not parsed")
	}
	fixed := "0:4.18.0-553.162.1.rt7.503.el8_10"
	lower := "0:4.18.0-553.100.1.rt7.500.el8_10"
	if ok, _ := kernel.Match("Rocky Linux:8", "kernel-rt", lower); !ok {
		t.Errorf("an older kernel-rt (%s) below fix %s must match", lower, fixed)
	}
	if ok, _ := kernel.Match("Rocky Linux:8", "kernel-rt", fixed); ok {
		t.Error("kernel-rt at the fixed version must not match")
	}
	if ok, _ := kernel.Match("Rocky Linux:9", "kernel-rt", lower); ok {
		t.Error("a different Rocky release must not match")
	}
}

// TestRockyRejectsUnsoundEntries proves the two false-positive guards: a range whose "introduced" is not 0 is
// never collapsed to [0, fixed) (which would match older unaffected rpms), and a non-Rocky ecosystem is never
// written by this Rocky-only ingester (which would false-match another distro). A conforming entry still emits.
func TestRockyRejectsUnsoundEntries(t *testing.T) {
	const doc = `{"advisories":[
	  {"id":"RLSA-2026:1","upstream":["CVE-2026-2001"],"affected":[
	    {"package":{"ecosystem":"Rocky Linux:9","name":"nonzero"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.0.0"},{"fixed":"0:3.0.7-1.el9"}]}]}
	  ]},
	  {"id":"RLSA-2026:2","upstream":["CVE-2026-2002"],"affected":[
	    {"package":{"ecosystem":"Red Hat Enterprise Linux:9","name":"foreign"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:1.2.3-1.el9"}]}]}
	  ]},
	  {"id":"RLSA-2026:3","upstream":["CVE-2026-2003"],"affected":[
	    {"package":{"ecosystem":"Rocky Linux:9","name":"good"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:1.2.3-1.el9"}]}]}
	  ]}
	]}`
	advs, err := ParseRockyOSV([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]advisory.Advisory{}
	for _, a := range advs {
		byID[a.ID] = a
	}
	if _, ok := byID["CVE-2026-2001"]; ok {
		t.Error("a non-zero introduced range must not be emitted as [0, fixed) (false-positive risk)")
	}
	if _, ok := byID["CVE-2026-2002"]; ok {
		t.Error("a non-Rocky ecosystem must not be written by the Rocky ingester (cross-distro false match)")
	}
	good, ok := byID["CVE-2026-2003"]
	if !ok || len(good.Affected) != 1 || good.Affected[0].Ecosystem != "Rocky Linux:9" || good.Affected[0].Package != "good" {
		t.Errorf("a conforming Rocky [0, fixed) entry must still be emitted, got %+v", good)
	}
}

// TestRockyCVEsFromUpstream proves the CVEs come from the OSV "upstream" field (Rocky) and aliases, not the
// RLSA document id.
func TestRockyCVEsFromUpstream(t *testing.T) {
	doc := osvDoc{ID: "RLSA-2026:1", Upstream: []string{"CVE-2026-1000", "CVE-2026-1001", "not-a-cve"}, Aliases: []string{"CVE-2026-1000"}}
	got := rockyCVEs(doc)
	if len(got) != 2 || got[0] != "CVE-2026-1000" || got[1] != "CVE-2026-1001" {
		t.Errorf("rockyCVEs = %v, want [CVE-2026-1000 CVE-2026-1001]", got)
	}
}
