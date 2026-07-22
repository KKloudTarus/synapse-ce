package grype

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const sampleGrype = `{
  "matches": [
    {
      "vulnerability": {
        "id": "GHSA-aaaa-bbbb-cccc",
        "severity": "High",
        "description": "bad thing",
        "fix": {"versions": ["1.2.4"], "state": "fixed"},
        "cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "metrics": {"baseScore": 7.5}}]
      },
      "relatedVulnerabilities": [{"id": "CVE-2024-1234"}],
      "artifact": {"name": "lodash", "version": "4.17.20"}
    }
  ],
  "descriptor": {"name": "grype", "version": "0.74.0", "db": {"status": {"built": "2026-06-01T00:00:00Z", "schemaVersion": "v6.1.7"}}}
}`

func TestGrypeParseAndMap(t *testing.T) {
	var out grypeOutput
	if err := json.Unmarshal([]byte(sampleGrype), &out); err != nil {
		t.Fatal(err)
	}
	if got := out.dbLabel(); got != "schema-v6.1.7@2026-06-01T00:00:00Z" {
		t.Errorf("dbLabel = %q", got)
	}
	if len(out.Matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(out.Matches))
	}
	r := matchToRaw(out.Matches[0], nil)
	if r.Source != "grype" {
		t.Errorf("source = %q, want grype", r.Source)
	}
	if r.AdvisoryID != "CVE-2024-1234" {
		t.Errorf("AdvisoryID = %q, want the CVE (preferred over GHSA)", r.AdvisoryID)
	}
	if r.Severity != shared.SeverityHigh {
		t.Errorf("severity = %q, want high", r.Severity)
	}
	if r.Component != "lodash" || r.Version != "4.17.20" {
		t.Errorf("component = %q@%q", r.Component, r.Version)
	}
	if r.FixedVersion != "1.2.4" {
		t.Errorf("fixed = %q, want 1.2.4", r.FixedVersion)
	}
	if r.CVSSScore != 7.5 {
		t.Errorf("cvss = %v, want 7.5", r.CVSSScore)
	}
}

func TestGrypeUsesSBOMComponentNameForArtifactPURL(t *testing.T) {
	match := grypeMatch{}
	match.Vulnerability.ID = "CVE-2024-38816"
	match.Artifact.Name = "spring-webmvc"
	match.Artifact.Version = "5.3.39"
	match.Artifact.PURL = "pkg:maven/org.springframework/spring-webmvc@5.3.39?type=jar"

	components := map[string]sbom.Component{
		"pkg:maven/org.springframework/spring-webmvc@5.3.39?type=jar": {
			Name:    "org.springframework:spring-webmvc",
			Version: "5.3.39",
			PURL:    "pkg:maven/org.springframework/spring-webmvc@5.3.39?type=jar",
		},
	}
	r := matchToRaw(match, components)
	if r.Component != "org.springframework:spring-webmvc" {
		t.Fatalf("component = %q, want canonical SBOM component name", r.Component)
	}
}

// Regression #7: a missing Grype binary degrades gracefully (no error, no crash).
func TestGrypeMissingBinaryDegrades(t *testing.T) {
	s := New("synapse-no-such-grype-binary", "")
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "x", Version: "1", PURL: "pkg:npm/x@1"}}}
	raws, err := s.Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("missing binary must degrade gracefully (nil error), got %v", err)
	}
	if raws != nil {
		t.Errorf("want no findings when grype is missing, got %d", len(raws))
	}
	if v, db := s.Provenance(); v != "" || db != "" {
		t.Errorf("provenance must be empty when grype unavailable, got %q/%q", v, db)
	}
}

func TestGrypeEmptySBOM(t *testing.T) {
	s := New("grype", "")
	raws, err := s.Scan(context.Background(), &sbom.SBOM{})
	if err != nil || raws != nil {
		t.Fatalf("empty sbom: want nil,nil; got %v,%v", raws, err)
	}
}

// TestWriteCycloneDXCarriesDistro verifies the reconstructed SBOM (doc.Raw empty) puts the OS distro on
// metadata.component so Grype scopes OS-package matching to the right advisory namespace (e.g. redhat:9).
// Without it, an el9 package is matched against every RHEL stream's advisories - a large false-positive
// inflation (a clean ubi9 base went from 30 to 555 RHSA matches before this fix).
func TestWriteCycloneDXCarriesDistro(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "1:3.5.5-5.el9_8", PURL: "pkg:rpm/rhel/openssl@1:3.5.5-5.el9_8?arch=x86_64&distro=rhel-9.8"},
		{Name: "some-app", Version: "1.0.0", PURL: "pkg:golang/example.com/app@1.0.0"},
	}}
	path, cleanup, err := writeCycloneDX(doc)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatalf("SBOM has no metadata.component distro; grype cannot scope OS matching")
	}
	mc := bom.Metadata.Component
	if mc.Type != "operating-system" || mc.Name != "rhel" || mc.Version != "9.8" {
		t.Errorf("distro component = {%q %q %q}, want {operating-system rhel 9.8}", mc.Type, mc.Name, mc.Version)
	}
	props := map[string]string{}
	for _, p := range mc.Properties {
		props[p.Name] = p.Value
	}
	if props["syft:distro:id"] != "rhel" || props["syft:distro:versionID"] != "9.8" {
		t.Errorf("syft:distro props = %v, want id=rhel versionID=9.8", props)
	}
}

func TestDistroFromComponents(t *testing.T) {
	tests := []struct {
		name, purl, wantID, wantVer string
	}{
		{"rhel rpm", "pkg:rpm/rhel/openssl@1:3.5.5-5.el9_8?arch=x86_64&distro=rhel-9.8", "rhel", "9.8"},
		{"debian deb", "pkg:deb/debian/libc6@2.36?arch=amd64&distro=debian-12", "debian", "12"},
		{"ubuntu multi-dot", "pkg:deb/ubuntu/bash@5.1?distro=ubuntu-22.04", "ubuntu", "22.04"},
		{"no distro qualifier", "pkg:golang/example.com/app@1.0.0", "", ""},
		{"no qualifiers at all", "pkg:rpm/rhel/openssl@1.0", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, ver := distroFromComponents([]sbom.Component{{PURL: tc.purl}})
			if id != tc.wantID || ver != tc.wantVer {
				t.Errorf("distroFromComponents(%q) = (%q,%q), want (%q,%q)", tc.purl, id, ver, tc.wantID, tc.wantVer)
			}
		})
	}
}
