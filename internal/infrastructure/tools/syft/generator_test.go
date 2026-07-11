package syft

import "testing"

const cdxFixture = `{
  "components": [
    {"name":"github.com/go-enry/go-enry/v2","version":"v2.9.6","purl":"pkg:golang/github.com/go-enry/go-enry/v2@v2.9.6"},
    {"name":"express","version":"4.18.2","purl":"pkg:npm/express@4.18.2","licenses":[{"license":{"id":"MIT"}}]},
    {"name":"some-pkg","version":"1.0.0","purl":"pkg:npm/some-pkg@1.0.0","licenses":[{"expression":"(MIT OR Apache-2.0)"}]},
    {"name":"/tmp/scan/go.mod","version":"","purl":""}
  ]
}`

func TestParseCycloneDXLayerID(t *testing.T) {
	// An image-scan component carries syft:location:N:path +:layerID; the layerID of the
	// chosen primary location must be recovered onto Component.LayerID (Epic D attribution).
	data := `{"components":[{
		"name":"openssl","version":"1.1","purl":"pkg:deb/debian/openssl@1.1",
		"properties":[
			{"name":"syft:location:0:path","value":"/var/lib/dpkg/status"},
			{"name":"syft:location:0:layerID","value":"sha256:baselayer"}
		]
	}]}`
	comps, _, _, err := parseCycloneDX([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("want 1 component, got %d", len(comps))
	}
	if comps[0].LayerID != "sha256:baselayer" {
		t.Errorf("LayerID = %q, want sha256:baselayer", comps[0].LayerID)
	}
	if comps[0].Location != "/var/lib/dpkg/status" {
		t.Errorf("Location = %q", comps[0].Location)
	}
}

func TestParseCycloneDXNoLayerID(t *testing.T) {
	// A source (non-image) scan has paths but no layerID – LayerID stays empty, no attribution.
	data := `{"components":[{"name":"p","version":"1","purl":"pkg:npm/p@1",
		"properties":[{"name":"syft:location:0:path","value":"package.json"}]}]}`
	comps, _, _, err := parseCycloneDX([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 1 || comps[0].LayerID != "" {
		t.Errorf("want empty LayerID for source scan, got %+v", comps)
	}
}

func TestParseCycloneDXComponents(t *testing.T) {
	comps, _, _, err := parseCycloneDX([]byte(cdxFixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The 4th entry (no version, no purl) must be filtered out.
	if len(comps) != 3 {
		t.Fatalf("want 3 components, got %d: %+v", len(comps), comps)
	}
	if comps[0].Name != "github.com/go-enry/go-enry/v2" || comps[0].PURL == "" {
		t.Errorf("component[0] = %+v", comps[0])
	}
	if len(comps[1].Licenses) != 1 || comps[1].Licenses[0].SPDXID != "MIT" {
		t.Errorf("express license = %+v", comps[1].Licenses)
	}
	if len(comps[2].Licenses) != 1 || comps[2].Licenses[0].Name != "(MIT OR Apache-2.0)" {
		t.Errorf("expression license = %+v", comps[2].Licenses)
	}
}

func TestParseCycloneDXEmpty(t *testing.T) {
	comps, _, _, err := parseCycloneDX([]byte(`{"components":[]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if comps == nil {
		t.Fatal("want non-nil empty slice")
	}
	if len(comps) != 0 {
		t.Fatalf("want 0 components, got %d", len(comps))
	}
}

func TestParseCycloneDXInvalid(t *testing.T) {
	if _, _, _, err := parseCycloneDX([]byte("not json")); err == nil {
		t.Fatal("want error for invalid json")
	}
}

func TestParseCycloneDXLicenseNameFallback(t *testing.T) {
	data := `{"components":[{"name":"p","version":"1","purl":"pkg:npm/p@1","licenses":[{"license":{"name":"BSD-3-Clause"}}]}]}`
	comps, _, _, err := parseCycloneDX([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 1 || len(comps[0].Licenses) != 1 {
		t.Fatalf("want 1 component with 1 license, got %+v", comps)
	}
	if comps[0].Licenses[0].Name != "BSD-3-Clause" || comps[0].Licenses[0].SPDXID != "" {
		t.Errorf("license name fallback = %+v", comps[0].Licenses[0])
	}
}

func TestParseCycloneDXLicenseURLPreferredOverName(t *testing.T) {
	data := `{"components":[{"name":"logback-core","version":"1.3.16","purl":"pkg:maven/ch.qos.logback/logback-core@1.3.16?type=jar","licenses":[{"license":{"name":"GNU Lesser General Public License","url":"http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html"}}]}]}`
	comps, _, _, err := parseCycloneDX([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 1 || len(comps[0].Licenses) != 1 {
		t.Fatalf("want 1 component with 1 license, got %+v", comps)
	}
	if got := comps[0].Licenses[0].Name; got != "http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html" {
		t.Fatalf("license = %q, want URL for SPDX normalization", got)
	}
}

func TestSyftVersionFromMetadata(t *testing.T) {
	// CycloneDX 1.5+ object form: metadata.tools.components[]
	if _, _, v, err := parseCycloneDX([]byte(`{"metadata":{"tools":{"components":[{"name":"syft","version":"1.45.1"}]}},"components":[]}`)); err != nil || v != "1.45.1" {
		t.Errorf("object form version = %q (err %v), want 1.45.1", v, err)
	}
	// CycloneDX 1.4 array form: metadata.tools[]
	if _, _, v, err := parseCycloneDX([]byte(`{"metadata":{"tools":[{"name":"syft","version":"1.0.0"}]},"components":[]}`)); err != nil || v != "1.0.0" {
		t.Errorf("array form version = %q (err %v), want 1.0.0", v, err)
	}
	// no tools metadata → empty version, no error
	if _, _, v, err := parseCycloneDX([]byte(`{"components":[]}`)); err != nil || v != "" {
		t.Errorf("missing-tools version = %q (err %v), want empty", v, err)
	}
}

func TestParseCycloneDXDependencies(t *testing.T) {
	data := `{
	  "components": [
	    {"bom-ref":"ref-a","name":"a","version":"1","purl":"pkg:npm/a@1"},
	    {"bom-ref":"ref-b","name":"b","version":"2","purl":"pkg:npm/b@2"},
	    {"bom-ref":"ref-main","name":"/tmp/app","version":"","purl":""}
	  ],
	  "dependencies": [
	    {"ref":"ref-a","dependsOn":["ref-b","ref-main"]},
	    {"ref":"ref-main","dependsOn":["ref-a"]}
	  ]
	}`
	_, deps, _, err := parseCycloneDX([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// ref-main has no package identity and is filtered out, so the a->[b,main]
	// edge keeps only a->b, and the main->a edge is dropped entirely.
	if len(deps) != 1 {
		t.Fatalf("want 1 edge, got %d: %+v", len(deps), deps)
	}
	if deps[0].Ref != "pkg:npm/a@1" || len(deps[0].DependsOn) != 1 || deps[0].DependsOn[0] != "pkg:npm/b@2" {
		t.Errorf("edge = %+v, want a@1 -> [b@2]", deps[0])
	}
}

func TestParseCycloneDXDependencyDedup(t *testing.T) {
	// r1 and r2 share a PURL; the self-reference (r1->r2 collapses to a@1->a@1)
	// must be dropped and the duplicated target must appear once.
	data := `{
	  "components": [
	    {"bom-ref":"r1","name":"a","version":"1","purl":"pkg:npm/a@1"},
	    {"bom-ref":"r2","name":"a","version":"1","purl":"pkg:npm/a@1"},
	    {"bom-ref":"rb","name":"b","version":"1","purl":"pkg:npm/b@1"}
	  ],
	  "dependencies": [
	    {"ref":"r1","dependsOn":["r2","rb","rb"]}
	  ]
	}`
	_, deps, _, err := parseCycloneDX([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("want 1 edge group, got %d: %+v", len(deps), deps)
	}
	if len(deps[0].DependsOn) != 1 || deps[0].DependsOn[0] != "pkg:npm/b@1" {
		t.Errorf("dependsOn = %+v, want [pkg:npm/b@1] (self-edge + dup dropped)", deps[0].DependsOn)
	}
}
