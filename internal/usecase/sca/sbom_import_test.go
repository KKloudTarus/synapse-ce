package sca

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestParseCycloneDX(t *testing.T) {
	doc := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"metadata": {
			"tools": [{"name":"CycloneDX Maven plugin","version":"2.7.10"}],
			"component": {"name": "acme-app"}
		},
		"components": [
			{"type":"library","group":"org.springframework.boot","name":"spring-boot-starter-web","version":"2.5.15","purl":"pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.15?type=jar","bom-ref":"pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.15?type=jar","licenses":[{"license":{"id":"Apache-2.0"}}]},
			{"type":"library","name":"express","version":"4.18.2","purl":"pkg:npm/express@4.18.2","bom-ref":"pkg:npm/express@4.18.2"},
			{"type":"library","name":""}
		],
		"dependencies": [
			{"ref":"pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.15?type=jar","dependsOn":["pkg:npm/express@4.18.2"]}
		]
	}`)
	parsed, err := parseCycloneDX(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.TargetRef != "acme-app" {
		t.Errorf("target = %q", parsed.TargetRef)
	}
	if parsed.SpecVersion != "1.4" || parsed.GeneratorVersion != "CycloneDX Maven plugin/2.7.10" {
		t.Errorf("spec/tool = %q/%q", parsed.SpecVersion, parsed.GeneratorVersion)
	}
	if len(parsed.Components) != 2 { // the empty-name component is skipped
		t.Fatalf("components = %d, want 2", len(parsed.Components))
	}
	if got := parsed.Components[0]; got.Name != "org.springframework.boot:spring-boot-starter-web" || got.PURL != "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.15?type=jar" {
		t.Errorf("component[0] = %+v", got)
	}
	if len(parsed.Components[0].Licenses) != 1 || parsed.Components[0].Licenses[0].SPDXID != "Apache-2.0" {
		t.Errorf("maven license = %+v", parsed.Components[0].Licenses)
	}
	if parsed.Components[0].LicenseSource != "sbom" {
		t.Errorf("license source = %q, want sbom", parsed.Components[0].LicenseSource)
	}
	if len(parsed.Dependencies) != 1 || parsed.Dependencies[0].Ref != "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.15?type=jar" || len(parsed.Dependencies[0].DependsOn) != 1 {
		t.Fatalf("dependencies = %+v", parsed.Dependencies)
	}
}

func TestParseCycloneDXIncludesMetadataComponentAndLicenseURL(t *testing.T) {
	doc := []byte(`{
		"bomFormat":"CycloneDX",
		"specVersion":"1.4",
		"metadata":{"component":{"type":"library","group":"com.hdss","name":"product-service","version":"0.0.1-SNAPSHOT","purl":"pkg:maven/com.hdss/product-service@0.0.1-SNAPSHOT?type=jar","licenses":[{"license":{"id":"Apache-2.0"}}]}},
		"components":[{"type":"library","group":"ch.qos.logback","name":"logback-core","version":"1.3.16","purl":"pkg:maven/ch.qos.logback/logback-core@1.3.16?type=jar","licenses":[{"license":{"name":"GNU Lesser General Public License","url":"http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html"}}]}]
	}`)
	parsed, err := parseCycloneDX(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Components) != 2 {
		t.Fatalf("components = %d, want metadata component + dependency", len(parsed.Components))
	}
	if got := parsed.Components[0]; got.Name != "com.hdss:product-service" || got.Version != "0.0.1-SNAPSHOT" {
		t.Fatalf("metadata component = %+v", got)
	}
	if got := parsed.Components[1].Licenses[0].Name; got != "http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html" {
		t.Fatalf("license URL = %q, want URL preserved for SPDX normalization", got)
	}
}

func TestParseCycloneDXAcceptsModernSpecVersions(t *testing.T) {
	// CycloneDX 1.5 and 1.6 are what current Syft/Trivy/cdxgen emit by default; the fields Synapse reads are
	// stable across the 1.x line, so they must parse the same as 1.4 (not be rejected).
	for _, v := range []string{"1.4", "1.5", "1.6"} {
		doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"` + v + `","metadata":{"component":{"name":"app"}},"components":[{"type":"library","name":"express","version":"4.18.2","purl":"pkg:npm/express@4.18.2"}]}`)
		parsed, err := parseCycloneDX(doc)
		if err != nil {
			t.Errorf("specVersion %s must parse, got %v", v, err)
			continue
		}
		if len(parsed.Components) != 1 || parsed.Components[0].PURL != "pkg:npm/express@4.18.2" {
			t.Errorf("specVersion %s: components = %+v", v, parsed.Components)
		}
	}
}

func TestCDXGeneratorVersionCappedAndBounded(t *testing.T) {
	// An untrusted, over-long tool name is capped (it flows to the stored + sealed manifest).
	raw := json.RawMessage(`[{"name":"` + strings.Repeat("x", 1000) + `","version":"1.0"}]`)
	if got := cdxGeneratorVersion(raw); len([]rune(got)) > 256 {
		t.Errorf("generator version must be capped to 256 runes, got %d", len([]rune(got)))
	}
	// An implausibly large tools blob yields no generator string (bounded), never a panic.
	huge := json.RawMessage(`[` + strings.Repeat(`{"name":"a"},`, 10000) + `{"name":"b"}]`)
	if got := cdxGeneratorVersion(huge); got != "" {
		t.Errorf("an oversized tools blob should yield an empty generator version, got %q", got)
	}
}

// TestCycloneDXSelfRoundTrip proves the CycloneDX exporter and importer agree: a document Synapse EMITS can
// be re-INGESTED. It caught the export(1.6)/import(1.4-only) asymmetry this change fixes.
func TestCycloneDXSelfRoundTrip(t *testing.T) {
	out, err := json.Marshal(buildCycloneDX(cdxFixtureSBOM(), "github.com/org/repo", time.Unix(0, 0).UTC()))
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	parsed, err := parseCycloneDX(out)
	if err != nil {
		t.Fatalf("re-import of own export failed: %v", err)
	}
	byPURL := map[string]bool{}
	for _, c := range parsed.Components {
		byPURL[c.PURL] = true
	}
	if !byPURL["pkg:golang/github.com/gin-gonic/gin@v1.9.1"] || !byPURL["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"] {
		t.Errorf("round-trip lost components: %+v", parsed.Components)
	}
}

func TestParseCycloneDXRejectsNonCycloneDX(t *testing.T) {
	if _, err := parseCycloneDX([]byte(`{"bomFormat":"SPDX","components":[]}`)); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("non-CycloneDX: want ErrValidation, got %v", err)
	}
	if _, err := parseCycloneDX([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}`)); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty components: want ErrValidation, got %v", err)
	}
	if _, err := parseCycloneDX([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.3","components":[{"name":"x"}]}`)); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unsupported spec (below the 1.4 floor): want ErrValidation, got %v", err)
	}
	if _, err := parseCycloneDX([]byte(`not json`)); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bad json: want ErrValidation, got %v", err)
	}
}

func TestImportSBOMStoresActiveArtifact(t *testing.T) {
	store := memory.NewImportedSBOMStore()
	svc := NewService(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, fakeIDs{}, ports.Provenance{}, fakeClock{t: time.Unix(200, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0, &fakeAcquirer{}, &fakeDetector{}, fakeSBOM{}, nil, nil, fakeLic{}, nil)
	svc.SetImportedSBOMStore(store)

	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","metadata":{"component":{"name":"product-service"}},"components":[{"group":"org.yaml","name":"snakeyaml","version":"1.28","purl":"pkg:maven/org.yaml/snakeyaml@1.28?type=jar"}],"dependencies":[{"ref":"pkg:maven/org.yaml/snakeyaml@1.28?type=jar","dependsOn":[]}]}`)
	res, err := svc.ImportSBOMFile(context.Background(), "operator", "tenant-1", "e1", "SBOM.json", data)
	if err != nil {
		t.Fatalf("ImportSBOMFile: %v", err)
	}
	if res.Target != "product-service" || len(res.SBOM.Components) != 1 || len(res.SBOM.Dependencies) != 1 {
		t.Fatalf("result target/components/deps = %q/%d/%d", res.Target, len(res.SBOM.Components), len(res.SBOM.Dependencies))
	}

	record, err := store.LatestByEngagement(context.Background(), "tenant-1", "e1")
	if err != nil {
		t.Fatalf("LatestByEngagement: %v", err)
	}
	if record.Filename != "SBOM.json" || record.SpecVersion != "1.4" || record.TargetRef != "product-service" {
		t.Fatalf("record metadata = %+v", record.Metadata())
	}
	if record.ComponentCount != 1 || record.DependencyCount != 1 || record.SHA256 == "" || string(record.RawJSON) != string(data) {
		t.Fatalf("record counts/hash/raw = %d/%d/%q/%q", record.ComponentCount, record.DependencyCount, record.SHA256, string(record.RawJSON))
	}
}
