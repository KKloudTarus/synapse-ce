package sbom

import (
	"os/exec"
	"strings"
	"testing"
)

// TestVendorNeutralDataSpine is the vendor-neutrality tripwire: the SBOM/vuln data
// spine – the whole business-logic surface (every internal/domain + internal/usecase package) –
// depends ONLY on the normalized domain types (sbom.SBOM, vulnerability.Vulnerability), NEVER on a
// vendor scanner / SBOM / advisory Go library. Syft/Grype/OSV are pinned BINARIES shelled via argv
// or hand-parsed JSON, and the producer adapters (internal/infrastructure/tools/*) return
// domain types – so a vendor type cannot leak into the domain. This test fails if a future import
// regresses that (e.g. someone adds `import cyclonedx-go` to a use case), keeping detection
// independence (the moat: "not dependent on any one scanner"). Best-effort: skips without the toolchain.
func TestVendorNeutralDataSpine(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}",
		"github.com/KKloudTarus/synapse-ce/internal/domain/...",
		"github.com/KKloudTarus/synapse-ce/internal/usecase/...",
	).CombinedOutput()
	if err != nil {
		t.Skipf("go toolchain unavailable for the dependency scan (%v); the boundary is otherwise structural (vendors are binaries, not libraries)", err)
	}
	// Vendor scanner / SBOM / advisory Go libraries the business logic must NEVER import directly – they
	// belong behind a producer port in internal/infrastructure/tools/*, returning normalized domain types.
	forbidden := []string{
		"github.com/anchore/",           // syft + grype as Go libraries (we shell the binaries instead)
		"github.com/CycloneDX/",         // cyclonedx-go (we hand-parse the JSON in the adapter)
		"github.com/spdx/",              // spdx tools-golang
		"github.com/aquasecurity/",      // trivy
		"github.com/google/osv-scanner", // osv-scanner as a library (we query/parse OSV ourselves)
		"github.com/google/osv-scalibr", // osv-scalibr (Google's SBOM/extractor lib) – the likeliest future leak
	}
	// Floor: the scan must actually have run (the domain/sbom package itself must appear), so a future
	// go-list flag/format change can't silently turn this green.
	if !strings.Contains(string(out), "KKloudTarus/synapse-ce/internal/domain/sbom") {
		t.Fatalf("go list produced no expected packages – the vendor-neutral scan did not run: %.200q", out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		for _, bad := range forbidden {
			if strings.HasPrefix(dep, bad) {
				t.Errorf("business logic transitively imports vendor SBOM/scanner library %q – the data spine must stay vendor-neutral: confine vendor parsing to internal/infrastructure/tools/* behind a producer port that returns domain types", dep)
			}
		}
	}
}
