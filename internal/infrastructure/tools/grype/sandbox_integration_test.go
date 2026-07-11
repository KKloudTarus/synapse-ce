package grype_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/grype"
)

// TestGrypeSandboxedMatchesDirect proves for Grype that matching against the
// pinned DB inside the sandbox yields the SAME findings as a direct exec. Needs grype +
// bubblewrap + a pre-synced DB on the host.
func TestGrypeSandboxedMatchesDirect(t *testing.T) {
	if _, err := exec.LookPath("grype"); err != nil {
		t.Skip("grype not installed")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}
	dbDir := filepath.Join(os.Getenv("HOME"), ".cache", "grype", "db")
	if _, err := os.Stat(dbDir); err != nil {
		t.Skipf("grype DB not at %s (run `grype db update`)", dbDir)
	}
	// lodash 4.17.4 has known advisories – a stable, offline match.
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.4", PURL: "pkg:npm/lodash@4.17.4"}}}
	ctx := context.Background()

	direct, err := grype.New("grype", dbDir).Scan(ctx, doc)
	if err != nil {
		t.Fatalf("direct grype: %v", err)
	}
	if len(direct) == 0 {
		t.Fatal("direct grype found 0 vulns for lodash@4.17.4 – DB/setup problem")
	}
	sb, err := sandbox.NewRunner(2*time.Minute, 16<<20, 512<<20, 256)
	if err != nil {
		t.Fatalf("sandbox: %v", err)
	}
	sandboxed, err := grype.New("grype", dbDir).WithRunner(sb).Scan(ctx, doc)
	if err != nil {
		t.Fatalf("sandboxed grype: %v", err)
	}
	d, x := advisorySet(direct), advisorySet(sandboxed)
	if !equalStr(d, x) {
		t.Errorf("sandboxed grype findings differ from direct:\n direct(%d)=%v\n sandbox(%d)=%v", len(d), d, len(x), x)
	}
}

func advisorySet(fs []vulnerability.RawFinding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.AdvisoryID)
	}
	sort.Strings(out)
	return out
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
