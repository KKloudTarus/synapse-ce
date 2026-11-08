package tests

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProductionChartSecurityAndDataGovernance(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the shell chart tests are covered by Helm CI on Linux")
	}
	chartDir, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{"render_test.sh", "data_governance_test.sh"} {
		t.Run(script, func(t *testing.T) {
			cmd := exec.Command("sh", filepath.Join(chartDir, "testdata", script))
			cmd.Dir = chartDir
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("chart test %s failed: %v\n%s", script, err, output)
			}
		})
	}
}
