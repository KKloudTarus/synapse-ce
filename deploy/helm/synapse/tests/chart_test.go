package tests

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProductionChartRendersWithRequiredSecurityPosture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the shell chart test is covered by Helm CI on Linux")
	}
	chartDir, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", filepath.Join(chartDir, "testdata", "render_test.sh"))
	cmd.Dir = chartDir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("chart render test failed: %v\n%s", err, output)
	}
}
