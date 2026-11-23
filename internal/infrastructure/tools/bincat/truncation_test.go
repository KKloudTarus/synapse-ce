package bincat

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withBounds narrows the walk caps for one test and restores them afterwards, so truncation is proved on a
// deterministic fixture rather than on an image large enough to reach the production caps.
func withBounds(t *testing.T, files, components int) {
	t.Helper()
	prevFiles, prevComponents := maxFilesWalked, maxComponents
	maxFilesWalked, maxComponents = files, components
	t.Cleanup(func() { maxFilesWalked, maxComponents = prevFiles, prevComponents })
}

// distInfo writes an installed Python distribution under root.
func distInfo(t *testing.T, root, name, version string) {
	t.Helper()
	dir := filepath.Join(root, "usr", "lib", "python3", name+"-"+version+".dist-info")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("Metadata-Version: 2.1\nName: %s\nVersion: %s\n", name, version)
	if err := os.WriteFile(filepath.Join(dir, "METADATA"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A catalog that stopped at its file cap found real packages and did not look everywhere. Both facts have
// to survive: the components stand, and the inventory is reported as a lower bound.
func TestFileCapTruncatesAndKeepsWhatWasFound(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 6; i++ {
		distInfo(t, root, fmt.Sprintf("pkg%d", i), "1.0.0")
	}
	withBounds(t, 3, 1000)
	report, err := Cataloger{}.CatalogInstalledReport(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Truncated {
		t.Fatal("a walk stopped by the file cap must report truncation")
	}
	if len(report.TruncationReasons) == 0 || !strings.Contains(report.TruncationReasons[0], "file-walk cap") {
		t.Fatalf("the reason must name the bound that was reached, got %v", report.TruncationReasons)
	}
	if len(report.Components) == 0 {
		t.Fatal("the packages found before the cap must be retained")
	}
	if len(report.Components) >= 6 {
		t.Fatalf("a truncated walk cannot have cataloged every package, got %d", len(report.Components))
	}
}

// The component cap is the other bound, and it is reported as its own reason.
func TestComponentCapTruncates(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 6; i++ {
		distInfo(t, root, fmt.Sprintf("pkg%d", i), "1.0.0")
	}
	withBounds(t, 1000, 2)
	report, err := Cataloger{}.CatalogInstalledReport(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Truncated {
		t.Fatal("a catalog stopped by the component cap must report truncation")
	}
	if len(report.TruncationReasons) == 0 || !strings.Contains(report.TruncationReasons[0], "component cap") {
		t.Fatalf("the reason must name the component cap, got %v", report.TruncationReasons)
	}
	if len(report.Components) != 2 {
		t.Fatalf("the cap must hold, got %d components", len(report.Components))
	}
}

// A catalog that covered the whole rootfs within its bounds reports no gap, or the warning becomes noise on
// every image.
func TestCompleteCatalogReportsNoTruncation(t *testing.T) {
	root := t.TempDir()
	distInfo(t, root, "requests", "2.31.0")
	report, err := Cataloger{}.CatalogInstalledReport(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if report.Truncated || report.Unreadable != 0 {
		t.Fatalf("a complete catalog must report no gap, got truncated=%v unreadable=%d", report.Truncated, report.Unreadable)
	}
	if len(report.Components) != 1 {
		t.Fatalf("want the one installed distribution, got %d", len(report.Components))
	}
}

// An entry the walk could not read is a package that may exist and was never examined, so it is counted.
func TestUnreadableEntriesAreCounted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits cannot stage read denial on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory, so an unreadable entry cannot be staged")
	}
	root := t.TempDir()
	distInfo(t, root, "requests", "2.31.0")
	blocked := filepath.Join(root, "opt", "blocked")
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	report, err := Cataloger{}.CatalogInstalledReport(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if report.Unreadable == 0 {
		t.Fatal("an unreadable directory must be counted, not silently skipped")
	}
	if len(report.Components) != 1 {
		t.Fatalf("the readable distribution must still be cataloged, got %d", len(report.Components))
	}
}
