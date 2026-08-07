package hostinv

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
)

func TestCollectFromFixtureRoot(t *testing.T) {
	root := filepath.Join("testdata", "root")
	inv, err := Collect(context.Background(), root)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// Facts read from files under root.
	if inv.Facts.OSVersion != "12" {
		t.Fatalf("OSVersion from os-release should be 12, got %q", inv.Facts.OSVersion)
	}
	if inv.Facts.MachineID == "" {
		t.Fatalf("MachineID should be read from etc/machine-id")
	}
	if inv.Facts.OS == "" || inv.Facts.Arch == "" {
		t.Fatalf("OS/Arch should be populated from the runtime")
	}
	// Packages parsed by REUSING the engine's dpkg cataloger.
	names := map[string]bool{}
	for _, c := range inv.Packages {
		names[c.Name] = true
	}
	if !names["acl"] || !names["zlib1g"] {
		t.Fatalf("expected acl + zlib1g from the dpkg fixture, got %v", names)
	}
	// A readable dpkg DB and complete facts -> the collected package/fact data is trustworthy (not
	// degraded), even though the inventory is Incomplete because this release does not yet gather the
	// listener/service/config/source dimensions (declared as not-collected coverage).
	if inv.Degraded() {
		t.Fatalf("a readable dpkg DB must not be degraded, coverage=%v", inv.Coverage)
	}
	if inv.Complete {
		t.Fatalf("inventory must be Incomplete while listener/service/config/source are not collected")
	}
	var notCollected int
	for _, c := range inv.Coverage {
		if c.Kind == hostinventory.CoverageNotCollected {
			notCollected++
		}
		if c.Kind == hostinventory.CoverageUnreadableDB || c.Kind == hostinventory.CoverageNoPackageDB {
			t.Fatalf("readable dpkg fixture must not report a package-DB coverage failure: %v", c)
		}
	}
	if notCollected == 0 {
		t.Fatalf("deferred dimensions must be declared as not-collected coverage")
	}
}

func TestIrregularPackageDBIsDegraded(t *testing.T) {
	// A package-DB path that exists as a directory (not a regular file) must be reported as an
	// unreadable/degraded DB, not silently treated as "no DB" or "found and read".
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/lib/dpkg/status"), 0o755); err != nil {
		t.Fatal(err)
	}
	inv, err := Collect(context.Background(), root)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !inv.Degraded() {
		t.Fatalf("an irregular package-DB path must make the inventory degraded, coverage=%v", inv.Coverage)
	}
	for _, c := range inv.Coverage {
		if c.Kind == hostinventory.CoverageNoPackageDB {
			t.Fatalf("a present (irregular) DB must not also report no-package-db: %v", c)
		}
	}
}

func TestCollectNoPackageDBIsIncomplete(t *testing.T) {
	// A root with no package database and no facts must be reported incomplete, never silently empty.
	root := t.TempDir()
	inv, err := Collect(context.Background(), root)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if inv.Complete {
		t.Fatalf("a host with no package DB must be Incomplete")
	}
	var noDB bool
	for _, c := range inv.Coverage {
		if c.Kind == hostinventory.CoverageNoPackageDB {
			noDB = true
		}
	}
	if !noDB {
		t.Fatalf("expected a no-package-db coverage issue, got %v", inv.Coverage)
	}
}
