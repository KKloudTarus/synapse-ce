package hostinventory

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestNormalizeCompleteAndOrder(t *testing.T) {
	// No coverage issues -> complete, packages sorted.
	h := HostInventory{Packages: []sbom.Component{{Name: "zlib", Version: "1"}, {Name: "acl", Version: "2"}}}
	n := h.Normalize()
	if !n.Complete {
		t.Fatalf("no coverage issues must be Complete")
	}
	if n.Packages[0].Name != "acl" || n.Packages[1].Name != "zlib" {
		t.Fatalf("packages must be sorted by name, got %v", n.Packages)
	}

	// Any coverage issue -> incomplete.
	h2 := HostInventory{}
	h2.AddIssue(CoverageUnreadableDB, "/var/lib/rpm unreadable")
	n2 := h2.Normalize()
	if n2.Complete {
		t.Fatalf("a coverage issue must make the inventory incomplete")
	}
}

func TestCoverageKindValid(t *testing.T) {
	for _, k := range []CoverageKind{CoverageUnreadableDB, CoverageNoPackageDB, CoverageUnsupportedPlatform, CoverageMissingFact, CoverageNotCollected} {
		if !k.Valid() {
			t.Errorf("%q should be valid", k)
		}
	}
	if CoverageKind("bogus").Valid() {
		t.Errorf("bogus should be invalid")
	}
}

func TestDegradedVsInformationalCoverage(t *testing.T) {
	// Only an unreadable DB poisons collected data; expected gaps do not.
	if !CoverageUnreadableDB.Degraded() {
		t.Errorf("an unreadable package DB must be degraded")
	}
	for _, k := range []CoverageKind{CoverageNoPackageDB, CoverageUnsupportedPlatform, CoverageMissingFact, CoverageNotCollected} {
		if k.Degraded() {
			t.Errorf("%q is an expected gap, must not be degraded", k)
		}
	}

	// An inventory with only not-collected gaps is incomplete but NOT degraded.
	var incomplete HostInventory
	incomplete.AddIssue(CoverageNotCollected, "running-services")
	if incomplete.IsComplete() {
		t.Errorf("a not-collected gap must make the inventory incomplete")
	}
	if incomplete.Degraded() {
		t.Errorf("a not-collected gap must not be degraded")
	}

	// One unreadable DB makes it degraded.
	var bad HostInventory
	bad.AddIssue(CoverageNotCollected, "running-services")
	bad.AddIssue(CoverageUnreadableDB, "/var/lib/rpm unreadable")
	if !bad.Degraded() {
		t.Errorf("an unreadable DB must make the inventory degraded")
	}
}
