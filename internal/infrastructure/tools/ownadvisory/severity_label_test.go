package ownadvisory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestParseOSVSeverityFromLabel(t *testing.T) {
	// A GHSA/OSV advisory with a database_specific.severity label and NO CVSS vector.
	doc := `{"id":"GHSA-z","aliases":["CVE-2024-2"],"summary":"label only","database_specific":{"severity":"HIGH"},
		"affected":[{"package":{"ecosystem":"npm","name":"foo"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`
	adv, err := ParseOSV([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if adv.Severity != shared.SeverityHigh {
		t.Fatalf("advisory band = %q, want high (from label)", adv.Severity)
	}
	if adv.CVSSScore != 0 {
		t.Fatalf("label-only advisory should have no computed score, got %v", adv.CVSSScore)
	}
}

func TestScanUsesLabelBandWhenNoScore(t *testing.T) {
	adv := advisory.Advisory{
		ID: "CVE-2024-2", Summary: "label only", Severity: shared.SeverityHigh,
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "npm", Package: "foo", FixedVersion: "2.0.0",
			Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}},
		}},
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"npm|foo": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "foo", Version: "1.0.0", PURL: "pkg:npm/foo@1.0.0"}}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 || raws[0].Severity != shared.SeverityHigh {
		t.Fatalf("finding must carry the label band (high), got %+v", raws)
	}
}
