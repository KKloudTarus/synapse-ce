package ownadvisory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestParseOSVMarksWithdrawn(t *testing.T) {
	withdrawn := `{"id":"GHSA-x","aliases":["CVE-2018-16487"],"summary":"retracted","withdrawn":"2021-03-01T00:00:00Z",
		"affected":[{"package":{"ecosystem":"npm","name":"event-stream"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.0.0"}]}]}]}`
	adv, err := ParseOSV([]byte(withdrawn))
	if err != nil {
		t.Fatalf("parse withdrawn: %v", err)
	}
	if !adv.Withdrawn {
		t.Fatal("withdrawn advisory must set Advisory.Withdrawn = true")
	}

	active := `{"id":"GHSA-y","summary":"active","affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.12"}]}]}]}`
	adv2, err := ParseOSV([]byte(active))
	if err != nil {
		t.Fatalf("parse active: %v", err)
	}
	if adv2.Withdrawn {
		t.Fatal("advisory with no withdrawn timestamp must be active")
	}
}

func TestScanSkipsWithdrawnAdvisory(t *testing.T) {
	adv := advisory.Advisory{
		ID: "CVE-2018-16487", Summary: "retracted", CVSSScore: 9.8, Withdrawn: true,
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "npm", Package: "event-stream", FixedVersion: "4.0.0",
			Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "4.0.0"}}}},
		}},
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"npm|event-stream": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		// 3.3.5 is inside [0,4.0.0), so a non-withdrawn advisory WOULD match; the withdrawn flag must skip it.
		{Name: "event-stream", Version: "3.3.5", PURL: "pkg:npm/event-stream@3.3.5"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 0 {
		t.Fatalf("withdrawn advisory must produce no finding, got %+v", raws)
	}
}
