package ownadvisory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestParseOSVv4Vector covers D1.5/D1.6: a v4-only OSV advisory (no v3 vector, no label) is scored
// from its CVSS:4.0 vector so it carries a numeric score offline instead of falling to Unknown.
func TestParseOSVv4Vector(t *testing.T) {
	doc := `{"id":"GHSA-v4","aliases":["CVE-2025-9"],"summary":"v4 only",
		"severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
		"affected":[{"package":{"ecosystem":"npm","name":"bar"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"3.0.0"}]}]}]}`
	adv, err := ParseOSV([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if adv.CVSSVector != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" {
		t.Fatalf("v4 vector not retained: %q", adv.CVSSVector)
	}
	if adv.CVSSScore < 9.29 || adv.CVSSScore > 9.31 { // reference score 9.3
		t.Fatalf("v4 score = %v, want 9.3", adv.CVSSScore)
	}
}

// TestParseOSVPrefersV3OverV4 asserts an advisory carrying both a v3 and a v4 vector keeps the v3
// vector and v3 score, so a corpus that historically banded on v3 does not shift.
func TestParseOSVPrefersV3OverV4(t *testing.T) {
	doc := `{"id":"GHSA-both","summary":"v3 and v4",
		"severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
			{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"}],
		"affected":[{"package":{"ecosystem":"npm","name":"bar"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"3.0.0"}]}]}]}`
	adv, err := ParseOSV([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if adv.CVSSVector != "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" {
		t.Fatalf("v3 must win over v4: %q", adv.CVSSVector)
	}
	if adv.CVSSScore < 3.6 || adv.CVSSScore > 3.8 { // v3.1 score 3.7
		t.Fatalf("score = %v, want 3.7 (v3)", adv.CVSSScore)
	}
}

// TestScanBandsV4VectorWithoutStoredScore covers the offline scan path: a stored advisory that has a
// v4 vector but no precomputed score must still band the finding (source.go derives it via the
// version-agnostic CVSSBaseScore), not leave it Unknown.
func TestScanBandsV4VectorWithoutStoredScore(t *testing.T) {
	adv := advisory.Advisory{
		ID: "CVE-2025-9", Summary: "v4 vector, no stored score",
		CVSSVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", // 9.3 -> critical
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "npm", Package: "bar", FixedVersion: "3.0.0",
			Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "3.0.0"}}}},
		}},
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"npm|bar": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "bar", Version: "1.0.0", PURL: "pkg:npm/bar@1.0.0"}}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("want 1 finding, got %d", len(raws))
	}
	if raws[0].Severity != shared.SeverityCritical {
		t.Fatalf("v4 vector must band to critical (9.3), got %q", raws[0].Severity)
	}
	if raws[0].CVSSScore < 9.29 || raws[0].CVSSScore > 9.31 {
		t.Fatalf("finding score = %v, want 9.3", raws[0].CVSSScore)
	}
}

// TestParseOSVMalformedV3FallsBackToV4 covers the Codex-flagged false-suppression case: an advisory
// carrying a MALFORMED v3 vector and a valid v4 vector must be scored from the v4 vector, never left
// Unknown because the v3 string was present but unscorable.
func TestParseOSVMalformedV3FallsBackToV4(t *testing.T) {
	doc := `{"id":"GHSA-badv3","summary":"malformed v3 plus valid v4",
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:Z/AC:bogus"},
			{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
		"affected":[{"package":{"ecosystem":"npm","name":"bar"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"3.0.0"}]}]}]}`
	adv, err := ParseOSV([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if adv.CVSSVector != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" {
		t.Fatalf("must fall back to the scorable v4 vector, got %q", adv.CVSSVector)
	}
	if adv.CVSSScore < 9.29 || adv.CVSSScore > 9.31 {
		t.Fatalf("v4 score = %v, want 9.3", adv.CVSSScore)
	}
}
