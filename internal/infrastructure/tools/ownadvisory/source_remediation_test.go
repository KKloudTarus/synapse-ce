package ownadvisory

import (
	"context"
	"slices"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestScanFixedVersionUsesApplicableArchitectureRanges(t *testing.T) {
	bounded := func(arches []string, fixed string) advisory.AffectedPackage {
		return advisory.AffectedPackage{
			Ecosystem:     "SUSE:15.6",
			Package:       "libacl1",
			Architectures: arches,
			Ranges:        []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
			FixedVersion:  fixed,
		}
	}
	for _, test := range []struct {
		name         string
		blocks       []advisory.AffectedPackage
		arch         string
		wantFix      string
		wantValid    []string
		wantRejected []string
		wantHits     int
	}{
		{
			name:      "disjoint x86_64 boundary",
			blocks:    []advisory.AffectedPackage{bounded([]string{"x86_64"}, "0:2-1"), bounded([]string{"aarch64"}, "0:3-1")},
			arch:      "x86_64",
			wantFix:   "0:2-1",
			wantValid: []string{"0:2-1"},
			wantHits:  1,
		},
		{
			name:      "disjoint aarch64 boundary",
			blocks:    []advisory.AffectedPackage{bounded([]string{"x86_64"}, "0:2-1"), bounded([]string{"aarch64"}, "0:3-1")},
			arch:      "aarch64",
			wantFix:   "0:3-1",
			wantValid: []string{"0:3-1"},
			wantHits:  1,
		},
		{
			name:         "overlapping x86_64 boundary",
			blocks:       []advisory.AffectedPackage{bounded([]string{"x86_64"}, "0:2-1"), bounded([]string{"aarch64", "x86_64"}, "0:3-1")},
			arch:         "x86_64",
			wantFix:      "0:3-1",
			wantValid:    []string{"0:3-1"},
			wantRejected: []string{"0:2-1"},
			wantHits:     1,
		},
		{
			name:     "missing architecture fails closed",
			blocks:   []advisory.AffectedPackage{bounded([]string{"x86_64"}, "0:2-1")},
			wantHits: 0,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			adv := advisory.Advisory{ID: "CVE-2026-54369", Affected: test.blocks}
			store := memStore{byKey: map[string][]advisory.Advisory{"SUSE:15.6|libacl1": {adv}}}
			purl := "pkg:rpm/sles/libacl1@1-1?distro=sles-15.6"
			if test.arch != "" {
				purl += "&arch=" + test.arch
			}
			doc := &sbom.SBOM{Components: []sbom.Component{{Name: "libacl1", Version: "1-1", PURL: purl}}}
			findings, err := New(store).Scan(context.Background(), doc)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != test.wantHits {
				t.Fatalf("findings = %+v, want %d", findings, test.wantHits)
			}
			if test.wantHits == 1 && findings[0].FixedVersion != test.wantFix {
				t.Errorf("fixed version = %q, want %q; finding=%+v", findings[0].FixedVersion, test.wantFix, findings[0])
			}
			if test.wantHits == 1 && (!slices.Equal(findings[0].FixedVersions, test.wantValid) ||
				!slices.Equal(findings[0].RejectedFixedVersions, test.wantRejected)) {
				t.Errorf("candidate versions = %v rejected = %v, want valid %v rejected %v",
					findings[0].FixedVersions, findings[0].RejectedFixedVersions, test.wantValid, test.wantRejected)
			}
		})
	}
}

func TestScanRejectsFixedCandidateStillListedAsAffected(t *testing.T) {
	adv := advisory.Advisory{
		ID: "CVE-2026-54369",
		Affected: []advisory.AffectedPackage{
			{
				Ecosystem: "SUSE:15.6", Package: "libacl1", Architectures: []string{"x86_64"},
				Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "0:2-1"}}}},
				FixedVersion: "0:2-1",
			},
			{
				Ecosystem: "SUSE:15.6", Package: "libacl1", Architectures: []string{"x86_64"},
				Versions: []string{"0:2-1"},
			},
		},
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"SUSE:15.6|libacl1": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{{
		Name: "libacl1", Version: "1-1", PURL: "pkg:rpm/sles/libacl1@1-1?distro=sles-15.6&arch=x86_64",
	}}}
	findings, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want one affected finding, got %+v", findings)
	}
	if findings[0].FixedVersion != "" || !slices.Equal(findings[0].RejectedFixedVersions, []string{"0:2-1"}) {
		t.Fatalf("candidate remains explicitly affected and cannot be a fix: %+v", findings[0])
	}
}

func TestScanRejectsFixedCandidateBelowInstalledRPMEpoch(t *testing.T) {
	bounded := func(introduced, fixed string) advisory.AffectedPackage {
		return advisory.AffectedPackage{
			Ecosystem: "SUSE:15.6", Package: "libacl1", Architectures: []string{"x86_64"},
			Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: introduced}, {Fixed: fixed}}}},
			FixedVersion: fixed,
		}
	}
	adv := advisory.Advisory{
		ID: "CVE-2026-54369",
		Affected: []advisory.AffectedPackage{
			bounded("0", "0:9-1"),
			bounded("1:0-1", "1:2-1"),
		},
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"SUSE:15.6|libacl1": {adv}}}
	for _, version := range []string{"1-1", "1:1-1"} {
		t.Run(version, func(t *testing.T) {
			doc := &sbom.SBOM{Components: []sbom.Component{{
				Name: "libacl1", Version: version, PURL: "pkg:rpm/sles/libacl1@1-1?distro=sles-15.6&arch=x86_64&epoch=1",
			}}}
			findings, err := New(store).Scan(context.Background(), doc)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 {
				t.Fatalf("want one affected finding, got %+v", findings)
			}
			if findings[0].Ecosystem != "SUSE:15.6" ||
				findings[0].FixedVersion != "1:2-1" ||
				!slices.Equal(findings[0].FixedVersions, []string{"1:2-1"}) ||
				!slices.Equal(findings[0].RejectedFixedVersions, []string{"0:9-1"}) {
				t.Fatalf("fix must be above installed epoch 1:1-1: %+v", findings[0])
			}
		})
	}
}

func TestScanSourceMatchUsesSourceVersionForRemediation(t *testing.T) {
	adv := advisory.Advisory{
		ID: "CVE-2024-UPV",
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "Debian:11", Package: "openssl",
			Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.1.1m"}}}},
			FixedVersion: "1.1.1m",
		}},
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"Debian:11|openssl": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{{
		Name: "libssl1.1", Version: "1.1.1n",
		PURL: "pkg:deb/debian/libssl1.1@1.1.1n?distro=debian-11&upstream=openssl%401.1.1k",
	}}}
	findings, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].FixedVersion != "1.1.1m" {
		t.Fatalf("source-keyed advisory must validate remediation against source version: %+v", findings)
	}
	correlated := vulnerability.Correlate(findings)
	if len(correlated) != 1 || correlated[0].FixedVersion != "" ||
		correlated[0].FixStatus != vulnerability.FixStatusAdvisoryInvalid {
		t.Fatalf("source fix older than installed binary cannot become an upgrade: %+v", correlated)
	}
}

func TestScanWithholdsRemediationForContradictoryPURL(t *testing.T) {
	adv := advisory.Advisory{
		ID: "CVE-2026-54369",
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "SUSE:15.6", Package: "libacl1", Architectures: []string{"x86_64"},
			Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "0:2-1"}}}},
			FixedVersion: "0:2-1",
		}},
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"SUSE:15.6|libacl1": {adv}}}
	for _, purl := range []string{
		"pkg:rpm/sles/libacl1@9-9?distro=sles-15.6&arch=x86_64",
		"pkg:rpm/sles/other@1-1?distro=sles-15.6&arch=x86_64",
	} {
		t.Run(purl, func(t *testing.T) {
			doc := &sbom.SBOM{Components: []sbom.Component{{Name: "libacl1", Version: "1-1", PURL: purl}}}
			findings, err := New(store).Scan(context.Background(), doc)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 {
				t.Fatalf("want existing detection retained, got %+v", findings)
			}
			if findings[0].FixedVersion != "" || len(findings[0].FixedVersions) != 0 {
				t.Fatalf("contradictory component and PURL cannot justify a fix: %+v", findings[0])
			}
		})
	}
}

func TestRemediationWithholdsUnverifiedFixFromLargeVersionList(t *testing.T) {
	versions := make([]string, maxRemediationVersionComparisons+1)
	for index := range versions {
		versions[index] = "0:99-1"
	}
	adv := advisory.Advisory{Affected: []advisory.AffectedPackage{
		{
			Ecosystem: "SUSE:15.6", Package: "libacl1", Architectures: []string{"x86_64"},
			Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "0:2-1"}}}},
			FixedVersion: "0:2-1",
		},
		{
			Ecosystem: "SUSE:15.6", Package: "libacl1", Architectures: []string{"x86_64"},
			Versions: versions,
		},
	}}
	valid, rejected := ownedFixedVersions(
		adv,
		sbom.ComponentIdentity{Ecosystem: "SUSE:15.6", Package: "libacl1", Version: "0:1-1"},
		"x86_64",
		"0:2-1",
	)
	if len(valid) != 0 || !slices.Equal(rejected, []string{"0:2-1"}) {
		t.Fatalf("large explicit version list must withhold unverified remediation: valid=%v rejected=%v", valid, rejected)
	}
}

func TestScanCPEFixCannotDowngradeRPMPastInstalledEpoch(t *testing.T) {
	adv := advisory.Advisory{
		ID: "CVE-2026-54369",
		CPEs: []advisory.CPEMatch{{
			Criteria:            "cpe:2.3:a:libacl1:libacl1:*:*:*:*:*:*:*:*",
			Vulnerable:          true,
			VersionEndExcluding: "2-1",
		}},
	}
	store := cpeMemStore{byCPE: map[string][]advisory.Advisory{"a|libacl1|libacl1": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{{
		Name: "libacl1", Version: "1-1",
		PURL: "pkg:rpm/sles/libacl1@1-1?distro=sles-15.6&epoch=1",
		CPE:  "cpe:2.3:a:libacl1:libacl1:1-1:*:*:*:*:*:*:*",
	}}}
	findings, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want one CPE finding, got %+v", findings)
	}
	if findings[0].FixedVersion != "" || len(findings[0].FixedVersions) != 0 ||
		!slices.Equal(findings[0].RejectedFixedVersions, []string{"2-1"}) {
		t.Fatalf("older RPM epoch cannot be a fix: %+v", findings[0])
	}
}

func TestCPEFixUsesCoherentComponentIdentity(t *testing.T) {
	for _, test := range []struct {
		name    string
		item    sbom.Component
		hint    string
		wantFix string
		wantEco string
	}{
		{
			name: "valid RPM epoch representation",
			item: sbom.Component{
				Name: "libacl1", Version: "1:1-1",
				PURL: "pkg:rpm/sles/libacl1@1-1?distro=sles-15.6&epoch=1",
			},
			hint: "1:2-1", wantFix: "1:2-1", wantEco: "SUSE:15.6",
		},
		{
			name: "Maven artifact name",
			item: sbom.Component{
				Name: "logback-core", Version: "1.3.16",
				PURL: "pkg:maven/ch.qos.logback/logback-core@1.3.16",
			},
			hint: "1.3.17", wantFix: "1.3.17", wantEco: "Maven",
		},
		{
			name: "contradictory Maven artifact",
			item: sbom.Component{
				Name: "other", Version: "1.3.16",
				PURL: "pkg:maven/ch.qos.logback/logback-core@1.3.16",
			},
			hint: "1.3.17",
		},
		{
			name: "contradictory non-RPM package",
			item: sbom.Component{
				Name: "other", Version: "1.0.0",
				PURL: "pkg:npm/foo@1.0.0",
			},
			hint: "2.0.0",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			finding := rawFinding(advisory.Advisory{ID: "CVE-2026-54369"}, test.item, test.hint, nil, nil)
			if finding.FixedVersion != test.wantFix {
				t.Fatalf("fixed version = %q, want %q; finding=%+v", finding.FixedVersion, test.wantFix, finding)
			}
			if test.wantEco != "" && finding.Ecosystem != test.wantEco {
				t.Fatalf("ecosystem = %q, want %q; finding=%+v", finding.Ecosystem, test.wantEco, finding)
			}
		})
	}
}

func TestScanCPEMavenArtifactNameKeepsFix(t *testing.T) {
	advisoryRecord := advisory.Advisory{
		ID: "CVE-2026-54369",
		CPEs: []advisory.CPEMatch{{
			Criteria:            "cpe:2.3:a:logback:logback-core:*:*:*:*:*:*:*:*",
			Vulnerable:          true,
			VersionEndExcluding: "1.3.17",
		}},
	}
	store := cpeMemStore{byCPE: map[string][]advisory.Advisory{"a|logback|logback-core": {advisoryRecord}}}
	doc := &sbom.SBOM{Components: []sbom.Component{{
		Name: "logback-core", Version: "1.3.16",
		PURL: "pkg:maven/ch.qos.logback/logback-core@1.3.16",
		CPE:  "cpe:2.3:a:logback:logback-core:1.3.16:*:*:*:*:*:*:*",
	}}}
	findings, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Ecosystem != "Maven" || findings[0].FixedVersion != "1.3.17" {
		t.Fatalf("CPE finding should retain coherent Maven remediation: %+v", findings)
	}
}

func TestScanMavenArtifactNameUsesPURLPackageKey(t *testing.T) {
	const packageKey = "ch.qos.logback:logback-core"
	advisoryRecord := advisory.Advisory{
		ID: "CVE-2026-54369",
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "Maven", Package: packageKey,
			Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.3.17"}}}},
			FixedVersion: "1.3.17",
		}},
	}
	contradictoryRecord := advisoryRecord
	contradictoryRecord.Affected = append([]advisory.AffectedPackage(nil), advisoryRecord.Affected...)
	contradictoryRecord.Affected[0].Package = "evil:lib"
	store := memStore{byKey: map[string][]advisory.Advisory{
		"Maven|" + packageKey: {advisoryRecord},
		"Maven|evil:lib":      {contradictoryRecord},
	}}
	for _, test := range []struct {
		name         string
		component    string
		wantFindings int
	}{
		{name: "artifact name", component: "logback-core", wantFindings: 1},
		{name: "full coordinate", component: packageKey, wantFindings: 1},
		{name: "different artifact", component: "other", wantFindings: 0},
		{name: "contradictory full coordinate", component: "evil:lib", wantFindings: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc := &sbom.SBOM{Components: []sbom.Component{{
				Name: test.component, Version: "1.3.16",
				PURL: "pkg:maven/ch.qos.logback/logback-core@1.3.16",
			}}}
			findings, err := New(store).Scan(context.Background(), doc)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != test.wantFindings {
				t.Fatalf("findings = %+v, want %d", findings, test.wantFindings)
			}
			if test.wantFindings == 1 && (findings[0].Ecosystem != "Maven" || findings[0].FixedVersion != "1.3.17") {
				t.Fatalf("Maven package hit must retain fix: %+v", findings[0])
			}
		})
	}
}
