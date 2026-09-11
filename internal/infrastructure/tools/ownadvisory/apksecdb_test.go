package ownadvisory

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

// TestParseSecdbWolfiFixture parses a real (trimmed) Wolfi secdb: advisories are keyed by CVE and ecosystem
// "Wolfi", a "0" secfix (triaged NOT affected) never becomes a range, and a package whose only entry is "0"
// yields no advisory.
func TestParseSecdbWolfiFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "wolfi-secdb.json"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseSecdb(data)
	if err != nil {
		t.Fatalf("ParseSecdb: %v", err)
	}
	byID := map[string]advisory.Advisory{}
	for _, a := range advs {
		byID[a.ID] = a
		for _, ap := range a.Affected {
			if ap.Ecosystem != "Wolfi" {
				t.Errorf("%s: ecosystem = %q, want Wolfi", a.ID, ap.Ecosystem)
			}
		}
	}
	// A real aactl fix: CVE-2024-29902 fixed at 0.4.12-r10, carrying its GHSA as an alias.
	a, ok := byID["CVE-2024-29902"]
	if !ok {
		t.Fatal("CVE-2024-29902 (aactl fix) missing")
	}
	if len(a.Affected) != 1 || a.Affected[0].Package != "aactl" || a.Affected[0].FixedVersion != "0.4.12-r10" {
		t.Errorf("CVE-2024-29902 affected = %+v, want aactl fixed 0.4.12-r10", a.Affected)
	}
	if !contains(a.Aliases, "GHSA-88jx-383q-w4qc") {
		t.Errorf("CVE-2024-29902 aliases = %v, want the GHSA alias", a.Aliases)
	}
	// The "0" (not-affected) entries must never be emitted as a range.
	if _, bad := byID["CVE-2023-45283"]; bad {
		t.Error("CVE-2023-45283 was a \"0\" not-affected marker on aactl and must NOT be emitted")
	}
	// actionlint's only entry is "0", so none of its exclusive CVEs may appear.
	if _, bad := byID["CVE-2026-39822"]; bad {
		t.Error("CVE-2026-39822 is only an actionlint \"0\" marker and must NOT be emitted")
	}
	// ascan's real fix is present.
	if _, ok := byID["CVE-2026-55093"]; !ok {
		t.Error("CVE-2026-55093 (ascan fix) missing")
	}
}

// TestParseSecdbAlpineFixture parses a real (trimmed) Alpine secdb, keyed to the Alpine:v3.19 ecosystem.
func TestParseSecdbAlpineFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "alpine-secdb-v3.19-main.json"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseSecdb(data)
	if err != nil {
		t.Fatalf("ParseSecdb: %v", err)
	}
	var aom advisory.Advisory
	for _, a := range advs {
		if a.ID == "CVE-2021-30473" {
			aom = a
		}
		for _, ap := range a.Affected {
			if ap.Ecosystem != "Alpine:v3.19" {
				t.Errorf("%s: ecosystem = %q, want Alpine:v3.19", a.ID, ap.Ecosystem)
			}
		}
	}
	if aom.ID == "" || aom.Affected[0].Package != "aom" || aom.Affected[0].FixedVersion != "3.1.1-r0" {
		t.Errorf("CVE-2021-30473 = %+v, want aom fixed 3.1.1-r0", aom)
	}
}

// TestParseSecdbMatchesViaDomainMatcher proves a Wolfi secdb advisory matches by CVE through the apk comparator.
func TestParseSecdbMatchesViaDomainMatcher(t *testing.T) {
	data, _ := os.ReadFile(filepath.Join("testdata", "wolfi-secdb.json"))
	advs, err := ParseSecdb(data)
	if err != nil {
		t.Fatal(err)
	}
	var a advisory.Advisory
	for _, x := range advs {
		if x.ID == "CVE-2024-29902" {
			a = x
		}
	}
	if a.ID == "" {
		t.Fatal("CVE-2024-29902 not parsed")
	}
	if ok, _ := a.Match("Wolfi", "aactl", "0.4.12-r9"); !ok {
		t.Error("aactl 0.4.12-r9 (below the 0.4.12-r10 fix) must match")
	}
	if ok, _ := a.Match("Wolfi", "aactl", "0.4.12-r10"); ok {
		t.Error("aactl at the fixed 0.4.12-r10 must not match")
	}
	if ok, _ := a.Match("Alpine:v3.19", "aactl", "0.4.12-r9"); ok {
		t.Error("a Wolfi advisory must not match an Alpine ecosystem")
	}
}

// TestSecdbSemantics locks the id-filtering and skip rules on crafted input: "0" is skipped; a GO-only entry is
// skipped; a GHSA-only entry keys by the GHSA; a CVE+GHSA entry keys by the CVE with the GHSA as an alias; and a
// package with two distinct fixed versions for one id is skipped (ambiguous), while its other packages emit.
func TestSecdbSemantics(t *testing.T) {
	const doc = `{"reponame":"wolfi","packages":[
	  {"pkg":{"name":"notaffected","secfixes":{"0":["CVE-2024-1000"]}}},
	  {"pkg":{"name":"golangonly","secfixes":{"1.0.0-r0":["GO-2024-1","RUSTSEC-2024-1"]}}},
	  {"pkg":{"name":"ghsaonly","secfixes":{"2.0.0-r0":["GHSA-aaaa-bbbb-cccc"]}}},
	  {"pkg":{"name":"both","secfixes":{"3.0.0-r0":["CVE-2024-2000","GHSA-dddd-eeee-ffff","GO-2024-2"]}}},
	  {"pkg":{"name":"ambiguous","secfixes":{"1.0.0-r0":["CVE-2024-3000"],"2.0.0-r0":["CVE-2024-3000"]}}}
	]}`
	advs, err := ParseSecdb([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]advisory.Advisory{}
	for _, a := range advs {
		byID[a.ID] = a
	}
	if _, bad := byID["CVE-2024-1000"]; bad {
		t.Error("a \"0\" not-affected entry must be skipped")
	}
	if _, bad := byID["GO-2024-1"]; bad {
		t.Error("a GO-only entry must be skipped (no CVE/GHSA)")
	}
	if len(byID) != 2 { // ghsaonly + both; notaffected/golangonly/ambiguous all drop out
		t.Errorf("got ids %v, want exactly 2 (GHSA-only + CVE+GHSA; \"0\", GO-only, and ambiguous dropped)", keysOf(byID))
	}
	if g, ok := byID["GHSA-aaaa-bbbb-cccc"]; !ok || g.Affected[0].Package != "ghsaonly" {
		t.Error("a GHSA-only entry must key by the GHSA")
	}
	both, ok := byID["CVE-2024-2000"]
	if !ok || !contains(both.Aliases, "GHSA-dddd-eeee-ffff") {
		t.Errorf("a CVE+GHSA entry must key by the CVE with the GHSA alias, got %+v", both)
	}
	if _, bad := byID["CVE-2024-3000"]; bad {
		t.Error("a package with two distinct fixed versions for one id is ambiguous and must be skipped")
	}
}

// TestSecdbEcosystem locks the ecosystem derivation for each secdb source shape.
func TestSecdbEcosystem(t *testing.T) {
	cases := []struct {
		reponame, distroversion, want string
	}{
		{"main", "v3.19", "Alpine:v3.19"},
		{"community", "v3.20", "Alpine:v3.20"},
		{"wolfi", "", "Wolfi"},
		{"chainguard", "", "Chainguard"},
		// reponame is authoritative: a Wolfi feed carrying a stray distroversion must NOT key as Alpine.
		{"wolfi", "v3.19", "Wolfi"},
		{"chainguard", "v3.19", "Chainguard"},
		{"unknown", "", ""},
		{"unknown", "v3.19", "Alpine:v3.19"},
	}
	for _, tc := range cases {
		got := secdbEcosystem(secdbDoc{Reponame: tc.reponame, DistroVersion: tc.distroversion})
		if got != tc.want {
			t.Errorf("secdbEcosystem(repo=%q ver=%q) = %q, want %q", tc.reponame, tc.distroversion, got, tc.want)
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func keysOf(m map[string]advisory.Advisory) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
