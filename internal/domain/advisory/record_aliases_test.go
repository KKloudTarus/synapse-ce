package advisory

import (
	"reflect"
	"testing"
)

func TestRecordAliasesFollowsOneUnambiguousRecord(t *testing.T) {
	lookup := RecordAliases([]AliasEdge{
		// pillow: one record, two CVEs. Either CVE may be a different vulnerability, so it is skipped.
		{AliasID: "CVE-2023-4863", CanonicalID: "GHSA-j7hp-h8jx-5ppr"},
		{AliasID: "CVE-2023-5129", CanonicalID: "GHSA-j7hp-h8jx-5ppr"},
		{AliasID: "PYSEC-2023-1", CanonicalID: "CVE-2030-0001"},
		{AliasID: "GHSA-aaaa-aaaa-aaaa", CanonicalID: "CVE-2030-0001"},
		// A second record naming CVE-2030-0001 and another CVE must not bridge to CVE-2030-0002.
		{AliasID: "CVE-2030-0001", CanonicalID: "GHSA-bbbb-bbbb-bbbb"},
		{AliasID: "CVE-2030-0002", CanonicalID: "GHSA-bbbb-bbbb-bbbb"},
		// GHSA-y is named by records of two different CVEs: unambiguous each, ambiguous together.
		{AliasID: "GHSA-y", CanonicalID: "CVE-2031-0001"},
		{AliasID: "GHSA-y", CanonicalID: "CVE-2031-0002"},
		// PYSEC-1 names the pillow GHSA and only one of its CVEs; it must not settle which CVE the GHSA is, so
		// the GHSA stays out of PYSEC-1's result and still resolves to nothing.
		{AliasID: "GHSA-j7hp-h8jx-5ppr", CanonicalID: "PYSEC-1"},
		{AliasID: "CVE-2023-4863", CanonicalID: "PYSEC-1"},
	})
	cases := []struct {
		id   string
		want []string
	}{
		{"ghsa-j7hp-h8jx-5ppr", nil},
		{"CVE-2023-4863", []string{"CVE-2023-4863", "PYSEC-1"}},
		{"cve-2030-0001", []string{"CVE-2030-0001", "GHSA-aaaa-aaaa-aaaa", "PYSEC-2023-1"}},
		{"GHSA-aaaa-aaaa-aaaa", []string{"CVE-2030-0001", "GHSA-aaaa-aaaa-aaaa", "PYSEC-2023-1"}},
		{"CVE-2030-0002", nil},
		{"GHSA-y", nil},
		{"PYSEC-1", []string{"CVE-2023-4863", "PYSEC-1"}},
		{"CVE-0000-0", nil},
	}
	for _, tc := range cases {
		if got := lookup(tc.id); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("RecordAliases(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}
