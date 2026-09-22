package ownadvisory

import (
	"reflect"
	"testing"
)

func TestParseCSAFSnapshotProjectsSoleCVEIdentityAndEmptyReplacement(t *testing.T) {
	document := []byte(`{
		"document":{"title":"replacement"},
		"vulnerabilities":[{
			"cve":" cve-2026-0001 ",
			"ids":[{"text":"RHSA-2026:0001"},{"text":"GHSA-aaaa-bbbb-cccc"}],
			"product_status":{"known_affected":["unrepresentable-product"]}
		}]
	}`)

	advisories, err := ParseCSAFSnapshot([][]byte{document})
	if err != nil {
		t.Fatalf("ParseCSAFSnapshot: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("advisories = %+v, want one replacement", advisories)
	}
	got := advisories[0]
	if got.ID != "CVE-2026-0001" || len(got.Aliases) != 0 {
		t.Fatalf("snapshot identity = id %q aliases %v, want sole normalized CVE", got.ID, got.Aliases)
	}
	if len(got.Affected) != 0 {
		t.Fatalf("empty affected replacement was lost: %+v", got.Affected)
	}
}

func TestParseCSAFSnapshotIsDocumentOrderDeterministic(t *testing.T) {
	first := []byte(`{"document":{"title":"first"},"vulnerabilities":[{"cve":"CVE-2026-0002"}]}`)
	second := []byte(`{"document":{"title":"second"},"vulnerabilities":[{"cve":"CVE-2026-0001"}]}`)

	forward, err := ParseCSAFSnapshot([][]byte{first, second})
	if err != nil {
		t.Fatalf("forward snapshot: %v", err)
	}
	reversed, err := ParseCSAFSnapshot([][]byte{second, first})
	if err != nil {
		t.Fatalf("reversed snapshot: %v", err)
	}
	if !reflect.DeepEqual(forward, reversed) {
		t.Fatalf("snapshot output depends on document order:\nforward=%+v\nreverse=%+v", forward, reversed)
	}
	if len(forward) != 2 || forward[0].ID != "CVE-2026-0001" || forward[1].ID != "CVE-2026-0002" {
		t.Fatalf("snapshot records are not deterministically ordered: %+v", forward)
	}
}

func TestParseCSAFSnapshotRejectsConflictingDuplicateCVE(t *testing.T) {
	first := []byte(`{"document":{"title":"first"},"vulnerabilities":[{"cve":"CVE-2026-0001"}]}`)
	second := []byte(`{"document":{"title":"revised"},"vulnerabilities":[{"cve":"CVE-2026-0001"}]}`)

	if _, err := ParseCSAFSnapshot([][]byte{first, second}); err == nil {
		t.Fatal("conflicting duplicate CVE records were accepted")
	}
}

func TestParseCSAFSnapshotRejectsUnrepresentableOrMalformedDocuments(t *testing.T) {
	valid := []byte(`{"document":{"title":"valid"},"vulnerabilities":[{"cve":"CVE-2026-0001"}]}`)
	for _, document := range [][]byte{
		[]byte(`{"vulnerabilities":[{}]}`),
		[]byte(`{"vulnerabilities":[{"cve":"CVE-2026-1"}]}`),
		[]byte(`{`),
	} {
		if _, err := ParseCSAFSnapshot([][]byte{valid, document}); err == nil {
			t.Fatalf("unrepresentable snapshot document %q was accepted", document)
		}
	}
}
