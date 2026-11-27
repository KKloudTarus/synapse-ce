package audit

import (
	"strings"
	"testing"
	"time"
)

func TestHashSchemesOnFieldBoundaryCollisions(t *testing.T) {
	at := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	left := map[string]string{"a=b": "c"}
	right := map[string]string{"a": "b=c"}
	cases := []struct {
		name       string
		scheme     int
		wantShared bool
	}{
		// The legacy encoding is kept only so stored rows still verify. This pins the defect it has,
		// so nobody mistakes it for a scheme new rows may use.
		{name: "legacy encoding shares a preimage", scheme: HashSchemeLegacy, wantShared: true},
		{name: "framed encoding separates the records", scheme: HashSchemeFramed, wantShared: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := ComputeHash(tc.scheme, "", "ada", "x", "t", left, at)
			r := ComputeHash(tc.scheme, "", "ada", "x", "t", right, at)
			if (l == r) != tc.wantShared {
				t.Fatalf("shared hash = %v, want %v", l == r, tc.wantShared)
			}
		})
	}
}

func TestFramedSchemeSeparatesEveryStringField(t *testing.T) {
	at := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	// Moving bytes across any boundary between actor, action and target must change the hash.
	pairs := [][2][3]string{
		{{"ab", "c", "d"}, {"a", "bc", "d"}},
		{{"a", "bc", "d"}, {"a", "b", "cd"}},
		{{"a\x1fb", "c", "d"}, {"a", "b\x1fc", "d"}},
	}
	for _, p := range pairs {
		l := ComputeHash(HashSchemeFramed, "", p[0][0], p[0][1], p[0][2], nil, at)
		r := ComputeHash(HashSchemeFramed, "", p[1][0], p[1][1], p[1][2], nil, at)
		if l == r {
			t.Fatalf("%q and %q share a framed hash", p[0], p[1])
		}
	}
	// An empty metadata map and a map holding one empty pair are different records.
	if ComputeHash(HashSchemeFramed, "", "a", "b", "c", nil, at) == ComputeHash(HashSchemeFramed, "", "a", "b", "c", map[string]string{"": ""}, at) {
		t.Fatal("empty metadata and one empty pair share a framed hash")
	}
}

// TestWritersUseFramed pins the second half of the rollout (#1703). v0.3.0 taught every reader the
// scheme and kept writing legacy; this release writes framed, the encoding with one preimage per record.
func TestWritersUseFramed(t *testing.T) {
	if CurrentHashScheme != HashSchemeFramed {
		t.Fatalf("CurrentHashScheme = %d, want framed (%d)", CurrentHashScheme, HashSchemeFramed)
	}
}

// TestHashSchemeGoldenVectors fixes both encodings byte for byte. The legacy vector is what the
// release before schemes computed for the same record, so stored rows keep verifying. The framed
// vector pins the encoding every future reader will depend on.
func TestHashSchemeGoldenVectors(t *testing.T) {
	at := time.Date(2026, 11, 27, 8, 0, 0, 123456789, time.UTC)
	meta := map[string]string{"b": "2", "a": "1"}
	cases := []struct {
		scheme int
		want   string
	}{
		{scheme: 0, want: "411c029d1b392364a82f761b000ec566748c2b659aa6ad580aa0bf9ba68728db"},
		{scheme: HashSchemeLegacy, want: "411c029d1b392364a82f761b000ec566748c2b659aa6ad580aa0bf9ba68728db"},
		{scheme: HashSchemeFramed, want: "0da0f77d225d507f352689b69ff431b3f9440e6ac2df09f799f1e681214b1d92"},
	}
	for _, tc := range cases {
		if got := ComputeHash(tc.scheme, "prev", "ada", "scan.start", "eng-1", meta, at); got != tc.want {
			t.Errorf("scheme %d = %s, want %s", tc.scheme, got, tc.want)
		}
	}
}

func TestVerifyRecomputesEachRecordUnderItsOwnScheme(t *testing.T) {
	at := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	link := func(scheme int, prev, action string) Record {
		r := Record{Actor: "ada", Action: action, Target: "t", At: at, PreviousHash: prev, Scheme: scheme}
		r.Hash = ComputeHash(scheme, prev, r.Actor, r.Action, r.Target, r.Metadata, r.At)
		return r
	}
	// A deployment upgraded in place: legacy rows (stored before the scheme column, so zero, and
	// after it with the explicit default), then rows written by the new binary.
	first := link(0, "", "a")
	second := link(HashSchemeLegacy, first.Hash, "b")
	third := link(HashSchemeFramed, second.Hash, "c")
	fourth := link(HashSchemeFramed, third.Hash, "d")

	cases := []struct {
		name    string
		records []Record
		intact  bool
		errPart string
	}{
		{name: "mixed schemes verify end to end", records: []Record{first, second, third, fourth}, intact: true},
		{name: "a framed row relabelled legacy breaks", records: []Record{first, second, withScheme(third, HashSchemeLegacy), fourth}, errPart: "entry 2 hash"},
		{name: "a legacy row relabelled framed breaks", records: []Record{first, withScheme(second, HashSchemeFramed), third, fourth}, errPart: "entry 1 hash"},
		{name: "an unknown scheme never verifies", records: []Record{first, second, withScheme(third, 9), fourth}, errPart: "entry 2 hash"},
		// An unknown scheme computes "", so a forged link that also carries an empty hash must not
		// compare equal to it. A link with no hash after the chain began is a break, not a pass.
		{name: "an empty hash with an unknown scheme is a break", records: []Record{first, second, forgedEmpty(second.Hash)}, errPart: "entry 2 hash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := Verify(tc.records)
			if rep.Intact != tc.intact {
				t.Fatalf("intact = %v, want %v (%s)", rep.Intact, tc.intact, rep.Error)
			}
			if tc.errPart != "" && !strings.Contains(rep.Error, tc.errPart) {
				t.Fatalf("error %q does not name %q", rep.Error, tc.errPart)
			}
		})
	}
}

func TestUnknownSchemeHasNoHash(t *testing.T) {
	for _, scheme := range []int{-1, 3, 9} {
		if got := ComputeHash(scheme, "", "a", "b", "c", nil, time.Unix(0, 0)); got != "" {
			t.Fatalf("scheme %d produced hash %q", scheme, got)
		}
	}
}

func forgedEmpty(prev string) Record {
	return Record{Actor: "mallory", Action: "engagement.deleted", Target: "t", At: time.Unix(0, 0), PreviousHash: prev, Scheme: 9}
}

func withScheme(r Record, scheme int) Record {
	r.Scheme = scheme
	return r
}
