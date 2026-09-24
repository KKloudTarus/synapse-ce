package scabench

import (
	"strings"
	"testing"
)

func validArchive() PinArchive {
	return PinArchive{
		SchemaVersion:   PinArchiveSchemaVersion,
		CatalogRevision: "same-sbom-linux-20260922",
		Entries: []ArchivedPin{{
			Reference:  "database:owned:redhat-rhel9-8-vex-2026-09-21",
			Digest:     "sha256:1786886d316990e5d30dc445d96bc1ceca89642643f00d931a2e1ee34154320f",
			Bytes:      34959,
			CapturedAt: "2026-09-21T00:00:00Z",
		}},
	}
}

// TestPinArchiveValidateRejectsUnusableEvidence covers the shapes an archive must refuse. Each one
// would otherwise be accepted as evidence while being unable to reproduce a capture.
func TestPinArchiveValidateRejectsUnusableEvidence(t *testing.T) {
	if err := validArchive().Validate(); err != nil {
		t.Fatalf("a complete archive must validate: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*PinArchive)
		wantErr string
	}{
		{"unknown schema", func(a *PinArchive) { a.SchemaVersion = "something-else" }, "schema version"},
		{"blank revision", func(a *PinArchive) { a.CatalogRevision = "  " }, "catalog revision is required"},
		{"no entries", func(a *PinArchive) { a.Entries = nil }, "preserved no entries"},
		{"blank reference", func(a *PinArchive) { a.Entries[0].Reference = "" }, "reference is required"},
		{"short digest", func(a *PinArchive) { a.Entries[0].Digest = "sha256:abc" }, "immutable sha256"},
		{"uppercase digest", func(a *PinArchive) {
			a.Entries[0].Digest = "sha256:1786886D316990E5D30DC445D96BC1CECA89642643F00D931A2E1EE34154320F"
		}, "immutable sha256"},
		{"unprefixed digest", func(a *PinArchive) {
			a.Entries[0].Digest = "1786886d316990e5d30dc445d96bc1ceca89642643f00d931a2e1ee34154320f"
		}, "immutable sha256"},
		{"zero length", func(a *PinArchive) { a.Entries[0].Bytes = 0 }, "positive byte length"},
		{"negative length", func(a *PinArchive) { a.Entries[0].Bytes = -1 }, "positive byte length"},
		{"unparseable time", func(a *PinArchive) { a.Entries[0].CapturedAt = "yesterday" }, "RFC3339"},
		{"non-UTC time", func(a *PinArchive) { a.Entries[0].CapturedAt = "2026-09-21T00:00:00+07:00" }, "must be UTC"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			archive := validArchive()
			testCase.mutate(&archive)
			err := archive.Validate()
			if err == nil {
				t.Fatalf("%s must be rejected", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("error must mention %q, got %v", testCase.wantErr, err)
			}
		})
	}
}

// TestPinArchiveValidateRejectsDuplicateReference keeps one pin from carrying two archived bodies,
// where the entry that wins would depend on map iteration rather than on the manifest.
func TestPinArchiveValidateRejectsDuplicateReference(t *testing.T) {
	archive := validArchive()
	duplicate := archive.Entries[0]
	duplicate.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	archive.Entries = append(archive.Entries, duplicate)
	err := archive.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("a duplicated reference must be rejected, got %v", err)
	}
}

// TestArchivablePinsSelectsOnlyFetchablePins pins the scope decision. A pin without an origin is
// produced locally, so archiving it would store bytes that nothing can drift away from.
func TestArchivablePinsSelectsOnlyFetchablePins(t *testing.T) {
	catalog := Catalog{Pins: []ArtifactPin{
		{Reference: "database:owned:sles", Digest: "sha256:aa", Origin: "https://ftp.suse.com/x.gz"},
		{Reference: "binary:synapse-sca-bench:reproducible-v1", Digest: "sha256:bb"},
		{Reference: "profile:owned:oval-v1", Digest: "sha256:cc", Origin: "   "},
		{Reference: "database:grype:v6", Digest: "sha256:dd", Origin: "https://grype.anchore.io/db.tar.zst"},
	}}

	got := ArchivablePins(catalog)
	if len(got) != 2 {
		t.Fatalf("only origin-bearing pins are archivable, got %d: %+v", len(got), got)
	}
	// Deterministic order keeps an archive manifest reproducible across runs.
	if got[0].Reference != "database:grype:v6" || got[1].Reference != "database:owned:sles" {
		t.Fatalf("archivable pins must be sorted by reference, got %q then %q", got[0].Reference, got[1].Reference)
	}
}

// TestValidateArchiveCoverageRequiresEveryFetchablePin is the load-bearing assertion. A partially
// archived corpus is the worst outcome available: recapture reproduces the archived pins, fails only
// on the rest, and reads as though archiving did not work at all.
func TestValidateArchiveCoverageRequiresEveryFetchablePin(t *testing.T) {
	const (
		suseDigest  = "sha256:bec078b7ff5ce08b1f46f84b3005ae2871bb000cd23b1b314c0e17842e61ff71"
		grypeDigest = "sha256:ed8844fd88095cb2b94734d4a3c54fb4e4b259bdffb4393bc9c4fe3b09ac257d"
	)
	catalog := Catalog{Revision: "same-sbom-linux-20260922", Pins: []ArtifactPin{
		{Reference: "database:owned:sles", Digest: suseDigest, Origin: "https://ftp.suse.com/x.gz"},
		{Reference: "database:grype:v6", Digest: grypeDigest, Origin: "https://grype.anchore.io/db.tar.zst"},
		{Reference: "profile:owned:oval-v1", Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
	}}
	complete := PinArchive{
		SchemaVersion:   PinArchiveSchemaVersion,
		CatalogRevision: "same-sbom-linux-20260922",
		Entries: []ArchivedPin{
			{Reference: "database:owned:sles", Digest: suseDigest, Bytes: 10, CapturedAt: "2026-09-21T00:00:00Z"},
			{Reference: "database:grype:v6", Digest: grypeDigest, Bytes: 20, CapturedAt: "2026-09-21T00:00:00Z"},
		},
	}
	if err := ValidateArchiveCoverage(catalog, complete); err != nil {
		t.Fatalf("a fully archived catalog must pass: %v", err)
	}

	t.Run("missing pin is named", func(t *testing.T) {
		partial := complete
		partial.Entries = complete.Entries[:1]
		err := ValidateArchiveCoverage(catalog, partial)
		if err == nil {
			t.Fatal("an incomplete archive must fail")
		}
		// Naming the gap is what makes the failure actionable rather than just red.
		if !strings.Contains(err.Error(), "database:grype:v6") {
			t.Fatalf("error must name the missing reference, got %v", err)
		}
	})

	t.Run("revision mismatch", func(t *testing.T) {
		stale := complete
		stale.CatalogRevision = "same-sbom-linux-20260915"
		err := ValidateArchiveCoverage(catalog, stale)
		if err == nil || !strings.Contains(err.Error(), "does not match catalog revision") {
			t.Fatalf("an archive from another revision must be rejected, got %v", err)
		}
	})

	t.Run("digest disagreement", func(t *testing.T) {
		wrong := complete
		wrong.Entries = append([]ArchivedPin(nil), complete.Entries...)
		wrong.Entries[0].Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		err := ValidateArchiveCoverage(catalog, wrong)
		if err == nil || !strings.Contains(err.Error(), "does not match catalog pin digest") {
			t.Fatalf("an entry disagreeing with its pin must be rejected, got %v", err)
		}
	})

	t.Run("entry for an absent pin", func(t *testing.T) {
		orphan := complete
		orphan.Entries = append(append([]ArchivedPin(nil), complete.Entries...), ArchivedPin{
			Reference:  "database:owned:retired",
			Digest:     "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			Bytes:      5,
			CapturedAt: "2026-09-21T00:00:00Z",
		})
		err := ValidateArchiveCoverage(catalog, orphan)
		if err == nil || !strings.Contains(err.Error(), "is not a catalog pin") {
			t.Fatalf("an orphaned entry must be rejected, got %v", err)
		}
	})
}

// TestValidateArchiveCoverageNamesEveryPinWhenNothingWasArchived covers the first run against a
// corpus whose origins have all been republished. Reporting only "the manifest is empty" would tell an
// operator nothing about how much of the corpus is unrecoverable.
func TestValidateArchiveCoverageNamesEveryPinWhenNothingWasArchived(t *testing.T) {
	catalog := Catalog{Revision: "rev-1", Pins: []ArtifactPin{
		{Reference: "database:owned:sles", Digest: "sha256:" + strings.Repeat("a", 64), Origin: "https://ftp.suse.com/x.gz"},
		{Reference: "source:redhat-vex", Digest: "sha256:" + strings.Repeat("b", 64), Origin: "https://security.access.redhat.com/v.json"},
	}}
	empty := PinArchive{SchemaVersion: PinArchiveSchemaVersion, CatalogRevision: "rev-1"}

	err := ValidateArchiveCoverage(catalog, empty)
	if err == nil {
		t.Fatal("an empty archive must not satisfy coverage")
	}
	for _, reference := range []string{"database:owned:sles", "source:redhat-vex"} {
		if !strings.Contains(err.Error(), reference) {
			t.Errorf("coverage must name %q, got %v", reference, err)
		}
	}

	// A malformed empty archive is still rejected on its own terms, so the exemption is narrow.
	if err := ValidateArchiveCoverage(catalog, PinArchive{CatalogRevision: "rev-1"}); err == nil || !strings.Contains(err.Error(), "schema version") {
		t.Fatalf("an empty archive with a bad schema must still be rejected, got %v", err)
	}
}

// TestValidateArchiveCoverageAcceptsOriginlessOnlyCatalog keeps the coverage rule from demanding an
// archive for a corpus that pins nothing fetchable.
func TestValidateArchiveCoverageAcceptsOriginlessOnlyCatalog(t *testing.T) {
	const digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	catalog := Catalog{Revision: "rev-1", Pins: []ArtifactPin{
		{Reference: "binary:synapse-sca-bench:reproducible-v1", Digest: digest},
	}}
	// The manifest still has to describe something real, so a locally produced pin may be archived
	// even though it is not required to be.
	archive := PinArchive{
		SchemaVersion:   PinArchiveSchemaVersion,
		CatalogRevision: "rev-1",
		Entries:         []ArchivedPin{{Reference: "binary:synapse-sca-bench:reproducible-v1", Digest: digest, Bytes: 7, CapturedAt: "2026-09-21T00:00:00Z"}},
	}
	if err := ValidateArchiveCoverage(catalog, archive); err != nil {
		t.Fatalf("a catalog with no fetchable pins must pass: %v", err)
	}
}
