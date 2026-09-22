package ownadvisory

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestParseCSAFSnapshotAgainstRealRedHatFeed runs the parser over real Red Hat VEX documents rather than
// hand-written fixtures, so the false-positive guards are checked against the vendor's actual product shapes
// instead of only the shapes a fixture author thought to write.
//
// The guards are deliberately conservative — a colon anywhere in a package product id, and any module or
// AppStream marker on the platform, both refuse an open range. Conservative guards risk over-refusing, which
// would silently undo the recall this ingestion path exists to deliver. This test is the counterweight: the
// real not-yet-fixed case must still be admitted.
//
// Set SYNAPSE_TEST_REDHAT_VEX_DIR to a directory of Red Hat CSAF VEX documents to run it.
func TestParseCSAFSnapshotAgainstRealRedHatFeed(t *testing.T) {
	directory := os.Getenv("SYNAPSE_TEST_REDHAT_VEX_DIR")
	if directory == "" {
		t.Skip("set SYNAPSE_TEST_REDHAT_VEX_DIR to a directory of Red Hat CSAF VEX documents")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read vendor feed directory: %v", err)
	}
	paths := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			paths = append(paths, filepath.Join(directory, entry.Name()))
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("no CSAF documents in %s", directory)
	}
	documents := make([][]byte, 0, len(paths))
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		documents = append(documents, body)
	}

	advisories, err := ParseCSAFSnapshot(documents)
	if err != nil {
		t.Fatalf("ParseCSAFSnapshot over %d real documents: %v", len(documents), err)
	}

	// The recall this PR delivers: the real not-yet-fixed expat advisory must still project an open range that
	// matches the installed RHEL 9.8 binary. If a guard over-refuses, this fails.
	var sawExpat bool
	for _, record := range advisories {
		if record.ID != "CVE-2025-66382" {
			continue
		}
		sawExpat = true
		matched, fixed := record.Match("Red Hat:9", "expat", "0:2.5.0-6.el9_8.3", "x86_64")
		if !matched {
			t.Fatalf("the real not-yet-fixed expat advisory must still match the installed binary; guards over-refused: %+v", record.Affected)
		}
		if fixed != "" {
			t.Fatalf("a not-yet-fixed advisory must carry no fixed version, got %q", fixed)
		}
	}
	if !sawExpat {
		t.Skip("CVE-2025-66382 is not present in the supplied feed directory")
	}

	// No projection may name a source or modular identity, whatever the vendor emitted.
	for _, record := range advisories {
		for _, affected := range record.Affected {
			if !redHatBinaryProductID(affected.Package) {
				t.Fatalf("%s projected a non-binary identity %q", record.ID, affected.Package)
			}
		}
	}
}
