package ownadvisory

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestOVALDirFeed(t *testing.T) {
	// Copy the fixture into a fresh dir so the feed reads exactly one OVAL file.
	src, err := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "com.ubuntu.jammy.cve.oval.xml"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	// A stray non-OVAL file must be ignored by the suffix filter.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# notes"), 0o644); err != nil {
		t.Fatal(err)
	}

	var got []advisory.Advisory
	skipped, err := NewOVALDirFeed(dir).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-2023-1000" {
		t.Fatalf("want 1 advisory CVE-2023-1000, got %+v", got)
	}
	if skipped != 0 {
		t.Errorf("want 0 skipped (README filtered by suffix), got %d", skipped)
	}
}

func TestOVALDirFeedIncludesSLENotYetFixed(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6-affected.xml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "suse.linux.enterprise.15-sp6-affected.xml"), src, 0o644); err != nil {
		t.Fatal(err)
	}

	var got []advisory.Advisory
	skipped, err := NewOVALDirFeed(dir).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("authoritative no-fix advisory must not be counted as inert: skipped=%d", skipped)
	}
	if len(got) != 1 || got[0].ID != "CVE-2026-53910" || len(got[0].Affected) != 2 {
		t.Fatalf("want the SLES no-fix advisory and both package branches, got %+v", got)
	}
}

func TestOVALDirFeedReducesCompleteSnapshotBeforeEmission(t *testing.T) {
	open := sleAffectedDefinitionsDoc(sleAffectedDefinition("open", "oval:test:open"))
	fixed := sleAffectedDefinitionsDoc(sleAffectedDefinition("fixed", "oval:test:fixed"))
	for _, names := range [][2]string{{"a-open.xml", "z-fixed.xml"}, {"z-open.xml", "a-fixed.xml"}} {
		t.Run(names[0], func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, names[0]), open, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, names[1]), fixed, 0o644); err != nil {
				t.Fatal(err)
			}
			var got []advisory.Advisory
			if _, err := NewOVALDirFeed(dir).Each(context.Background(), func(a advisory.Advisory) error {
				got = append(got, a)
				return nil
			}); err != nil {
				t.Fatalf("Each: %v", err)
			}
			if len(got) != 1 || len(got[0].Affected) != 1 || got[0].Affected[0].FixedVersion != "0:3.6-4.3.2" {
				t.Fatalf("snapshot reduction must be filename-order independent: %+v", got)
			}
		})
	}
}

func TestOVALDirFeedEmitsEmptyCurrentAdvisory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "not-affected.xml"), sleNotAffectedDoc(), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []advisory.Advisory
	if _, err := NewOVALDirFeed(dir).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Each: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-2026-53910" || len(got[0].Affected) != 0 {
		t.Fatalf("explicit not-affected state must remain an empty current replacement: %+v", got)
	}
}

func TestOVALDirFeedRejectsPartialSnapshotBeforeEmission(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "valid.xml"), sleAffectedDefinitionsDoc(sleAffectedDefinition("open", "oval:test:open")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "malformed.xml"), []byte("<oval_definitions>"), 0o644); err != nil {
		t.Fatal(err)
	}
	emitted := 0
	if _, err := NewOVALDirFeed(dir).Each(context.Background(), func(advisory.Advisory) error {
		emitted++
		return nil
	}); err == nil {
		t.Fatal("a malformed in-scope file must reject the complete snapshot")
	}
	if emitted != 0 {
		t.Fatalf("no advisory may be emitted before complete snapshot validation, emitted=%d", emitted)
	}
}

func TestOVALDirFeedRejectsUnrepresentableSnapshotBeforeEmission(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"oval-jammy.xml", "oval-jammy-deferred.xml"} {
		src, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), src, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	emitted := 0
	if _, err := NewOVALDirFeed(dir).Each(context.Background(), func(advisory.Advisory) error {
		emitted++
		return nil
	}); err == nil {
		t.Fatal("a relevant unrepresentable definition must reject the complete snapshot")
	}
	if emitted != 0 {
		t.Fatalf("no advisory may be emitted before semantic snapshot validation, emitted=%d", emitted)
	}
}

func TestOVALDirFeedRejectsEmptySnapshot(t *testing.T) {
	if _, err := NewOVALDirFeed(t.TempDir()).Each(context.Background(), func(advisory.Advisory) error { return nil }); err == nil {
		t.Fatal("an arbitrary empty directory is not an authoritative empty snapshot")
	}
}

func TestOVALDirFeedBz2(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "com.ubuntu.jammy.cve.oval.xml.bz2"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	var got []advisory.Advisory
	if _, err := NewOVALDirFeed(dir).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Each(bz2): %v", err)
	}
	if len(got) != 1 || got[0].Affected[0].Ecosystem != "Ubuntu:22.04" {
		t.Errorf("bz2 feed mismatch: %+v", got)
	}
}

func TestOVALDirFeedContextCancelled(t *testing.T) {
	dir := t.TempDir()
	src, _ := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml"))
	_ = os.WriteFile(filepath.Join(dir, "com.ubuntu.jammy.cve.oval.xml"), src, 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewOVALDirFeed(dir).Each(ctx, func(advisory.Advisory) error { return nil }); err == nil {
		t.Error("a cancelled context must surface an error")
	}
}

// SUSE publishes OVAL only as gzip (SLE ships no .bz2), and its decompressed .xml exceeds the per-file read
// cap, so the offline dir feed must accept and decompress .xml.gz. (D1.4)
func TestOVALDirFeedGz(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6.xml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "suse.linux.enterprise.15-sp6.xml.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write(src); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	var got []advisory.Advisory
	if _, err := NewOVALDirFeed(dir).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Each(gz): %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-2026-12345" || len(got[0].Affected) != 1 {
		t.Fatalf("gzipped SLE OVAL must ingest the architecture-scoped current advisory, got %+v", got)
	}
	if len(got[0].Affected[0].Architectures) == 0 {
		t.Fatalf("the ingested advisory must retain its architecture scope, got %+v", got[0].Affected[0])
	}
}

func TestOVALDirFeedRejectsAggregateRawBudgetBeforeEmission(t *testing.T) {
	document := sleAffectedDefinitionsDoc(sleAffectedDefinition("open", "oval:test:open"))
	documentBytes := int64(len(document))
	limits := ovalSnapshotLimits{
		fileBytes:                 documentBytes,
		snapshotBytes:             2*documentBytes - 1,
		documentDecompressedBytes: documentBytes,
		snapshotDecompressedBytes: 2 * documentBytes,
	}
	dir := t.TempDir()
	for _, name := range []string{"a.xml", "b.xml"} {
		if err := os.WriteFile(filepath.Join(dir, name), document, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	emitted := 0
	_, err := NewOVALDirFeed(dir).eachWithLimits(context.Background(), limits, func(advisory.Advisory) error {
		emitted++
		return nil
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("aggregate raw overflow must return validation error, got %v", err)
	}
	if emitted != 0 {
		t.Fatalf("aggregate raw overflow must emit no advisories, got %d", emitted)
	}
}

func TestOVALDirFeedRejectsAggregateDecompressedBudgetBeforeEmission(t *testing.T) {
	document := sleAffectedDefinitionsDoc(sleAffectedDefinition("open", "oval:test:open"))
	documentBytes := int64(len(document))
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(document); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	compressedBytes := int64(compressed.Len())
	fileBytes := documentBytes
	if compressedBytes > fileBytes {
		fileBytes = compressedBytes
	}
	limits := ovalSnapshotLimits{
		fileBytes:                 fileBytes,
		snapshotBytes:             documentBytes + compressedBytes,
		documentDecompressedBytes: documentBytes,
		snapshotDecompressedBytes: 2*documentBytes - 1,
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.xml"), document, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.xml.gz"), compressed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	emitted := 0
	_, err := NewOVALDirFeed(dir).eachWithLimits(context.Background(), limits, func(advisory.Advisory) error {
		emitted++
		return nil
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("aggregate decompressed overflow must return validation error, got %v", err)
	}
	if emitted != 0 {
		t.Fatalf("aggregate decompressed overflow must emit no advisories, got %d", emitted)
	}
}

func TestOVALDirFeedAcceptsMultipleDocumentsWithinSnapshotBudgets(t *testing.T) {
	document := sleAffectedDefinitionsDoc(sleAffectedDefinition("open", "oval:test:open"))
	documentBytes := int64(len(document))
	limits := ovalSnapshotLimits{
		fileBytes:                 documentBytes,
		snapshotBytes:             2 * documentBytes,
		documentDecompressedBytes: documentBytes,
		snapshotDecompressedBytes: 2 * documentBytes,
	}
	dir := t.TempDir()
	for _, name := range []string{"a.xml", "b.xml"} {
		if err := os.WriteFile(filepath.Join(dir, name), document, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var got []advisory.Advisory
	if _, err := NewOVALDirFeed(dir).eachWithLimits(context.Background(), limits, func(adv advisory.Advisory) error {
		got = append(got, adv)
		return nil
	}); err != nil {
		t.Fatalf("multiple documents within budgets: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-2026-53910" {
		t.Fatalf("want one reduced advisory from both documents, got %+v", got)
	}
}
