package runtimereach

import "testing"

func libssl3() PackageRef  { return PackageRef{Name: "libssl3", Version: "3.0.13-0ubuntu3.4"} }
func libssl11() PackageRef { return PackageRef{Name: "libssl1.1", Version: "1.1.1f-1ubuntu2"} }

func TestResolveByFileIdentityBeatsPath(t *testing.T) {
	// Two versions of the same library installed, each with its own inode. The same path is a symlink that
	// currently points at v3, but the load carries the v1 inode: identity must win and pick v1.
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 111}}}},
		{Package: libssl11(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.1.1", ID: FileID{Device: 64, Inode: 222}}}},
	})
	ref, kind := own.Resolve(LoadEvent{Path: "/usr/lib/libssl.so", RealPath: "/usr/lib/libssl.so.1.1", ID: FileID{Device: 64, Inode: 222}})
	if kind != MatchFileIdentity {
		t.Fatalf("match kind = %q, want file_identity", kind)
	}
	if ref != libssl11() {
		t.Fatalf("resolved %+v, want libssl1.1", ref)
	}
}

func TestResolveMultiVersionDisambiguatedByInode(t *testing.T) {
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", ID: FileID{Device: 64, Inode: 300}}}},
		{Package: libssl11(), Files: []OwnedFile{{Path: "/usr/lib/x86_64-linux-gnu/libssl.so.1.1", ID: FileID{Device: 64, Inode: 100}}}},
	})
	// Only v3 is loaded (its inode). v1's finding must NOT be attributed.
	ref, kind := own.Resolve(LoadEvent{Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", ID: FileID{Device: 64, Inode: 300}})
	if kind != MatchFileIdentity || ref != libssl3() {
		t.Fatalf("resolved (%+v,%q), want libssl3 file_identity", ref, kind)
	}
}

func TestResolveBarePathCollisionFailsClosed(t *testing.T) {
	// A path claimed by two packages, with NO filesystem identity on the load: must not misattribute.
	own := NewOwnership([]PackageFiles{
		{Package: PackageRef{Name: "pkg-a", Version: "1"}, Files: []OwnedFile{{Path: "/usr/lib/shared/libcommon.so"}}},
		{Package: PackageRef{Name: "pkg-b", Version: "2"}, Files: []OwnedFile{{Path: "/usr/lib/shared/libcommon.so"}}},
	})
	if ref, kind := own.Resolve(LoadEvent{Path: "/usr/lib/shared/libcommon.so"}); kind != MatchNone || !ref.IsZero() {
		t.Fatalf("collision resolved to (%+v,%q), want no match", ref, kind)
	}
}

func TestResolveInodeCollisionFailsClosed(t *testing.T) {
	// A single inode two packages both claim (cross-package hard link): identity cannot separate them.
	id := FileID{Device: 64, Inode: 900}
	own := NewOwnership([]PackageFiles{
		{Package: PackageRef{Name: "pkg-a", Version: "1"}, Files: []OwnedFile{{Path: "/a", ID: id}}},
		{Package: PackageRef{Name: "pkg-b", Version: "2"}, Files: []OwnedFile{{Path: "/b", ID: id}}},
	})
	if ref, kind := own.Resolve(LoadEvent{Path: "/a", ID: id}); kind != MatchNone || !ref.IsZero() {
		t.Fatalf("inode collision resolved to (%+v,%q), want no match", ref, kind)
	}
}

func TestResolveUniquePathFallback(t *testing.T) {
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3"}}},
	})
	ref, kind := own.Resolve(LoadEvent{Path: "/usr/lib/libssl.so.3"})
	if kind != MatchUniquePath || ref != libssl3() {
		t.Fatalf("resolved (%+v,%q), want libssl3 unique_path", ref, kind)
	}
}

func TestResolveDeletedFileWithoutIdentityFailsClosed(t *testing.T) {
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3"}}},
	})
	// The mapped file was unlinked; without an inode the path may now name a different file. Must not match.
	if ref, kind := own.Resolve(LoadEvent{Path: "/usr/lib/libssl.so.3 (deleted)", Deleted: true}); kind != MatchNone || !ref.IsZero() {
		t.Fatalf("deleted load resolved to (%+v,%q), want no match", ref, kind)
	}
}

func TestResolveDeletedFileWithIdentityMatches(t *testing.T) {
	id := FileID{Device: 64, Inode: 555}
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: id}}},
	})
	// A running process still maps the now-unlinked file; its inode still identifies the owning package.
	ref, kind := own.Resolve(LoadEvent{Path: "/usr/lib/libssl.so.3 (deleted)", Deleted: true, ID: id})
	if kind != MatchFileIdentity || ref != libssl3() {
		t.Fatalf("deleted-with-inode resolved to (%+v,%q), want libssl3 file_identity", ref, kind)
	}
}

func TestResolveUnknownPathNoMatch(t *testing.T) {
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3"}}},
	})
	if ref, kind := own.Resolve(LoadEvent{Path: "/opt/app/bundled/libssl.so.3"}); kind != MatchNone || !ref.IsZero() {
		t.Fatalf("unknown path resolved to (%+v,%q), want no match", ref, kind)
	}
}

func TestResolvePathNormalizationMatches(t *testing.T) {
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib//libssl.so.3/"}}},
	})
	if _, kind := own.Resolve(LoadEvent{Path: "/usr/lib/libssl.so.3"}); kind != MatchUniquePath {
		t.Fatalf("normalized path did not match: kind=%q", kind)
	}
}

func TestResolveKnownInodeAbsentFromIdentityCoveredDBFailsClosed(t *testing.T) {
	// The DB carries inode identity for its files, but the load's observed inode matches none of them: the
	// on-disk file was replaced out-of-band. Must not fall back to the path (which would over-attribute).
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 111}}}},
	})
	if ref, kind := own.Resolve(LoadEvent{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 999}}); kind != MatchNone || !ref.IsZero() {
		t.Fatalf("replaced-file load resolved to (%+v,%q), want no match (identity disagrees with DB)", ref, kind)
	}
}

func TestResolveKnownInodePathOnlyDBStillFallsBack(t *testing.T) {
	// The DB carries NO inode identity (path-only export). A load with an observed inode must still fall
	// back to the unique path, or an identity-carrying eBPF load would never match a path-only package DB.
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3"}}},
	})
	if ref, kind := own.Resolve(LoadEvent{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 999}}); kind != MatchUniquePath || ref != libssl3() {
		t.Fatalf("path-only DB resolved to (%+v,%q), want libssl3 unique_path", ref, kind)
	}
}

func TestNilOwnershipResolvesNothing(t *testing.T) {
	var o *Ownership
	if _, kind := o.Resolve(LoadEvent{Path: "/x", ID: FileID{Device: 1, Inode: 1}}); kind != MatchNone {
		t.Fatalf("nil ownership matched: %q", kind)
	}
}

func TestDuplicateOwnedFileIsNotACollision(t *testing.T) {
	// The same package listing a path twice, or two file-list rows for one package, must not fabricate a
	// collision that would fail closed on a legitimately unique path.
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3"}, {Path: "/usr/lib/libssl.so.3"}}},
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3"}}},
	})
	if _, kind := own.Resolve(LoadEvent{Path: "/usr/lib/libssl.so.3"}); kind != MatchUniquePath {
		t.Fatalf("duplicate owned file caused kind=%q, want unique_path", kind)
	}
}
