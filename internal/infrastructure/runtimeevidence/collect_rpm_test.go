package runtimeevidence

import (
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// rpm header tag/type numbers, mirrored here (the ospkg constants are package-private) so this test can
// hand-encode a header blob in the exact on-disk layout ospkg.RPMOwnership reads.
const (
	rTagName       = 1000
	rTagVersion    = 1001
	rTagRelease    = 1002
	rTagArch       = 1022
	rTagDirIndexes = 1116
	rTagBaseNames  = 1117
	rTagDirNames   = 1118
	rTypeInt32     = 4
	rTypeString    = 6
	rTypeStringArr = 8
)

type rhdrTag struct {
	tag, typ uint32
	str      string
	strs     []string
	i32s     []uint32
}

// buildRPMHeaderBlob encodes tags as an RPM header: magic(4)+reserved(4), nindex(u32), hsize(u32),
// nindex×16-byte index entries, then the data store.
func buildRPMHeaderBlob(tags []rhdrTag) []byte {
	var data, index []byte
	for _, e := range tags {
		off := uint32(len(data))
		var count uint32
		switch {
		case e.strs != nil:
			count = uint32(len(e.strs))
			for _, s := range e.strs {
				data = append(data, []byte(s)...)
				data = append(data, 0)
			}
		case e.i32s != nil:
			count = uint32(len(e.i32s))
			for _, v := range e.i32s {
				b := make([]byte, 4)
				binary.BigEndian.PutUint32(b, v)
				data = append(data, b...)
			}
		default:
			count = 1
			data = append(data, []byte(e.str)...)
			data = append(data, 0)
		}
		ent := make([]byte, 16)
		binary.BigEndian.PutUint32(ent[0:], e.tag)
		binary.BigEndian.PutUint32(ent[4:], e.typ)
		binary.BigEndian.PutUint32(ent[8:], off)
		binary.BigEndian.PutUint32(ent[12:], count)
		index = append(index, ent...)
	}
	buf := []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}
	intro := make([]byte, 8)
	binary.BigEndian.PutUint32(intro[0:], uint32(len(tags)))
	binary.BigEndian.PutUint32(intro[4:], uint32(len(data)))
	buf = append(buf, intro...)
	buf = append(buf, index...)
	buf = append(buf, data...)
	return buf
}

// writeRPMSqlite creates var/lib/rpm/rpmdb.sqlite under root holding the given package header blobs, using the
// same pure-Go driver ospkg reads with.
func writeRPMSqlite(t *testing.T, root string, blobs ...[]byte) {
	t.Helper()
	dbPath := filepath.Join(root, "var/lib/rpm/rpmdb.sqlite")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)"); err != nil {
		t.Fatal(err)
	}
	for _, b := range blobs {
		if _, err := db.Exec("INSERT INTO Packages(blob) VALUES(?)", b); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()
}

func opensslRPMHeader() []byte {
	return buildRPMHeaderBlob([]rhdrTag{
		{tag: rTagName, typ: rTypeString, str: "openssl-libs"},
		{tag: rTagVersion, typ: rTypeString, str: "3.0.7"},
		{tag: rTagRelease, typ: rTypeString, str: "27.el9"},
		{tag: rTagArch, typ: rTypeString, str: "x86_64"},
		{tag: rTagBaseNames, typ: rTypeStringArr, strs: []string{"libssl.so.3", "libcrypto.so.3"}},
		{tag: rTagDirNames, typ: rTypeStringArr, strs: []string{"/usr/lib64/"}},
		{tag: rTagDirIndexes, typ: rTypeInt32, i32s: []uint32{0, 0}},
	})
}

func zlibRPMHeader() []byte {
	return buildRPMHeaderBlob([]rhdrTag{
		{tag: rTagName, typ: rTypeString, str: "zlib"},
		{tag: rTagVersion, typ: rTypeString, str: "1.2.11"},
		{tag: rTagRelease, typ: rTypeString, str: "40.el9"},
		{tag: rTagArch, typ: rTypeString, str: "x86_64"},
		{tag: rTagBaseNames, typ: rTypeStringArr, strs: []string{"libz.so.1.2.11"}},
		{tag: rTagDirNames, typ: rTypeStringArr, strs: []string{"/usr/lib64/"}},
		{tag: rTagDirIndexes, typ: rTypeInt32, i32s: []uint32{0}},
	})
}

// TestCollectRpmResolvesLoadedPackage is the end-to-end positive path for the rpm collector (#1140): a
// synthetic sqlite rpmdb owns two packages, only one of whose files was loaded, and the collector must scope
// in only the loaded package, carry its device+inode, and join to the finding by file identity.
func TestCollectRpmResolvesLoadedPackage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rpm runtime evidence requires Linux filesystem semantics")
	}
	root := t.TempDir()
	writeRPMSqlite(t, root, opensslRPMHeader(), zlibRPMHeader())
	// The actual object file, so lstat yields a real device+inode.
	writeFile(t, root, "/usr/lib64/libssl.so.3", "so")
	writeFile(t, root, "/usr/lib64/libz.so.1.2.11", "so")

	rep := NewCollector(root).Collect([]string{"/usr/lib64/libssl.so.3"})
	if len(rep.Coverage) != 0 {
		t.Fatalf("unexpected coverage gaps: %v", rep.Coverage)
	}
	if len(rep.PackageFiles) != 1 ||
		rep.PackageFiles[0].Package != (runtimereach.PackageRef{Name: "openssl-libs", Version: "3.0.7-27.el9"}) {
		t.Fatalf("expected only openssl-libs scoped in, got %+v", rep.PackageFiles)
	}
	var sslFile *runtimereach.OwnedFile
	for i := range rep.PackageFiles[0].Files {
		if rep.PackageFiles[0].Files[i].Path == "/usr/lib64/libssl.so.3" {
			sslFile = &rep.PackageFiles[0].Files[i]
		}
	}
	if sslFile == nil || !sslFile.ID.Known() {
		t.Fatalf("owned .so must carry device+inode, got %+v", sslFile)
	}
	if len(rep.Loads) != 1 || !rep.Loads[0].ID.Known() {
		t.Fatalf("load must carry device+inode, got %+v", rep.Loads)
	}
	own, loads := rep.Build()
	hits := runtimereach.Join(loads, own, []runtimereach.FindingPackage{
		{FindingID: shared.ID("f-ssl"), Package: runtimereach.PackageRef{Name: "openssl-libs", Version: "3.0.7-27.el9"}},
		{FindingID: shared.ID("f-zlib"), Package: runtimereach.PackageRef{Name: "zlib", Version: "1.2.11-40.el9"}},
	})
	if len(hits) != 1 || hits[0].FindingID != "f-ssl" || hits[0].Match != runtimereach.MatchFileIdentity {
		t.Fatalf("join must raise only f-ssl by file identity, got %+v", hits)
	}
}

// TestCollectRpmSysimageNdbPathProbed pins that the collector recognizes the relocated openSUSE ndb path
// (/usr/lib/sysimage/rpm/Packages.db) as an rpm host, not an unsupported platform.
func TestCollectRpmSysimageNdbPathProbed(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/usr/lib/sysimage/rpm/Packages.db", "not a real ndb")
	rep := NewCollector(root).Collect([]string{"/usr/lib64/libssl.so.3"})
	// The DB is present but unreadable, so this is an honest coverage gap, never unsupported-platform.
	if len(rep.Coverage) != 1 || rep.Coverage[0] != runtimereach.CoverageUnreadablePackageDB {
		t.Fatalf("a relocated-ndb rpm host must declare an unreadable-db gap, got %v", rep.Coverage)
	}
}
