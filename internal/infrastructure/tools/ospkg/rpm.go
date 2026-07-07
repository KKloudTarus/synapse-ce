package ospkg

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"

	_ "modernc.org/sqlite" // pure-Go sqlite driver (matches CGO_ENABLED=0), for the RHEL9+/Fedora rpmdb.sqlite

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// RPM package cataloging. Modern distros (RHEL 9+/Fedora/AL2023/UBI9) store the package DB as sqlite at
// /var/lib/rpm/rpmdb.sqlite, whose Packages table holds one binary RPM HEADER blob per installed package. The
// older Berkeley-DB (/var/lib/rpm/Packages, RHEL<=8/CentOS/AL2) and ndb (openSUSE) backends are DEFERRED —
// their binary page formats are a larger, riskier parse and the generator already catalogs them from the
// layout. The header blob is UNTRUSTED (from a hostile image), so parseRPMHeader is fully bounds-checked and
// wrapped in a recover: a crafted header contributes nothing rather than panicking the scan (cf. PR #43).
const (
	maxRPMIndex = 1 << 16  // index-entry count cap per header (a real package has a few hundred tags at most)
	maxRPMData  = 64 << 20 // header data-store size cap
)

var rpmHeaderMagic = []byte{0x8e, 0xad, 0xe8, 0x01}

// RPM header tags + value types (the subset needed for identity).
const (
	rpmTagName    = 1000
	rpmTagVersion = 1001
	rpmTagRelease = 1002
	rpmTagEpoch   = 1004
	rpmTagArch    = 1022
	rpmTypeInt32  = 4
	rpmTypeString = 6
)

// rpmComponents reads /var/lib/rpm/rpmdb.sqlite and returns one component per installed package. namespace is
// the PURL namespace (distro id) and tag the distro qualifier (or ""). Best-effort: an absent/unreadable/
// non-sqlite DB yields nil (Berkeley-DB/ndb rootfs → no owned rpm components; the generator still catalogs them).
func rpmComponents(rootfsDir, namespace, tag string) []sbom.Component {
	blobs := rpmSqliteBlobs(filepath.Join(rootfsDir, "var/lib/rpm/rpmdb.sqlite"))
	var out []sbom.Component
	for _, blob := range blobs {
		if len(out) >= maxPackages {
			break
		}
		name, evr, arch, ok := safeParseRPMHeader(blob)
		if !ok {
			continue
		}
		if c, ok := osComponent("rpm", namespace, name, evr, arch, tag); ok {
			out = append(out, c)
		}
	}
	return out
}

// safeParseRPMHeader wraps parseRPMHeader in a recover: a crafted header blob must never panic the scan (the
// bounds checks below should already prevent it, but this is the belt-and-suspenders guard from PR #43).
func safeParseRPMHeader(blob []byte) (name, evr, arch string, ok bool) {
	defer func() {
		if recover() != nil {
			name, evr, arch, ok = "", "", "", false
		}
	}()
	return parseRPMHeader(blob)
}

// parseRPMHeader extracts (name, epoch:version-release, arch) from one RPM header blob. Layout: an optional
// 8-byte lead (magic 8e ad e8 01 + 4 reserved), then nindex (u32 BE) + hsize (u32 BE), then nindex 16-byte
// index entries (tag, type, offset, count), then an hsize-byte data store. Every offset is bounds-checked
// against the data store, so an attacker-authored blob cannot read out of bounds.
func parseRPMHeader(blob []byte) (name, evr, arch string, ok bool) {
	off := 0
	if len(blob) >= 4 && bytes.Equal(blob[:4], rpmHeaderMagic) {
		off = 8 // skip the 4-byte magic + 4 reserved bytes
	}
	if len(blob) < off+8 {
		return "", "", "", false
	}
	nindex := binary.BigEndian.Uint32(blob[off : off+4])
	hsize := binary.BigEndian.Uint32(blob[off+4 : off+8])
	if nindex == 0 || nindex > maxRPMIndex || hsize > maxRPMData {
		return "", "", "", false
	}
	idxStart := off + 8
	dataStart := idxStart + int(nindex)*16
	// The index block + data store must fit within the blob (the caps above keep the arithmetic in range).
	if dataStart < idxStart || dataStart+int(hsize) > len(blob) {
		return "", "", "", false
	}
	data := blob[dataStart : dataStart+int(hsize)]
	var version, release, epoch string
	for i := 0; i < int(nindex); i++ {
		e := idxStart + i*16
		tag := binary.BigEndian.Uint32(blob[e : e+4])
		typ := binary.BigEndian.Uint32(blob[e+4 : e+8])
		offset := binary.BigEndian.Uint32(blob[e+8 : e+12])
		switch tag {
		case rpmTagName:
			if typ == rpmTypeString {
				name = rpmCStr(data, offset)
			}
		case rpmTagVersion:
			if typ == rpmTypeString {
				version = rpmCStr(data, offset)
			}
		case rpmTagRelease:
			if typ == rpmTypeString {
				release = rpmCStr(data, offset)
			}
		case rpmTagArch:
			if typ == rpmTypeString {
				arch = rpmCStr(data, offset)
			}
		case rpmTagEpoch:
			if typ == rpmTypeInt32 && int(offset)+4 <= len(data) {
				epoch = strconv.FormatUint(uint64(binary.BigEndian.Uint32(data[offset:offset+4])), 10)
			}
		}
	}
	if name == "" || version == "" {
		return "", "", "", false
	}
	evr = version
	if release != "" {
		evr = version + "-" + release
	}
	if epoch != "" && epoch != "0" {
		evr = epoch + ":" + evr
	}
	return name, evr, arch, true
}

// rpmCStr reads the NUL-terminated string at data[off:], bounds-checked.
func rpmCStr(data []byte, off uint32) string {
	if int(off) >= len(data) {
		return ""
	}
	s := data[off:]
	if i := bytes.IndexByte(s, 0); i >= 0 {
		return string(s[:i])
	}
	return string(s) // no terminator: bounded by the data store length
}

// rpmSqliteBlobs opens rpmdb.sqlite read-only + immutable (an untrusted, static file) and returns the header
// blob of each Packages row, bounded. A missing/irregular path or any driver/query/scan error yields nil
// (best-effort — the generator still catalogs rpm from the layout).
func rpmSqliteBlobs(path string) [][]byte {
	fi, err := os.Lstat(path) // regular-file guard: never follow a symlinked DB out of the rootfs
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	// immutable=1: the rootfs is static, so skip locking; mode=ro: never write. The path is a fixed suffix of
	// the workspace dir (no attacker-controlled '?'), so the DSN query cannot be overridden.
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return nil
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query("SELECT blob FROM Packages") // fixed query (no concatenation); row count bounded below
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out [][]byte
	for rows.Next() {
		if len(out) >= maxPackages { // bound the number of packages read (in Go, not via a SQL LIMIT)
			break
		}
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return out
		}
		if len(b) > 0 && len(b) <= maxDBBytes {
			out = append(out, b)
		}
	}
	return out // rows.Err() ignored: a partial best-effort read still contributes what it parsed
}
