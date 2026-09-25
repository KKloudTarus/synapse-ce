package ospkg

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	// pure-Go sqlite driver (matches CGO_ENABLED=0), for the RHEL9+/Fedora rpmdb.sqlite. NOTE: the crafted-view
	// non-hang property (see rpmSQLiteComponents + TestCatalogRPMHostileViewTerminates) is driver-behavior-specific –
	// re-validate that test on any version bump of this dependency.
	_ "modernc.org/sqlite"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// RPM package cataloging. Modern distros (RHEL 9+/Fedora/AL2023/UBI9) store the package DB as sqlite at
// /var/lib/rpm/rpmdb.sqlite, whose Packages table holds one binary RPM HEADER blob per installed package. The
// older Berkeley-DB backend (/var/lib/rpm/Packages, RHEL<=8/CentOS/UBI8/Amazon Linux 2) is now parsed by the
// owned pure-Go bdb.go, which extracts the SAME header blobs from the hash pages and feeds each to
// safeParseRPMHeader. The ndb backend (openSUSE/SLE, /var/lib/rpm/Packages.db) is parsed by the owned pure-Go
// rpm_ndb.go, which reads the slot directory and feeds each slot's header blob to the same safeParseRPMHeader.
// Everything here treats the DB + header as UNTRUSTED (a hostile image): reads are cancellable
// (modernc interrupts the first query step, the loop re-checks ctx between steps, and a best-effort watchdog
// closes the DB on cancel) and bounded (per-blob size filter server-side + total-byte + row-count budgets);
// together with the pinned driver returning promptly on a crafted view rather than spinning, those bound a
// hostile DB. Each identity tag latches on its first NON-EMPTY value so a crafted header cannot amplify the
// per-entry scan; the header parse is fully bounds-checked and the whole sqlite interaction is recover-wrapped
// so a malformed DB contributes nothing rather than panicking the scan (cf. PR #43).
const (
	maxRPMIndex   = 1 << 16  // index-entry count cap per header
	maxRPMData    = 64 << 20 // header data-store size cap
	rpmMaxBlobLen = 12 << 20 // per-header-blob cap (a real RPM header is well under this)
)

var rpmHeaderMagic = [4]byte{0x8e, 0xad, 0xe8, 0x01}

var errIncompleteRPMDB = errors.New("RPM database inventory is incomplete")

// RPM header tags + value types (the subset needed for identity and file ownership).
const (
	rpmTagName       = 1000
	rpmTagVersion    = 1001
	rpmTagRelease    = 1002
	rpmTagEpoch      = 1004
	rpmTagArch       = 1022
	rpmTagDirIndexes = 1116 // int32 array: for file i, the index into DIRNAMES of its directory
	rpmTagBaseNames  = 1117 // string array: file i's base name
	rpmTagDirNames   = 1118 // string array: the distinct directory prefixes (with trailing slash)
	rpmTypeInt32     = 4
	rpmTypeString    = 6
	rpmTypeBin       = 7
	rpmTypeStringArr = 8
	// maxRPMArrayCount caps BASENAMES/DIRNAMES/DIRINDEXES element counts. A real package owns at most a few
	// hundred thousand files (texlive, linux-firmware); this bounds a hostile header's array claim.
	maxRPMArrayCount = 1 << 20
	// maxRPMPathLen bounds a single reconstructed file path. A real installed path is well under PATH_MAX
	// (4096); a longer one is a crafted DIRNAMES entry, so the path is skipped BEFORE the concat that would
	// allocate it, defeating a header that reuses one multi-megabyte directory across up to maxRPMArrayCount
	// basenames.
	maxRPMPathLen = 4096
	// maxRPMFileListBytes bounds the reconstructed path bytes for ONE package header, so a header claiming up
	// to maxRPMArrayCount files cannot amplify a ~12 MiB input blob into gigabytes of retained strings (an OOM
	// the recover cannot catch, since it is a runtime throw, not a panic). 32 MiB clears the largest real
	// package (texlive at ~200k files averages well under this at typical path lengths).
	maxRPMFileListBytes = 32 << 20
	// maxRPMOwnershipBytes bounds the reconstructed path bytes summed across ALL packages in one RPMOwnership
	// walk, so many medium hostile headers cannot sum past it. 64 MiB clears a real fat image's whole file
	// inventory (hundreds of thousands of files at typical path lengths).
	maxRPMOwnershipBytes = 64 << 20
)

// rpmComponents returns one component per installed RPM package. CentOS 7 requires exactly one BerkeleyDB
// database, because a competing backend or truncated inventory would make advisory coverage ambiguous.
// Other distros try sqlite, BerkeleyDB, then ndb; the first backend that yields packages wins.
// An error from any backend is surfaced; otherwise an absent or malformed DB contributes nothing.
func rpmComponents(ctx context.Context, rootfsDir, namespace, tag string) ([]sbom.Component, error) {
	if strings.HasPrefix(tag, "centos-7") {
		// CentOS 7 uses BerkeleyDB. A second RPM backend can hide packages
		// behind the first nonempty result and make partial advisory coverage
		// appear complete, so an ambiguous rootfs fails the scan.
		for _, rel := range []string{rpmDBPath, rpmSqliteSysimagePath, rpmNDBPath, rpmNDBSysimagePath} {
			if _, err := os.Lstat(filepath.Join(rootfsDir, rel)); err == nil {
				return nil, fmt.Errorf("CentOS 7 rootfs has an unexpected RPM database backend at %s", rel)
			} else if !os.IsNotExist(err) {
				return nil, fmt.Errorf("inspect CentOS 7 RPM database backend %s: %w", rel, err)
			}
		}
		path := filepath.Join(rootfsDir, rpmBDBPath)
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("CentOS 7 BerkeleyDB RPM database is missing or not a regular file")
		}
		components, err := rpmBDBComponents(ctx, path, namespace, tag)
		if err != nil {
			return nil, err
		}
		if len(components) == 0 {
			return nil, fmt.Errorf("CentOS 7 BerkeleyDB RPM inventory is unreadable or empty")
		}
		return components, nil
	}
	comps, err := rpmSQLiteComponents(ctx, rootfsDir, namespace, tag)
	if err != nil || len(comps) > 0 {
		return comps, err
	}
	comps, err = rpmBDBComponents(ctx, filepath.Join(rootfsDir, rpmBDBPath), namespace, tag)
	if err != nil || len(comps) > 0 {
		return comps, err
	}
	// ndb backend (openSUSE/SLE). Probe /var/lib/rpm/Packages.db first, then the relocated openSUSE location;
	// the first that yields packages wins, so a rootfs where /var/lib/rpm symlinks to /usr/lib/sysimage/rpm is
	// never double-counted.
	for _, p := range []string{rpmNDBPath, rpmNDBSysimagePath} {
		comps, err = rpmNDBComponents(ctx, filepath.Join(rootfsDir, p), namespace, tag)
		if err != nil || len(comps) > 0 {
			return comps, err
		}
	}
	return nil, nil
}

// rpmSQLiteComponents reads /var/lib/rpm/rpmdb.sqlite and returns one component per installed package. namespace
// is the PURL namespace (distro id) and tag the distro qualifier (or ""). Best-effort + hardened for an
// untrusted DB: streamed (one blob at a time), bounded (per-blob size filter + total-byte + row-count budgets),
// and recover-wrapped so a malformed sqlite cannot crash the scan. Cancellation
// and exhausted budgets return errors instead of a silently truncated inventory.
// An absent/non-sqlite DB (a Berkeley-DB/ndb rootfs) contributes nothing, and
// rpmComponents then tries the BerkeleyDB backend.
func rpmSQLiteComponents(ctx context.Context, rootfsDir, namespace, tag string) ([]sbom.Component, error) {
	var out []sbom.Component
	path := filepath.Join(rootfsDir, rpmDBPath)
	err := rpmSQLiteBlobs(ctx, rootfsDir, func(b []byte) {
		if c, compOK := rpmComponentFromBlob(b, namespace, tag); compOK {
			c.Location = path // the rpm DB's path, so the component attributes to the DB's image layer
			out = append(out, c)
		}
	})
	return out, err
}

func rpmComponentFromBlob(blob []byte, namespace, tag string) (sbom.Component, bool) {
	if strings.HasPrefix(tag, "centos-7") {
		name, evr, arch, ok := centOS7BaseSignedIdentity(blob)
		if ok {
			c, compOK := osComponent("rpm", namespace, name, evr, arch, tag, "")
			if !compOK {
				return sbom.Component{}, false
			}
			return sbom.WithVerifiedRPMOrigin(c, "rhel-base"), true
		}
		// Keep an unverifiable RPM in inventory but never grant it the CentOS
		// approximation. This includes EPEL, custom, and malformed headers.
	}
	name, evr, arch, ok := safeParseRPMHeader(blob)
	if !ok {
		return sbom.Component{}, false
	}
	return osComponent("rpm", namespace, name, evr, arch, tag, "")
}

// rpmSQLiteBlobs walks the sqlite rpmdb and hands each installed package's raw header blob to visit. It probes
// the primary /var/lib/rpm/rpmdb.sqlite first, then the relocated /usr/lib/sysimage/rpm location, and reads
// the FIRST that is a regular file, so an offline rootfs carrying only the relocated DB is still read while a
// live host (where /var/lib/rpm symlinks to the sysimage dir) reads it once through the primary path and is
// never double-counted. It carries the full untrusted-DB hardening of the identity path (streamed, per-blob +
// total-byte + count budgets, ctx-cancellable, recover-wrapped). An absent/non-sqlite DB → (nil), a hostile-DB
// read → (nil); only a context cancellation surfaces an error.
func rpmSQLiteBlobs(ctx context.Context, rootfsDir string, visit func([]byte)) error {
	for _, rel := range []string{rpmDBPath, rpmSqliteSysimagePath} {
		path := filepath.Join(rootfsDir, rel)
		fi, statErr := os.Lstat(path) // regular-file guard: never follow a symlinked DB out of the rootfs
		if statErr != nil || !fi.Mode().IsRegular() {
			continue
		}
		return rpmSQLiteBlobsAt(ctx, path, visit)
	}
	return nil
}

// rpmSQLiteBlobsAt reads one sqlite rpmdb at an absolute path. It holds the untrusted-DB hardening described on
// rpmSQLiteBlobs; the recover here degrades a driver panic on a malformed file to no components.
func rpmSQLiteBlobsAt(ctx context.Context, path string, visit func([]byte)) (err error) {
	defer func() {
		if recover() != nil { // the sqlite file is untrusted; a driver panic must degrade to no components
			err = nil
		}
	}()
	// mode=ro + immutable=1: the rootfs is static, never written; the path is a fixed suffix of the workspace
	// dir (no attacker-controlled '?'), so the DSN query cannot be overridden.
	db, openErr := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if openErr != nil {
		return nil
	}
	defer func() { _ = db.Close() }()
	// Best-effort cancellation backstop. Real cancellation of this read comes from (1) modernc arming a
	// ctx->sqlite3_interrupt watcher for QueryContext's FIRST step and (2) the per-row ctx.Err() check below,
	// between steps. A spin INSIDE a later rows.Next() step is NOT interruptible by modernc, by stdlib, or by
	// this close: sql.DB.Close closes an in-use connection only when it is returned and never interrupts a
	// running step, so this watchdog does not guarantee aborting a mid-step spin (it only unblocks idle work
	// and prevents new queries). Such a spin is only reachable via a crafted Packages view whose rows the
	// server-side LENGTH filter rejects internally (so they never reach the loop); the pinned modernc v1.53.0
	// returns promptly on that shape rather than spinning, which – with the per-blob + total-byte + row-count
	// bounds below – is what actually bounds a hostile DB. TestCatalogRPMHostileViewTerminates locks that
	// property; RE-VALIDATE it on any modernc bump. done stops the watchdog on a normal return; defer order
	// (close(done) before db.Close) means no double-close on the happy path, and db.Close is idempotent anyway.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = db.Close()
		case <-done:
		}
	}()
	// Bound each header server-side (parameterized, no string concatenation) so an oversized row is filtered
	// before Scan allocates it; the read is cancellable via QueryContext + the watchdog above.
	rows, queryErr := db.QueryContext(ctx, "SELECT blob FROM Packages WHERE LENGTH(blob) > 0 AND LENGTH(blob) <= ?", rpmMaxBlobLen)
	if queryErr != nil {
		return ctx.Err() // ctx.Err() is non-nil iff cancelled → surface; else a hostile-DB error → (nil, nil)
	}
	defer func() { _ = rows.Close() }()
	var total int64
	count := 0
	for rows.Next() {
		if count >= maxPackages || total >= maxDBBytes { // row-count + total-byte budgets (bomb guard)
			return errIncompleteRPMDB
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		var b []byte
		if scanErr := rows.Scan(&b); scanErr != nil {
			return ctx.Err() // watchdog-close (cancelled) → surface; otherwise a hostile-DB error → (nil)
		}
		total += int64(len(b))
		count++
		visit(b)
		if count >= maxPackages || total >= maxDBBytes {
			return errIncompleteRPMDB
		}
	}
	if rows.Err() != nil {
		return ctx.Err() // discard partials on a hostile-DB read error (matches parseOSDB); surface a cancel
	}
	return nil
}

// safeParseRPMHeader wraps parseRPMHeader in a recover: the bounds checks below should already prevent a
// panic, but this is the belt-and-suspenders guard from PR #43 for an attacker-authored header.
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
// index entries (tag, type, offset, count), then an hsize-byte data store. Every offset is bounds-checked in
// unsigned space (width-independent), and each identity tag latches on its first NON-EMPTY value – a costly
// rpmCStr scan only ever returns non-empty (an empty result is O(1)), so a crafted header with many duplicate
// tags cannot amplify the per-entry string scan.
func parseRPMHeader(blob []byte) (name, evr, arch string, ok bool) {
	off := 0
	if len(blob) >= 4 && [4]byte(blob[:4]) == rpmHeaderMagic {
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
	dataStart := idxStart + int(nindex)*16 // nindex<=65536 → *16 fits well within int on any target (no overflow)
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
			if typ == rpmTypeString && name == "" {
				name = rpmCStr(data, offset)
			}
		case rpmTagVersion:
			if typ == rpmTypeString && version == "" {
				version = rpmCStr(data, offset)
			}
		case rpmTagRelease:
			if typ == rpmTypeString && release == "" {
				release = rpmCStr(data, offset)
			}
		case rpmTagArch:
			if typ == rpmTypeString && arch == "" {
				arch = rpmCStr(data, offset)
			}
		case rpmTagEpoch:
			if typ == rpmTypeInt32 && epoch == "" && uint64(offset)+4 <= uint64(len(data)) {
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

// safeParseRPMHeaderFiles wraps parseRPMHeaderFiles in a recover, the belt-and-suspenders guard for an
// attacker-authored header (the bounds checks below should already prevent a panic).
func safeParseRPMHeaderFiles(blob []byte) (name, evr, arch string, files []string, ok bool) {
	defer func() {
		if recover() != nil {
			name, evr, arch, files, ok = "", "", "", nil, false
		}
	}()
	return parseRPMHeaderFiles(blob)
}

// parseRPMHeaderFiles extends parseRPMHeader to also reconstruct the absolute file paths the package owns,
// from BASENAMES (1117), DIRNAMES (1118) and DIRINDEXES (1116): path[i] = DIRNAMES[DIRINDEXES[i]] + BASENAMES[i]
// (each DIRNAMES entry already carries a trailing slash). A metapackage that owns no files returns ok=true
// with a nil files slice. Every array read is count-capped and bounds-checked in unsigned space, so a crafted
// header cannot over-allocate or read out of the data store; a partially-truncated array yields what was read.
func parseRPMHeaderFiles(blob []byte) (name, evr, arch string, files []string, ok bool) {
	off := 0
	if len(blob) >= 4 && [4]byte(blob[:4]) == rpmHeaderMagic {
		off = 8
	}
	if len(blob) < off+8 {
		return "", "", "", nil, false
	}
	nindex := binary.BigEndian.Uint32(blob[off : off+4])
	hsize := binary.BigEndian.Uint32(blob[off+4 : off+8])
	if nindex == 0 || nindex > maxRPMIndex || hsize > maxRPMData {
		return "", "", "", nil, false
	}
	idxStart := off + 8
	dataStart := idxStart + int(nindex)*16
	if dataStart < idxStart || dataStart+int(hsize) > len(blob) {
		return "", "", "", nil, false
	}
	data := blob[dataStart : dataStart+int(hsize)]
	var version, release, epoch string
	var baseNames, dirNames []string
	var dirIndexes []uint32
	for i := 0; i < int(nindex); i++ {
		e := idxStart + i*16
		tag := binary.BigEndian.Uint32(blob[e : e+4])
		typ := binary.BigEndian.Uint32(blob[e+4 : e+8])
		offset := binary.BigEndian.Uint32(blob[e+8 : e+12])
		count := binary.BigEndian.Uint32(blob[e+12 : e+16])
		switch tag {
		case rpmTagName:
			if typ == rpmTypeString && name == "" {
				name = rpmCStr(data, offset)
			}
		case rpmTagVersion:
			if typ == rpmTypeString && version == "" {
				version = rpmCStr(data, offset)
			}
		case rpmTagRelease:
			if typ == rpmTypeString && release == "" {
				release = rpmCStr(data, offset)
			}
		case rpmTagArch:
			if typ == rpmTypeString && arch == "" {
				arch = rpmCStr(data, offset)
			}
		case rpmTagEpoch:
			if typ == rpmTypeInt32 && epoch == "" && uint64(offset)+4 <= uint64(len(data)) {
				epoch = strconv.FormatUint(uint64(binary.BigEndian.Uint32(data[offset:offset+4])), 10)
			}
		case rpmTagBaseNames:
			if typ == rpmTypeStringArr && baseNames == nil {
				baseNames = rpmStringArray(data, offset, count)
			}
		case rpmTagDirNames:
			if typ == rpmTypeStringArr && dirNames == nil {
				dirNames = rpmStringArray(data, offset, count)
			}
		case rpmTagDirIndexes:
			if typ == rpmTypeInt32 && dirIndexes == nil {
				dirIndexes = rpmInt32Array(data, offset, count)
			}
		}
	}
	if name == "" || version == "" {
		return "", "", "", nil, false
	}
	evr = version
	if release != "" {
		evr = version + "-" + release
	}
	if epoch != "" && epoch != "0" {
		evr = epoch + ":" + evr
	}
	// Reconstruct paths only when the three arrays are internally consistent (one dir index per base name);
	// an inconsistent header yields identity with no files rather than fabricated paths.
	if n := len(baseNames); n > 0 && n == len(dirIndexes) {
		files = make([]string, 0, minU32(uint32(n), 4096))
		pathBytes := 0
		for i, base := range baseNames {
			di := dirIndexes[i]
			if uint64(di) >= uint64(len(dirNames)) {
				continue
			}
			dir := dirNames[di]
			plen := len(dir) + len(base)
			if plen > maxRPMPathLen {
				continue // longer than PATH_MAX: a crafted entry, skipped before the concat that would allocate it
			}
			if pathBytes+plen > maxRPMFileListBytes {
				break // bound reconstructed output so a hostile header cannot amplify a ~12 MiB blob to an OOM
			}
			pathBytes += plen
			files = append(files, dir+base)
		}
	}
	return name, evr, arch, files, true
}

// rpmStringArray reads count NUL-terminated strings from data[off:], bounds- and count-capped. A truncated
// array (offset past the store, or a missing terminator) returns the entries read so far.
func rpmStringArray(data []byte, off, count uint32) []string {
	if count == 0 || count > maxRPMArrayCount {
		return nil
	}
	out := make([]string, 0, minU32(count, 4096))
	pos := uint64(off)
	for i := uint32(0); i < count; i++ {
		if pos >= uint64(len(data)) {
			return out
		}
		s := data[pos:]
		if idx := bytes.IndexByte(s, 0); idx >= 0 {
			out = append(out, string(s[:idx]))
			pos += uint64(idx) + 1
			continue
		}
		out = append(out, string(s)) // no terminator: bounded by the data store length
		return out
	}
	return out
}

// rpmInt32Array reads count big-endian uint32s from data[off:], bounds- and count-capped.
func rpmInt32Array(data []byte, off, count uint32) []uint32 {
	if count == 0 || count > maxRPMArrayCount {
		return nil
	}
	out := make([]uint32, 0, minU32(count, 4096))
	pos := uint64(off)
	for i := uint32(0); i < count; i++ {
		if pos+4 > uint64(len(data)) {
			return out
		}
		out = append(out, binary.BigEndian.Uint32(data[pos:pos+4]))
		pos += 4
	}
	return out
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// rpmCStr reads the NUL-terminated string at data[off:], bounds-checked in unsigned space (so a >2^31 offset
// on a 32-bit build cannot sign-wrap past the guard).
func rpmCStr(data []byte, off uint32) string {
	if uint64(off) >= uint64(len(data)) {
		return ""
	}
	s := data[off:]
	if i := bytes.IndexByte(s, 0); i >= 0 {
		return string(s[:i])
	}
	return string(s) // no terminator: bounded by the data store length
}
