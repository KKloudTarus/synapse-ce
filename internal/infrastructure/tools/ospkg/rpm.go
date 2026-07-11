package ospkg

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"

	// pure-Go sqlite driver (matches CGO_ENABLED=0), for the RHEL9+/Fedora rpmdb.sqlite. NOTE: the crafted-view
	// non-hang property (see rpmComponents + TestCatalogRPMHostileViewTerminates) is driver-behavior-specific –
	// re-validate that test on any version bump of this dependency.
	_ "modernc.org/sqlite"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// RPM package cataloging. Modern distros (RHEL 9+/Fedora/AL2023/UBI9) store the package DB as sqlite at
// /var/lib/rpm/rpmdb.sqlite, whose Packages table holds one binary RPM HEADER blob per installed package. The
// older Berkeley-DB (/var/lib/rpm/Packages, RHEL<=8/CentOS/AL2) and ndb (openSUSE) backends are DEFERRED –
// their binary page formats are a larger, riskier parse and the generator already catalogs them from the
// layout. Everything here treats the DB + header as UNTRUSTED (a hostile image): reads are cancellable
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
// the PURL namespace (distro id) and tag the distro qualifier (or ""). Best-effort + hardened for an untrusted
// DB: streamed (one blob at a time), bounded (per-blob size filter + total-byte + row-count budgets), and
// recover-wrapped so a malformed sqlite yields nil rather than crashing the scan. It is cancellable: an error
// is returned ONLY on context cancellation (so the pipeline surfaces a timed-out read as a failure, never a
// silently-truncated success); a hostile-DB read error or panic degrades to (nil, nil). An absent/non-sqlite
// DB (a Berkeley-DB/ndb rootfs) → (nil, nil); the generator still catalogs those from the layout.
func rpmComponents(ctx context.Context, rootfsDir, namespace, tag string) (out []sbom.Component, err error) {
	defer func() {
		if recover() != nil { // the sqlite file is untrusted; a driver panic must degrade to no components
			out, err = nil, nil
		}
	}()
	path := filepath.Join(rootfsDir, "var/lib/rpm/rpmdb.sqlite")
	fi, statErr := os.Lstat(path) // regular-file guard: never follow a symlinked DB out of the rootfs
	if statErr != nil || !fi.Mode().IsRegular() {
		return nil, nil
	}
	// mode=ro + immutable=1: the rootfs is static, never written; the path is a fixed suffix of the workspace
	// dir (no attacker-controlled '?'), so the DSN query cannot be overridden.
	db, openErr := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if openErr != nil {
		return nil, nil
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
		return nil, ctx.Err() // ctx.Err() is non-nil iff cancelled → surface; else a hostile-DB error → (nil, nil)
	}
	defer func() { _ = rows.Close() }()
	var total int64
	for rows.Next() {
		if len(out) >= maxPackages || total >= maxDBBytes { // row-count + total-byte budgets (bomb guard)
			break
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		var b []byte
		if scanErr := rows.Scan(&b); scanErr != nil {
			return nil, ctx.Err() // watchdog-close (cancelled) → surface; otherwise a hostile-DB error → (nil, nil)
		}
		total += int64(len(b))
		if name, evr, arch, ok := safeParseRPMHeader(b); ok {
			if c, ok := osComponent("rpm", namespace, name, evr, arch, tag); ok {
				out = append(out, c)
			}
		}
	}
	if rows.Err() != nil {
		return nil, ctx.Err() // discard partials on a hostile-DB read error (matches parseOSDB); surface a cancel
	}
	return out, nil
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
