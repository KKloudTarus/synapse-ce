package ospkg

import (
	"context"
	"encoding/binary"
	"os"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// BerkeleyDB-backed rpmdb parsing. RHEL<=8 / CentOS / UBI8 / Amazon Linux 2 store the installed-package
// database as a BerkeleyDB HASH file at /var/lib/rpm/Packages, whose VALUES are the same binary RPM header
// blobs the sqlite backend (rpm.go) holds one-per-row. This is an OWNED, pure-Go parser (no go-rpmdb, no cgo
// librpm) that walks the hash pages, reassembles each header blob from its overflow-page chain, and hands the
// blob to the SAME safeParseRPMHeader the sqlite path uses. The DB is UNTRUSTED (a pulled image), so it is
// hardened exactly like the sqlite path: a regular-file guard (no symlink follow), per-blob + total-byte +
// package-count budgets, context cancellation honored, and the whole parse recover-wrapped so a malformed DB
// yields (nil,nil) rather than crashing the scan. It is conservative by construction: a malformed page, entry,
// or overflow chain is SKIPPED, never turned into a fabricated blob (a misparse is a wrong CVE match).
//
// On-disk layout facts (BerkeleyDB db_page.h, verified against a real UBI8-micro fixture):
//   - Metadata page 0 (DBMETA): magic u32 at byte 12 == 0x00061561 for a HASH db (native byte order, so read
//     LE then BE), page size u32 at byte 20, page type byte 25 == 8 (P_HASHMETA), last page number u32 at
//     byte 32. The whole file is a sequence of fixed page-size pages.
//   - Every page has a 26-byte header: LSN(0-7), page number(8-11), prev(12-15), next(16-19), entry count
//     u16(20-21), high-free/OV_LEN u16(22-23), level(24), page type(25).
//   - A HASH page (type 13, or 2 for the pre-4.6 unsorted variant) carries `entries` u16 index offsets packed
//     right after the header (inp[i] at byte 26+i*2). Entries come in KEY/VALUE pairs, so the values are the
//     odd indices. A value entry's first byte is its item type: H_KEYDATA(1) is inline, H_OFFPAGE(3) is an
//     overflow reference (HOFFPAGE: type(0), unused(1-3), overflow page number u32(4-7), total length u32(8-11)).
//   - An overflow page (type 7) holds a chunk of a large value in bytes [26 : 26+OV_LEN], and its next(16-19)
//     links the next chunk; the chain reassembles a value up to its declared total length.
//
// Both value shapes are extracted. A hash item spills to an overflow chain only when it exceeds ~pagesize/4;
// below that it is stored INLINE as an H_KEYDATA item on the page. Page size is configurable up to 64KiB, so a
// small real header (a ~3.9KB gpg-pubkey, or a small package on a 16/64KiB-page DB) can be inline. An H_OFFPAGE
// value is reassembled from its chain; an H_KEYDATA value's inline bytes (bounded by the entry's extent, from
// the sorted inp offset array) are read directly. Either way the bytes go to safeParseRPMHeader, which rejects
// anything that is not a real header (so the lone 5-byte inline counter in the 4KB-page fixture parses to
// nothing, exactly as before). On the 4KB-page UBI8 fixture every real header is >1KB and thus off-page.
//
// HASH pages are found by a linear scan of the page array (the same approach as the reference go-rpmdb reader),
// not by following the metadata bucket map (max_bucket + the spares array + each bucket's in-page next_pgno
// chain). Bucket traversal would eliminate the orphan-page class outright, but it is materially more complex and
// a spares/BS_TO_PAGE mistake would silently DROP real packages on a multi-bucket-group DB (thousands of
// packages), which is unvalidated by the single 2-bucket fixture and worse for a scanner than the residual
// risk below; the linear scan is kept for that reason. The residual limitation, stated precisely: a
// corrupt/hostile DB could carry a physically-present P_HASH page that a live-bucket walk would never return,
// so a stale header could be surfaced. It is bounded on every axis: BDB's __db_free retypes a freed page to
// P_INVALID (0), so a normally-deleted package's page is already excluded by the type check; rpm's delete
// removes the entry from its live bucket and BDB hash never contracts buckets, so no live page keeps a stale
// entry; an emptied bucket has entries==0 and is skipped; each page is cross-checked against its own header
// page-number (a relocated/copied image is rejected); and parseRPMHeader's structural validation gates what any
// surfaced blob can be. The failure direction is add-a-(real, previously-installed)-package, never hide one.
//
// The openSUSE ndb backend (/var/lib/rpm/Packages.db) is DEFERRED, not half-implemented: it is a different
// slot-directory format and no ndb fixture was available to validate an owned parser against, and shipping an
// unvalidated binary parser for untrusted input is exactly the misparse-is-a-wrong-CVE risk this file guards
// against. See rpm.go's rpmComponents dispatcher.
const (
	bdbHashMagic  = 0x00061561 // DBMETA magic for a HASH database (native byte order)
	bdbMagicOff   = 12         // byte offset of the magic in the metadata page
	bdbPageSzOff  = 20         // byte offset of the page-size u32 in the metadata page
	bdbLastPgOff  = 32         // byte offset of the last-page-number u32 in the metadata page
	bdbPageHdrLen = 26         // fixed per-page header size

	// Page types (db_page.h).
	bdbTypeHashUnsorted = 2  // hash page, pre-4.6 unsorted
	bdbTypeOverflow     = 7  // overflow (spill) page
	bdbTypeHashMeta     = 8  // hash metadata page (page 0)
	bdbTypeHash         = 13 // hash page, sorted

	// Hash item types (the first byte of a hash entry).
	bdbItemKeyData = 1 // H_KEYDATA: value stored inline on the hash page
	bdbItemOffPage = 3 // H_OFFPAGE: value spilled onto an overflow-page chain

	bdbOffPageEntryLen = 12       // HOFFPAGE entry size (type + 3 unused + pgno u32 + tlen u32)
	bdbMinPageSize     = 512      // smallest valid BerkeleyDB page size
	bdbMaxPageSize     = 64 << 10 // largest valid BerkeleyDB page size
	bdbMetaScanLen     = 512      // bytes of page 0 read to validate the metadata header
)

// rpmBDBComponents reads a BerkeleyDB-backend rpmdb at dbPath and returns one component per installed package,
// mirroring rpmSQLiteComponents. Best-effort + hardened for an untrusted DB: an error is returned ONLY on
// context cancellation (so a timed-out read surfaces as a failure, never a silently-truncated success); an
// absent/non-BDB/malformed DB or a parse panic degrades to (nil, nil). namespace is the PURL namespace and tag
// the distro qualifier, both passed straight to osComponent.
func rpmBDBComponents(ctx context.Context, dbPath, namespace, tag string) (out []sbom.Component, err error) {
	defer func() {
		if recover() != nil { // the DB is untrusted; a parse panic must degrade to no components
			out, err = nil, nil
		}
	}()
	fi, statErr := os.Lstat(dbPath) // regular-file guard: never follow a symlinked DB out of the rootfs
	if statErr != nil || !fi.Mode().IsRegular() {
		return nil, nil
	}
	f, openErr := os.Open(dbPath)
	if openErr != nil {
		return nil, nil
	}
	defer func() { _ = f.Close() }()

	size := fi.Size()
	order, pageSize, lastPgno, ok := bdbReadMeta(f, size)
	if !ok {
		return nil, nil // not a BerkeleyDB HASH database (e.g. a sqlite or ndb rootfs)
	}

	// Bound the page walk by the on-disk file size, so a lying last_pgno cannot drive an unbounded loop: a
	// page beyond EOF simply fails its ReadAt and is skipped. pageCount is at least 1 (the metadata page).
	pageCount := uint32(size / int64(pageSize))
	maxPage := lastPgno
	if pageCount == 0 || maxPage >= pageCount {
		if pageCount == 0 {
			return nil, nil
		}
		maxPage = pageCount - 1
	}

	if ctxErr := ctx.Err(); ctxErr != nil { // honor a context already cancelled before the walk
		return nil, ctxErr
	}
	// Global overflow-page read budget. In a well-formed DB each overflow page belongs to exactly one value
	// chain, so the sum of all chain reads is <= the page count; capping the AGGREGATE (not just each chain)
	// bounds total work at O(pageCount) even for a hostile file that packs many value entries, each pointing at
	// a long or self-looping chain. Without this, a broken chain returns no blob and hits `continue` below,
	// bypassing the maxPackages/maxDBBytes budgets, so many-entries * long-chain reads amplify to O(pageCount^2).
	overflowBudget := int64(pageCount)*3 + 64
	page := make([]byte, pageSize)   // reused for the current hash/meta page across the walk
	ovPage := make([]byte, pageSize) // separate scratch reused by every overflow-chain read (no per-value alloc)
	var totalBytes int64
	// emit parses a candidate value blob and appends a component if it is a real header; a non-header
	// contributes nothing. Shared by the inline and overflow value paths so both behave identically.
	emit := func(blob []byte) {
		if name, evr, arch, ok := safeParseRPMHeader(blob); ok {
			if c, compOK := osComponent("rpm", namespace, name, evr, arch, tag); compOK {
				c.Location = dbPath // the rpm DB's path, so the component attributes to the DB's image layer
				out = append(out, c)
			}
		}
	}
	for pgno := uint32(1); pgno <= maxPage; pgno++ {
		if overflowBudget <= 0 { // hostile DB exhausted the overflow budget: stop the best-effort walk
			return out, nil
		}
		if pgno&0x3f == 0 { // ~every 64 pages: honor cancellation of a large parse
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
		}
		if !bdbReadPage(f, size, pageSize, pgno, page) {
			continue
		}
		// A live page always stores its own page number in the header; a mismatch means a relocated/copied or
		// corrupt page image, which is rejected rather than extracted from.
		if order.Uint32(page[8:12]) != pgno {
			continue
		}
		ptype := page[25]
		if ptype != bdbTypeHash && ptype != bdbTypeHashUnsorted {
			continue
		}
		entries := order.Uint16(page[20:22])
		// Entries come in key/value pairs; an odd count is a malformed page (skip it, never guess a pairing).
		if entries == 0 || entries%2 != 0 {
			continue
		}
		var pageOffs []int // ascending inp offsets, built lazily to bound an inline value's extent
		offsBuilt := false
		for i := uint16(1); i < entries; i += 2 { // values are the odd indices
			if i&0x1ff == 1 { // periodic cancellation check within a large hash page's value scan
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, ctxErr
				}
			}
			idxPos := bdbPageHdrLen + int(i)*2
			if idxPos+2 > len(page) {
				break // index array runs past the page: stop reading this page
			}
			eoff := int(order.Uint16(page[idxPos : idxPos+2]))
			if eoff < bdbPageHdrLen || eoff >= len(page) {
				continue
			}
			switch page[eoff] { // the value item's type byte
			case bdbItemOffPage: // spilled onto an overflow-page chain
				if eoff+bdbOffPageEntryLen > len(page) {
					continue
				}
				opgno := order.Uint32(page[eoff+4 : eoff+8])
				tlen := order.Uint32(page[eoff+8 : eoff+12])
				if tlen == 0 || tlen > rpmMaxBlobLen { // per-blob cap: a real header is well under rpmMaxBlobLen
					continue
				}
				blob, blobOK := bdbOverflowValue(f, size, order, opgno, tlen, maxPage, &overflowBudget, ovPage)
				if !blobOK {
					continue // a malformed/broken overflow chain contributes nothing
				}
				totalBytes += int64(len(blob))
				emit(blob)
			case bdbItemKeyData: // stored inline on this page
				if !offsBuilt {
					pageOffs = bdbPageOffsets(page, entries, order)
					offsBuilt = true
				}
				end := bdbNextOffsetAbove(pageOffs, eoff, len(page)) // the entry ends where the next item begins
				if end <= eoff+1 || end > len(page) {
					continue // no room for even the header intro after the 1-byte type
				}
				blob := page[eoff+1 : end] // skip the item-type byte; the rest is the inline value
				totalBytes += int64(len(blob))
				emit(blob)
			default:
				continue // neither inline nor overflow: not a value we can read
			}
			if len(out) >= maxPackages || totalBytes >= maxDBBytes { // package-count + total-byte budgets
				return out, nil
			}
		}
	}
	return out, nil
}

// bdbPageOffsets returns the valid inp entry offsets on a hash page, ascending. It is used to bound an inline
// value's extent: an item at offset O occupies [O, nextOffsetAbove(O)), since page items are packed downward.
func bdbPageOffsets(page []byte, entries uint16, order binary.ByteOrder) []int {
	offs := make([]int, 0, entries)
	for i := 0; i < int(entries); i++ {
		pos := bdbPageHdrLen + i*2
		if pos+2 > len(page) {
			break
		}
		if o := int(order.Uint16(page[pos : pos+2])); o >= bdbPageHdrLen && o <= len(page) {
			offs = append(offs, o)
		}
	}
	sort.Ints(offs)
	return offs
}

// bdbNextOffsetAbove returns the smallest offset in sorted strictly greater than eoff, or pageLen if none. That
// is the exclusive end of the item at eoff.
func bdbNextOffsetAbove(sorted []int, eoff, pageLen int) int {
	if idx := sort.SearchInts(sorted, eoff+1); idx < len(sorted) {
		return sorted[idx]
	}
	return pageLen
}

// bdbReadMeta validates page 0 as a BerkeleyDB HASH metadata page and returns the byte order the file was
// written in, its page size, and the last page number. ok=false for any file that is not a HASH BDB or whose
// header fields are out of range.
func bdbReadMeta(r *os.File, size int64) (order binary.ByteOrder, pageSize, lastPgno uint32, ok bool) {
	if size < bdbMetaScanLen {
		return nil, 0, 0, false
	}
	meta := make([]byte, bdbMetaScanLen)
	if _, err := r.ReadAt(meta, 0); err != nil {
		return nil, 0, 0, false
	}
	// BerkeleyDB writes in the creating machine's native byte order; the magic disambiguates it.
	switch {
	case binary.LittleEndian.Uint32(meta[bdbMagicOff:bdbMagicOff+4]) == bdbHashMagic:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(meta[bdbMagicOff:bdbMagicOff+4]) == bdbHashMagic:
		order = binary.BigEndian
	default:
		return nil, 0, 0, false
	}
	if meta[25] != bdbTypeHashMeta { // page 0 must be a hash metadata page
		return nil, 0, 0, false
	}
	pageSize = order.Uint32(meta[bdbPageSzOff : bdbPageSzOff+4])
	if pageSize < bdbMinPageSize || pageSize > bdbMaxPageSize || pageSize&(pageSize-1) != 0 {
		return nil, 0, 0, false // must be a power of two in the valid range
	}
	if int64(pageSize) > size {
		return nil, 0, 0, false
	}
	lastPgno = order.Uint32(meta[bdbLastPgOff : bdbLastPgOff+4])
	return order, pageSize, lastPgno, true
}

// bdbReadPage reads page pgno into buf (len == pageSize). It returns false if the page lies beyond EOF or the
// read is short, so a caller simply skips a page that cannot be read in full.
func bdbReadPage(r *os.File, size int64, pageSize, pgno uint32, buf []byte) bool {
	offset := int64(pgno) * int64(pageSize)
	if offset < 0 || offset+int64(pageSize) > size {
		return false
	}
	_, err := r.ReadAt(buf, offset)
	return err == nil
}

// bdbOverflowValue reassembles a value of exactly tlen bytes by following the overflow-page chain that starts
// at pgno. It requires the chain to be WELL-FORMED, not merely to reach tlen: each page must be a valid overflow
// page inside the file, no page's OV_LEN may exceed the remaining need, the byte count must land on exactly tlen,
// and the page that supplies the final byte must terminate the chain (next_pgno == 0). A chain that overshoots a
// page boundary, under-delivers, or has trailing linked data after tlen is rejected (nil, false) rather than
// truncated into a fabricated blob. It is also bounded against a hostile chain: the step count is capped at the
// page count (so a cycle terminates) and each read draws down the caller's shared *budget (so the AGGREGATE reads
// across every chain stay O(pageCount)). tlen is already in (0, rpmMaxBlobLen]. page is a caller-owned scratch
// buffer (len == page size) reused across calls so a per-value allocation is avoided.
func bdbOverflowValue(r *os.File, size int64, order binary.ByteOrder, pgno, tlen, maxPage uint32, budget *int64, page []byte) ([]byte, bool) {
	// Pre-size modestly (not to tlen) so a hostile entry claiming a huge tlen with a short chain cannot force a
	// large up-front allocation; append grows to the real length for a legitimate large header.
	initial := tlen
	if initial > 1<<20 {
		initial = 1 << 20
	}
	out := make([]byte, 0, initial)
	pageSize := uint32(len(page))
	for steps := uint32(0); ; steps++ {
		if pgno == 0 || steps > maxPage || pgno > maxPage { // chain ended early, cycled, or ran off the file
			return nil, false
		}
		if *budget <= 0 { // shared overflow-read budget exhausted: stop drawing more work from a hostile file
			return nil, false
		}
		*budget--
		if !bdbReadPage(r, size, pageSize, pgno, page) {
			return nil, false
		}
		if page[25] != bdbTypeOverflow {
			return nil, false
		}
		used := int(order.Uint16(page[22:24])) // OV_LEN: bytes of data stored on this overflow page
		need := int(tlen) - len(out)
		// A well-formed chain fills each page fully except the last, whose OV_LEN is exactly the remainder. So
		// OV_LEN must be non-zero, fit the page, and never exceed the remaining need (no truncation, no overshoot).
		if used == 0 || bdbPageHdrLen+used > len(page) || used > need {
			return nil, false
		}
		out = append(out, page[bdbPageHdrLen:bdbPageHdrLen+used]...)
		next := order.Uint32(page[16:20]) // next_pgno
		if len(out) == int(tlen) {
			// The value is complete: this must be the terminal page, or the chain carries extra linked data and
			// the stored value is not what tlen claims (malformed) -> reject.
			if next != 0 {
				return nil, false
			}
			return out, true
		}
		if next == 0 { // more bytes needed but the chain ended: under-delivered
			return nil, false
		}
		pgno = next
	}
}
