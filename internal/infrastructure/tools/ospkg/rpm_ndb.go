package ospkg

import (
	"context"
	"encoding/binary"
	"os"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// ndb-backed rpmdb parsing. openSUSE / SLE (rpm >= 4.15) store the installed-package database in the "ndb"
// format at /var/lib/rpm/Packages.db (openSUSE Leap relocates it to /usr/lib/sysimage/rpm/Packages.db, with
// /var/lib/rpm a symlink to that dir). The VALUES are the same binary RPM header blobs the sqlite backend
// (rpm.go) holds one-per-row and the BerkeleyDB backend (bdb.go) reassembles from hash pages, so each blob is
// handed to the SAME safeParseRPMHeader all three backends share. This is an OWNED, pure-Go parser (no
// go-rpmdb, no cgo librpm): it reads the slot directory and hands each slot's header blob to the shared
// parser. The DB is UNTRUSTED (a pulled image), so it is hardened exactly like the sqlite and bdb paths: a
// regular-file guard (no symlink follow of the final DB out of the rootfs), per-blob + total-byte +
// package-count budgets, context cancellation honored between slots, and the whole parse recover-wrapped so a
// malformed DB yields (nil, nil) rather than crashing the scan. It is conservative by construction: a
// malformed header, slot, or blob is SKIPPED, never turned into a fabricated component (a misparse is a wrong
// CVE match).
//
// On-disk layout facts (librpm lib/backend/ndb/rpmpkg.c, verified byte-for-byte against a real openSUSE Leap
// 15.6 Packages.db fixture):
//   - File header, 16 bytes: magic[0:4] == "RpmP", version u32 LE [4:8], generation u32 LE [8:12], and the
//     slot-page count u32 LE [12:16]. Every integer in the ndb slot/blob structure is little-endian.
//   - The slot directory is slotNPages fixed 4096-byte pages at the start of the file. Each slot is 16 bytes,
//     so a page holds 256 slots; the first two slot entries (bytes 0..31) are the file header, so real slots
//     begin at slot index 2. A live slot is: magic[0:4] == "Slot", package index u32 LE [4:8], block offset
//     u32 LE [8:12], block count u32 LE [12:16]. An unused entry has a zero magic; a deleted one has a zero
//     block offset. Blocks are 16 bytes, so the slot's blob occupies file bytes [blkOff*16, (blkOff+blkCnt)*16)
//     in the blob area that follows the slot pages.
//   - A blob starts with a 16-byte header: magic[0:4] == "BlbS", package index u32 LE [4:8] (must equal the
//     slot's), generation u32 LE [8:12], and the RPM-header-blob length u32 LE [12:16]. The RPM header import
//     blob follows immediately and is exactly that many bytes; it carries no 8e ad e8 01 lead (parseRPMHeader
//     already treats the lead as optional). A per-block trailer after the header blob is not needed to extract
//     the package and is ignored.
//
// A package is rewritten in place (its slot updated to point at a new blob), so among LIVE slots each package
// index appears once. The blob generation increments on every write, so should a corrupt DB present two live
// slots for one index, keeping the highest generation is the librpm-correct resolution: the highest generation
// is the most recent (current) write, exactly the blob librpm itself would read. The failure direction matches
// bdb.go: surface a real, previously-installed package, never fabricate one.
const (
	ndbSlotSize           = 16   // one slot directory entry
	ndbSlotEntriesPerPage = 256  // 4096 / ndbSlotSize; the ndb slot page is a fixed 4096 bytes
	ndbSlotPageSize       = 4096 // fixed slot-page size
	ndbBlkSize            = 16   // blob offsets and counts are in 16-byte blocks
	ndbBlobHeaderSize     = 16   // BlbS magic(4) + package index(4) + generation(4) + header-blob length(4)
	ndbFirstSlot          = 2    // slot entries 0..1 overlay the file header
)

var (
	ndbHeaderMagic = [4]byte{'R', 'p', 'm', 'P'}
	ndbSlotMagic   = [4]byte{'S', 'l', 'o', 't'}
	ndbBlobMagic   = [4]byte{'B', 'l', 'b', 'S'}
)

// ndbCandidate is one package index's best (highest-generation) parsed header.
type ndbCandidate struct {
	gen             uint32
	name, evr, arch string
}

// rpmNDBComponents reads an ndb-backend rpmdb at dbPath and returns one component per installed package,
// mirroring rpmSQLiteComponents and rpmBDBComponents. Best-effort + hardened for an untrusted DB: an error is
// returned ONLY on context cancellation (so a timed-out read surfaces as a failure, never a silently-truncated
// success); an absent/non-ndb/malformed DB or a parse panic degrades to (nil, nil). namespace is the PURL
// namespace and tag the distro qualifier, both passed straight to osComponent.
func rpmNDBComponents(ctx context.Context, dbPath, namespace, tag string) (out []sbom.Component, err error) {
	defer func() {
		if recover() != nil { // the DB is untrusted; a parse panic must degrade to no components
			out, err = nil, nil
		}
	}()
	fi, statErr := os.Lstat(dbPath) // regular-file guard: never follow a symlinked DB out of the rootfs
	if statErr != nil || !fi.Mode().IsRegular() {
		return nil, nil
	}
	size := fi.Size()
	if size < ndbBlobHeaderSize || size > maxDBBytes {
		return nil, nil // too small to hold a header, or larger than the bomb-guard budget
	}
	f, openErr := os.Open(dbPath)
	if openErr != nil {
		return nil, nil
	}
	defer func() { _ = f.Close() }()

	var hdr [ndbBlobHeaderSize]byte
	if _, e := f.ReadAt(hdr[:], 0); e != nil {
		return nil, nil
	}
	if [4]byte(hdr[0:4]) != ndbHeaderMagic {
		return nil, nil // not an ndb pkgdb (a sqlite/BerkeleyDB rootfs)
	}
	slotNPages := binary.LittleEndian.Uint32(hdr[12:16])
	if slotNPages == 0 {
		return nil, nil
	}
	slotAreaLen := int64(slotNPages) * ndbSlotPageSize
	if slotAreaLen <= 0 || slotAreaLen > size { // *4096 overflow, or a slot area that runs past EOF
		return nil, nil
	}
	slots := make([]byte, slotAreaLen)
	if _, e := f.ReadAt(slots, 0); e != nil {
		return nil, nil
	}
	nSlots := int64(slotNPages) * ndbSlotEntriesPerPage

	best := map[uint32]ndbCandidate{} // package index -> highest-generation parse
	var order []uint32                // package indices in first-seen order, for deterministic output
	var total int64
	for i := int64(ndbFirstSlot); i < nSlots; i++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		off := i * ndbSlotSize
		if off+ndbSlotSize > slotAreaLen {
			break
		}
		s := slots[off : off+ndbSlotSize]
		if [4]byte(s[0:4]) != ndbSlotMagic {
			continue // an unused slot entry
		}
		pkgIdx := binary.LittleEndian.Uint32(s[4:8])
		blkOff := binary.LittleEndian.Uint32(s[8:12])
		blkCnt := binary.LittleEndian.Uint32(s[12:16])
		if pkgIdx == 0 || blkOff == 0 || blkCnt == 0 {
			continue // an empty or deleted slot
		}
		blobStart := int64(blkOff) * ndbBlkSize
		blobRegion := int64(blkCnt) * ndbBlkSize
		if blobStart < slotAreaLen || blobRegion < ndbBlobHeaderSize {
			continue // a blob lives in the blob area and holds at least its own header
		}
		if blobStart+blobRegion > size || blobStart+blobRegion < blobStart {
			continue // region past EOF, or a *16 overflow: skip, never fabricate
		}
		var bh [ndbBlobHeaderSize]byte
		if _, e := f.ReadAt(bh[:], blobStart); e != nil {
			continue
		}
		if [4]byte(bh[0:4]) != ndbBlobMagic {
			continue // not a blob header at the slot's offset
		}
		if binary.LittleEndian.Uint32(bh[4:8]) != pkgIdx {
			continue // the blob's package index disagrees with its slot: corrupt/relocated, skip
		}
		gen := binary.LittleEndian.Uint32(bh[8:12])
		blobLen := binary.LittleEndian.Uint32(bh[12:16])
		if blobLen == 0 || int64(blobLen) > blobRegion-ndbBlobHeaderSize || blobLen > rpmMaxBlobLen {
			continue // declared length exceeds its region or the per-blob cap
		}
		if int64(len(order)) >= maxPackages || total >= maxDBBytes {
			break // package-count + total-byte budgets (bomb guard)
		}
		blob := make([]byte, blobLen)
		if _, e := f.ReadAt(blob, blobStart+ndbBlobHeaderSize); e != nil {
			continue
		}
		total += int64(blobLen)
		name, evr, arch, ok := safeParseRPMHeader(blob)
		if !ok {
			continue
		}
		if prev, seen := best[pkgIdx]; seen {
			if gen <= prev.gen {
				continue // keep the higher-generation blob for this package index
			}
		} else {
			order = append(order, pkgIdx)
		}
		best[pkgIdx] = ndbCandidate{gen: gen, name: name, evr: evr, arch: arch}
	}
	for _, pkgIdx := range order {
		c := best[pkgIdx]
		if comp, ok := osComponent("rpm", namespace, c.name, c.evr, c.arch, tag); ok {
			comp.Location = dbPath // attribute the component to the DB's image layer
			out = append(out, comp)
		}
	}
	return out, nil
}
