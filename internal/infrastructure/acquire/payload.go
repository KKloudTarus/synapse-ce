package acquire

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// This file extracts the file payload of a standalone package artifact (.rpm / .deb) into the workspace so
// the SBOM generator catalogs the binaries the package SHIPS (e.g. a Go binary and its embedded module
// list), not just the package's own header identity. A loose .rpm/.deb otherwise yields only name/version
// from its metadata — the bundled-dependency CVE surface (which is where the real risk lives for an agent
// packaged as a single Go binary) stays invisible.
//
// Everything here reads bytes and writes bounded, path-confined regular files under a caller-owned temp
// dir; nothing is executed. Extraction shares the same hardening as the image-layer/zip paths (safeJoin
// path confinement, per-file + total size caps, entry-count cap, symlink/device entries skipped).

const maxCPIONameLen = 8192 // per-entry path-length cap

var (
	rpmLeadMagic   = []byte{0xED, 0xAB, 0xEE, 0xDB}
	rpmHeaderMagic = []byte{0x8E, 0xAD, 0xE8}
	arMagic        = []byte("!<arch>\n")
)

// extractRPMPayload extracts a .rpm's cpio payload (its shipped files) into destDir, bounded to maxBytes.
func extractRPMPayload(rpmPath, destDir string, maxBytes int64) error {
	f, err := os.Open(rpmPath) // #nosec G304 -- staged copy under our own fresh temp dir
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	off, err := rpmPayloadOffset(f)
	if err != nil {
		return err
	}
	dr, closeFn, err := decompressStream(io.NewSectionReader(f, off, fi.Size()-off))
	if err != nil {
		return err
	}
	defer closeFn()
	return extractCPIO(io.LimitReader(dr, maxBytes), destDir)
}

// rpmPayloadOffset walks the RPM structure (lead → signature header [padded to 8] → main header) and
// returns the byte offset where the compressed cpio payload begins. Header sizes are bounds-checked.
func rpmPayloadOffset(f io.ReaderAt) (int64, error) {
	lead := make([]byte, 96)
	if _, err := f.ReadAt(lead, 0); err != nil {
		return 0, fmt.Errorf("rpm: read lead: %w", err)
	}
	if !bytes.Equal(lead[0:4], rpmLeadMagic) {
		return 0, errors.New("rpm: bad lead magic")
	}
	sigEnd, err := rpmHeaderEnd(f, 96)
	if err != nil {
		return 0, err
	}
	sigEnd = (sigEnd + 7) &^ 7 // signature header is padded to an 8-byte boundary
	return rpmHeaderEnd(f, sigEnd)
}

// rpmHeaderEnd reads the 16-byte header intro at off and returns the offset just past the header store.
func rpmHeaderEnd(f io.ReaderAt, off int64) (int64, error) {
	intro := make([]byte, 16)
	if _, err := f.ReadAt(intro, off); err != nil {
		return 0, fmt.Errorf("rpm: read header intro: %w", err)
	}
	if !bytes.Equal(intro[0:3], rpmHeaderMagic) {
		return 0, errors.New("rpm: bad header magic")
	}
	nindex := binary.BigEndian.Uint32(intro[8:12])
	hsize := binary.BigEndian.Uint32(intro[12:16])
	if nindex > 1<<20 || hsize > 1<<30 { // header index/store sanity bounds
		return 0, fmt.Errorf("rpm: header too large (nindex=%d hsize=%d)", nindex, hsize)
	}
	return off + 16 + int64(nindex)*16 + int64(hsize), nil
}

// extractDebPayload extracts a .deb's data.tar.* (its shipped files) into destDir, bounded to maxBytes.
func extractDebPayload(debPath, destDir string, maxBytes int64) error {
	f, err := os.Open(debPath) // #nosec G304 -- staged copy under our own fresh temp dir
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	br := bufio.NewReader(f)
	magic := make([]byte, len(arMagic))
	if _, err := io.ReadFull(br, magic); err != nil || !bytes.Equal(magic, arMagic) {
		return errors.New("deb: not an ar archive")
	}
	for {
		hdr := make([]byte, 60)
		if _, err := io.ReadFull(br, hdr); err != nil {
			if err == io.EOF {
				return errors.New("deb: no data.tar member found")
			}
			return err
		}
		name := strings.TrimRight(strings.TrimRight(string(hdr[0:16]), " "), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("deb: bad ar member size: %w", err)
		}
		if strings.HasPrefix(name, "data.tar") {
			dr, closeFn, derr := decompressStream(io.LimitReader(br, size))
			if derr != nil {
				return derr
			}
			defer closeFn()
			// Reuse the package's hardened tar extractor (safeJoin + per-file cap + symlink skip).
			return extractTarStream(io.LimitReader(dr, maxBytes), destDir, maxBytes)
		}
		if _, err := io.CopyN(io.Discard, br, size); err != nil {
			return err
		}
		if size%2 == 1 { // ar members are padded to an even boundary
			if _, err := br.Discard(1); err != nil {
				return err
			}
		}
	}
}

// decompressStream sniffs the leading magic bytes and wraps r in the matching decompressor. An
// uncompressed tar (deb "data.tar") passes through. Supports gzip, xz, zstd, bzip2 — the compressors
// rpm/deb use. It returns a cleanup func the caller MUST defer: the zstd decoder in particular spawns
// goroutines that leak in a long-lived process unless its Close runs (RHEL 8+ rpms default to zstd).
func decompressStream(r io.Reader) (io.Reader, func(), error) {
	noop := func() {}
	br := bufio.NewReader(r)
	magic, err := br.Peek(6)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return nil, noop, err
	}
	switch {
	case bytes.HasPrefix(magic, []byte{0x1F, 0x8B}):
		gz, gerr := gzip.NewReader(br)
		if gerr != nil {
			return nil, noop, gerr
		}
		return gz, func() { _ = gz.Close() }, nil
	case bytes.HasPrefix(magic, []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}):
		xr, xerr := xz.NewReader(br) // xz.Reader has no Close
		if xerr != nil {
			return nil, noop, xerr
		}
		return xr, noop, nil
	case bytes.HasPrefix(magic, []byte{0x28, 0xB5, 0x2F, 0xFD}):
		zr, zerr := zstd.NewReader(br, zstd.WithDecoderConcurrency(1))
		if zerr != nil {
			return nil, noop, zerr
		}
		return zr.IOReadCloser(), zr.Close, nil
	case bytes.HasPrefix(magic, []byte{'B', 'Z', 'h'}):
		return bzip2.NewReader(br), noop, nil
	default:
		return br, noop, nil // treat as an uncompressed tar (deb allows a bare data.tar); tar reader errors cleanly if not
	}
}

// extractCPIO extracts an SVR4 "newc" cpio stream (the RPM payload format) into destDir. Only directories
// and regular files are written; symlink/device/FIFO entries are skipped (their body is still consumed to
// keep the stream aligned). Total size is bounded by the caller's LimitReader; per-file by the shared cap.
func extractCPIO(r io.Reader, destDir string) error {
	br := bufio.NewReader(r)
	if err := os.MkdirAll(filepath.Clean(destDir), 0o750); err != nil {
		return err
	}
	entries := 0
	hdr := make([]byte, 110)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil // clean end of stream
			}
			return err
		}
		if m := string(hdr[0:6]); m != "070701" && m != "070702" {
			return fmt.Errorf("cpio: bad entry magic %q", m)
		}
		field := func(i int) (int64, error) {
			return strconv.ParseInt(string(hdr[6+i*8:6+i*8+8]), 16, 64)
		}
		mode, e1 := field(1)
		fsize, e2 := field(6)
		namesize, e3 := field(11)
		if e1 != nil || e2 != nil || e3 != nil {
			return errors.New("cpio: non-hex numeric header field")
		}
		if namesize <= 0 || namesize > maxCPIONameLen || fsize < 0 {
			return fmt.Errorf("cpio: bad sizes (name=%d file=%d)", namesize, fsize)
		}
		name := make([]byte, namesize)
		if _, err := io.ReadFull(br, name); err != nil {
			return err
		}
		if err := discardPad(br, 110+int(namesize)); err != nil { // name padded so data starts on a 4-byte boundary
			return err
		}
		n := strings.TrimRight(string(name), "\x00")
		if n == "TRAILER!!!" {
			return nil
		}
		if entries++; entries > maxArchiveEntries {
			return errors.New("cpio: too many entries")
		}
		if err := writeCPIOEntry(destDir, n, mode, fsize, br); err != nil {
			return err
		}
		if err := discardPad(br, int(fsize)); err != nil { // file data padded to a 4-byte boundary
			return err
		}
	}
}

// writeCPIOEntry materializes one cpio entry. Directories and regular files (confined via safeJoin) are
// written; anything else (symlink/device/FIFO) is skipped after consuming its body. A regular file's body
// must be read as exactly fsize bytes to keep the stream aligned, so it cannot use copyCapped (which reads
// max+1); the per-file cap is enforced up-front and the total by the caller's stream-level LimitReader.
func writeCPIOEntry(dest, name string, mode, fsize int64, br *bufio.Reader) error {
	switch mode & 0xF000 {
	case 0x4000: // directory
		target, err := safeJoin(dest, name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(target, 0o750); err != nil {
			return err
		}
		_, err = io.CopyN(io.Discard, br, fsize) // dirs carry no body, but drain any declared bytes to stay aligned
		return err
	case 0x8000: // regular file
		if fsize > maxArchiveFileBytes {
			return fmt.Errorf("cpio: entry %q exceeds the per-file cap", name)
		}
		target, err := safeJoin(dest, name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		_, err = io.CopyN(out, br, fsize)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		return err
	default: // symlink / device / FIFO / socket — never created; consume the body to stay aligned
		_, err := io.CopyN(io.Discard, br, fsize)
		return err
	}
}

// discardPad skips the bytes that pad `consumed` up to the cpio 4-byte alignment boundary.
func discardPad(br *bufio.Reader, consumed int) error {
	if pad := (4 - consumed%4) % 4; pad > 0 {
		_, err := br.Discard(pad)
		return err
	}
	return nil
}
