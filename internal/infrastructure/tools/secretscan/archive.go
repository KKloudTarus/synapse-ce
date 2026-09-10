package secretscan

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Secret scanning INSIDE archives. A credential is often shipped inside a .jar/.war (ZIP) or a release
// .tar.gz, invisible to a file-by-file walk that skips those extensions. This extracts archive members and
// runs the same detectors, allowlist, and redaction over each text member, attributing a hit to
// "<archive>!<member>". It is fully bounded against a decompression bomb: a per-member byte cap, a per-archive
// decompressed-bytes budget that is ALSO charged against the scan-wide byte budget (so a directory of many
// bombs cannot collectively exceed it), an entry-count cap charged for EVERY archive member (dirs included),
// and a nesting-depth cap (a jar inside a war). Members are never written to disk (member names are display
// labels only, so there is no zip-slip), and a corrupt archive or member is skipped, never a scan failure.
// (EPIC #860 D6.9.)

const (
	maxArchiveFileBytes  = 64 << 20  // largest archive file read from disk into memory
	maxArchiveEntries    = 20000     // members counted across one top-level archive (dirs included)
	maxArchiveTotalBytes = 256 << 20 // per-archive decompressed cap, further clamped to the scan-wide budget
	maxArchiveDepth      = 2         // archive-in-archive nesting limit (a jar inside a war)
)

// archiveExts are the container formats the secret scan looks INSIDE. jar/war/ear are ZIP; tgz/gz are gzip (of
// a tar or a single file); tar is uncompressed.
var archiveExts = map[string]bool{
	".zip": true, ".jar": true, ".war": true, ".ear": true,
	".tar": true, ".gz": true, ".tgz": true,
}

// archiveBudget bounds one top-level archive's extraction: total members counted and total decompressed bytes.
// maxBytes is set by the caller to min(maxArchiveTotalBytes, remaining scan-wide byte budget). bytes, once the
// scan returns, is charged back to the scan-wide budget so nested/subsequent archives cannot exceed it.
type archiveBudget struct {
	entries    int
	maxEntries int
	bytes      int64
	maxBytes   int64
}

func (b *archiveBudget) exhausted() bool {
	return b.entries >= b.maxEntries || b.bytes >= b.maxBytes
}

// openAndReadArchive reads an archive file into memory bounded by min(limit, maxArchiveFileBytes), with the
// same open-time and post-read stability checks as a loose file so a swapped/growing archive is rejected.
func openAndReadArchive(root *os.Root, rel string, walkInfo fs.FileInfo, limit int64) ([]byte, error) {
	if limit > maxArchiveFileBytes {
		limit = maxArchiveFileBytes
	}
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	openedInfo, err := f.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(walkInfo, openedInfo) ||
		openedInfo.Size() == 0 || openedInfo.Size() > limit {
		return nil, fmt.Errorf("opened archive %q changed", rel)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("read archive %q", rel)
	}
	after, err := f.Stat()
	if err != nil || !stableFileSnapshot(openedInfo, after, int64(len(data))) {
		return nil, fmt.Errorf("archive %q changed during scan", rel)
	}
	return data, nil
}

// scanArchiveData scans the members of an archive held in data (dispatched by ext). Bounded by budget and
// depth. Returns true if a scan cap was hit (report should be marked truncated).
func (s *Scanner) scanArchiveData(ctx context.Context, displayPath string, data []byte, ext string, seen map[string]bool, out *[]ports.SecretRawFinding, limit int, budget *archiveBudget, depth int) bool {
	if ctx.Err() != nil || depth > maxArchiveDepth {
		return true
	}
	switch ext {
	case ".zip", ".jar", ".war", ".ear":
		return s.scanZip(ctx, displayPath, data, seen, out, limit, budget, depth)
	case ".tar":
		return s.scanTar(ctx, displayPath, bytes.NewReader(data), seen, out, limit, budget, depth)
	case ".gz", ".tgz":
		return s.scanGzip(ctx, displayPath, data, ext, seen, out, limit, budget, depth)
	}
	return false
}

// scanMember scans one extracted member's content. It does NOT count the entry (the zip/tar/gzip caller counts
// every entry, dirs included, so the entry cap cannot be bypassed by type filtering); it charges the bytes it
// reads to the budget EVEN on a read error (so a corrupt member that decompresses far then fails a checksum is
// still charged), recurses when the member is itself an archive (within depth), and otherwise runs the
// detectors over its text. Returns true when a cap was hit and extraction should stop.
func (s *Scanner) scanMember(ctx context.Context, memberPath string, r io.Reader, seen map[string]bool, out *[]ports.SecretRawFinding, limit int, budget *archiveBudget, depth int) bool {
	if budget.exhausted() || len(*out) >= limit {
		return true
	}
	remaining := budget.maxBytes - budget.bytes // a single member is capped at the loose-file size too
	if remaining > maxFileBytes {
		remaining = maxFileBytes
	}
	data, rerr := io.ReadAll(io.LimitReader(r, remaining+1))
	budget.bytes += int64(len(data)) // charge what was read, even on rerr (a bomb that fails a checksum still cost)
	if int64(len(data)) > remaining {
		return true // member exceeds the per-member cap: stop rather than scan a truncated giant
	}
	if rerr != nil {
		return budget.exhausted()
	}
	ext := strings.ToLower(path.Ext(memberPath))
	if archiveExts[ext] && depth < maxArchiveDepth {
		return s.scanArchiveData(ctx, memberPath, data, ext, seen, out, limit, budget, depth+1)
	}
	if isBinary(data) {
		return false
	}
	return s.scanContent(memberPath, data, seen, out, limit)
}

func (s *Scanner) scanZip(ctx context.Context, displayPath string, data []byte, seen map[string]bool, out *[]ports.SecretRawFinding, limit int, budget *archiveBudget, depth int) bool {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	for _, f := range zr.File {
		if ctx.Err() != nil {
			return true
		}
		budget.entries++ // count every central-directory entry (dirs included) so the cap cannot be bypassed
		if budget.exhausted() || len(*out) >= limit {
			return true
		}
		if f.FileInfo().IsDir() {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			continue
		}
		stop := s.scanMember(ctx, displayPath+"!"+f.Name, rc, seen, out, limit, budget, depth)
		_ = rc.Close()
		if stop {
			return true
		}
	}
	return false
}

func (s *Scanner) scanTar(ctx context.Context, displayPath string, r io.Reader, seen map[string]bool, out *[]ports.SecretRawFinding, limit int, budget *archiveBudget, depth int) bool {
	tr := tar.NewReader(r)
	for {
		if ctx.Err() != nil {
			return true
		}
		hdr, err := tr.Next()
		if err != nil {
			return false // io.EOF or a corrupt tar: stop cleanly
		}
		budget.entries++ // count every header (dirs, symlinks, extended headers) before the type filter
		if budget.exhausted() || len(*out) >= limit {
			return true
		}
		if hdr.Typeflag == tar.TypeReg { // tar.Reader normalizes the legacy TypeRegA to TypeReg, so this covers it too
			if s.scanMember(ctx, displayPath+"!"+hdr.Name, tr, seen, out, limit, budget, depth) {
				return true
			}
			continue
		}
		// A non-regular entry is not scanned, but its body must still be charged and bounded: for a streamed
		// gz-tar, tar.Next would otherwise decompress and discard the skipped body OUTSIDE the budget.
		if hdr.Size > 0 {
			remaining := budget.maxBytes - budget.bytes
			n, _ := io.CopyN(io.Discard, tr, remaining+1)
			budget.bytes += n
			if n > remaining {
				return true // the skipped body alone exhausts the budget: stop
			}
		}
	}
}

func (s *Scanner) scanGzip(ctx context.Context, displayPath string, data []byte, ext string, seen map[string]bool, out *[]ports.SecretRawFinding, limit int, budget *archiveBudget, depth int) bool {
	// Classify by PARSING the first tar header from a bounded decompression (not a magic sniff): a valid tar
	// (including GNU format, which lacks the ustar magic) is scanned entry by entry; anything else falls back to
	// a single gzipped file. This avoids both a plain .gz whose bytes coincidentally look like a tar header and a
	// non-ustar tar being misclassified. The detection reads only the first header block; scanTar then
	// re-decompresses from a fresh reader so every entry (including the first) is scanned and budget-charged.
	if gz, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
		_, headerErr := tar.NewReader(bufio.NewReaderSize(gz, 4096)).Next()
		_ = gz.Close()
		if headerErr == nil {
			gz2, err2 := gzip.NewReader(bytes.NewReader(data))
			if err2 == nil {
				defer func() { _ = gz2.Close() }()
				return s.scanTar(ctx, displayPath, gz2, seen, out, limit, budget, depth)
			}
		}
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return false
	}
	defer func() { _ = gz.Close() }()
	budget.entries++
	if budget.exhausted() {
		return true
	}
	inner := path.Base(strings.TrimSuffix(displayPath, ext)) // "foo.txt.gz" -> member "foo.txt"
	return s.scanMember(ctx, displayPath+"!"+inner, gz, seen, out, limit, budget, depth+1)
}
