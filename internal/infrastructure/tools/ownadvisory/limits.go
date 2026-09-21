package ownadvisory

// Ingestion safety caps shared by BOTH advisory feeds (DirFeed + RemoteFeed): they bound per-entry
// decompressed size (oversized-file / zip-bomb guard), the total entry/file count (runaway tree or
// many-entry zip), and a single remote zip download (disk-bomb). Kept here, not in either feed file, so the
// cross-feed sharing is explicit rather than governed by a comment scoped to one feed.
const (
	maxAdvisoryBytes = 8 << 20   // per-entry / per-file decompressed cap (a single OSV advisory JSON is KBs)
	maxAdvisoryFiles = 2_000_000 // entry/file-count cap (bounds a runaway dir tree or a many-entry zip)
	maxZipDownload   = 1 << 30   // 1 GiB cap on a single ecosystem's all.zip download (RemoteFeed only)

	// OVAL feeds are ONE large XML per release (a distro's whole CVE set), unlike OSV's one-advisory-per-
	// small-JSON, so they need their own caps: a bigger per-file read cap (raw .xml can be ~100 MiB) and a
	// decompressed-stream cap that fails a bzip2 bomb closed.
	maxOVALFileBytes     = 128 << 20 // per-file raw read cap for an OVAL .xml / compressed document
	maxOVALSnapshotBytes = 256 << 20 // aggregate raw cap, aligned with the remote authoritative snapshot cap
	maxOVALDecompressed  = 1 << 30   // per-document decompressed stream cap
	// The aggregate cap matches the legacy document cap, retaining every legal one-document snapshot (including
	// the frozen SLES feed at ~245 MiB decompressed) while bounding expansion across multiple documents.
	maxOVALSnapshotDecompressed = maxOVALDecompressed

	// The GitLab gemnasium-db archive is one tar.gz of tens of thousands of small YAML advisories; this caps
	// the decompressed tar stream (gzip-bomb guard) so a malicious archive cannot expand without bound. The
	// real archive decompresses to well under this.
	maxGemnasiumDecompressed = 2 << 30
)

// ovalSnapshotLimits keeps production byte budgets together and gives focused tests a small-budget seam.
// All values limit bytes and must be positive in production.
type ovalSnapshotLimits struct {
	fileBytes                 int64
	snapshotBytes             int64
	documentDecompressedBytes int64
	snapshotDecompressedBytes int64
}

func defaultOVALSnapshotLimits() ovalSnapshotLimits {
	return ovalSnapshotLimits{
		fileBytes:                 maxOVALFileBytes,
		snapshotBytes:             maxOVALSnapshotBytes,
		documentDecompressedBytes: maxOVALDecompressed,
		snapshotDecompressedBytes: maxOVALSnapshotDecompressed,
	}
}
