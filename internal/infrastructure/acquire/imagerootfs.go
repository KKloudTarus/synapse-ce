package acquire

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Materializing an image rootfs assembles the layer tars of a pulled OCI layout into a single filesystem
// tree, so the owned parsers (OS-package DBs, os-release, on-disk artifacts) can read it. Layers are UNTRUSTED
// (a hostile image is a real threat model), so extraction reuses the same hardening as archive extraction:
// path traversal is blocked (safeJoin), only regular files + directories are written (symlink / hardlink /
// device entries are skipped, since a link could redirect a later read/write outside the tree), and the total
// is bounded across ALL layers (bomb guard). OCI whiteout markers are honored so a deleted file does not
// reappear from a lower layer. It is FAIL-CLOSED: any refusal returns an error and no unsafe path is written;
// the caller treats rootfs extraction as best-effort (a failure skips the rootfs, it does not abort the scan).
const (
	// whiteoutPrefix marks a deletion: ".wh.<name>" removes <name> from the assembled tree.
	whiteoutPrefix = ".wh."
	// whiteoutOpaque clears the marker's parent directory's lower-layer contents.
	whiteoutOpaque = ".wh..wh..opq"
)

// rootfsExtractor assembles OCI layers into dest, accumulating the resource caps across ALL layers.
type rootfsExtractor struct {
	dest      string
	maxBytes  int64
	total     int64             // bytes written across all layers (bomb guard)
	entries   int               // tar entries seen across all layers (bomb guard)
	layers    map[string]string // rootfs-relative (slash) path -> introducing layer diff_id; nil disables attribution
	curDiffID string            // diff_id of the layer currently being applied
}

// extractOCIRootFS materializes the assembled root filesystem of the image in the OCI layout at layoutDir into
// dest, applying each layer tar in order with OCI whiteout semantics. Producers read dest afterward. A
// malformed layout, a decompression bomb, an unsupported layer compression, or a path-traversal attempt fails
// closed with an error (the caller skips the rootfs on any error). ctx cancels a large multi-layer extraction.
// Symlinks are not materialized, so a path behind a symlinked directory will be absent; the target OS-package
// DBs (/var/lib/dpkg/status, /lib/apk/db/installed) and /etc/os-release are regular files at real paths, so
// this is sufficient for OS-package cataloging.
// The returned map attributes each materialized file (rootfs-relative, slash-separated) to the diff_id of the
// layer that last wrote it (the squashed view). It is nil when the image config's diff_ids are unavailable or
// inconsistent, in which case extraction still succeeds without attribution.
func extractOCIRootFS(ctx context.Context, layoutDir, dest string, maxBytes int64) (map[string]string, error) {
	if maxBytes <= 0 {
		maxBytes = MaxWorkspaceBytes
	}
	layers, diffIDs, err := ociLayerBlobs(layoutDir)
	if err != nil {
		return nil, err
	}
	if len(layers) == 0 {
		return nil, fmt.Errorf("%w: OCI image has no layers", shared.ErrValidation)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, fmt.Errorf("create rootfs dir: %w", err)
	}
	x := &rootfsExtractor{dest: dest, maxBytes: maxBytes}
	if diffIDs != nil {
		x.layers = make(map[string]string) // per-file layer attribution is available for this image
	}
	for i, blob := range layers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if diffIDs != nil {
			x.curDiffID = diffIDs[i]
		}
		if err := x.applyLayer(blob); err != nil {
			return nil, err
		}
	}
	return x.layers, nil
}

// ociLayerBlobs resolves the layout's image manifest to the ORDERED on-disk paths of its layer blobs. Each
// layer digest is validated (bare algo:hex) so it cannot escape the blobs directory.
func ociLayerBlobs(layoutDir string) (paths, diffIDs []string, err error) {
	man, ok := readManifest(layoutDir)
	if !ok {
		return nil, nil, fmt.Errorf("%w: cannot read OCI image manifest", shared.ErrValidation)
	}
	paths = make([]string, 0, len(man.Layers))
	for _, l := range man.Layers {
		p, ok := blobPath(layoutDir, l.Digest)
		if !ok {
			return nil, nil, fmt.Errorf("%w: invalid layer digest %q", shared.ErrValidation, l.Digest)
		}
		paths = append(paths, p)
	}
	// Layer diff_ids (uncompressed digests) come from the image config, index-aligned with the manifest layers
	// per the OCI spec, and match ImageInfo.Layers[].DiffID. They enable per-layer attribution; if the config
	// is missing or its count disagrees with the layer count, attribution is disabled (diffIDs stays nil) while
	// extraction proceeds unchanged.
	if cfg, ok := readBlobJSON[ociConfig](layoutDir, man.Config.Digest); ok && len(cfg.RootFS.DiffIDs) == len(paths) {
		diffIDs = cfg.RootFS.DiffIDs
	}
	return paths, diffIDs, nil
}

// maxZstdWindow caps the zstd decoder's decompression window so a frame declaring a huge window is
// refused BEFORE any large allocation (real OCI layers use windows well under this). It bounds the
// decoder's own memory the way applyTar's caps bound the decompressed OUTPUT.
const maxZstdWindow = 64 << 20 // 64 MiB

// applyLayer opens a layer blob, detects its compression by magic (gzip or zstd, the two OCI layer
// compressions; anything else is treated as a raw tar), and applies it onto dest. The per-entry byte
// and count caps in applyTar bound the DECOMPRESSED output, so a compression bomb is caught for either
// codec; the zstd decoder is capped to maxZstdWindow so its own window allocation is bounded too.
func (x *rootfsExtractor) applyLayer(blob string) error {
	f, err := os.Open(blob)
	if err != nil {
		return fmt.Errorf("%w: open layer blob: %v", shared.ErrValidation, err)
	}
	defer func() { _ = f.Close() }()

	br := bufio.NewReader(f)
	magic, _ := br.Peek(4)
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b: // gzip
		gz, gerr := gzip.NewReader(br)
		if gerr != nil {
			return fmt.Errorf("%w: layer gzip: %v", shared.ErrValidation, gerr)
		}
		defer func() { _ = gz.Close() }()
		return x.applyTar(tar.NewReader(gz))
	case len(magic) == 4 && magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd: // zstd
		zr, zerr := zstd.NewReader(br, zstd.WithDecoderMaxWindow(maxZstdWindow))
		if zerr != nil {
			return fmt.Errorf("%w: layer zstd: %v", shared.ErrValidation, zerr)
		}
		defer zr.Close()
		return x.applyTar(tar.NewReader(zr))
	default:
		return x.applyTar(tar.NewReader(br)) // uncompressed tar (garbage bytes surface as a tar error)
	}
}

// applyTar extracts one layer's tar stream onto dest with OCI whiteout semantics, reusing the hardened
// per-entry logic (safeJoin, copyCapped, symlink/special-file omission). Counters accumulate across layers.
func (x *rootfsExtractor) applyTar(tr *tar.Reader) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: layer tar: %v", shared.ErrValidation, err)
		}
		x.entries++
		if x.entries > maxArchiveEntries {
			return fmt.Errorf("%w: image layers have too many entries (>%d)", shared.ErrValidation, maxArchiveEntries)
		}
		base := filepath.Base(hdr.Name)
		if strings.HasPrefix(base, whiteoutPrefix) { // a whiteout marker deletes, it is not a real file
			if err := x.applyWhiteout(hdr.Name, base); err != nil {
				return err
			}
			continue
		}
		target, err := safeJoin(x.dest, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			// A later layer may put a directory where a lower layer wrote a regular file; drop the file first.
			if fi, e := os.Lstat(target); e == nil && !fi.IsDir() {
				if err := os.RemoveAll(target); err != nil {
					return fmt.Errorf("replace file with dir: %w", err)
				}
			}
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir: %w", err)
			}
			// The reverse: a later layer replaces a directory a lower layer created; drop the dir first.
			if fi, e := os.Lstat(target); e == nil && fi.IsDir() {
				if err := os.RemoveAll(target); err != nil {
					return fmt.Errorf("replace dir with file: %w", err)
				}
			}
			n, err := copyCapped(target, tr, maxArchiveFileBytes)
			if err != nil {
				return err
			}
			x.total += n
			if x.total > x.maxBytes {
				return fmt.Errorf("%w: image rootfs exceeds the %d-byte cap", shared.ErrValidation, x.maxBytes)
			}
			if x.layers != nil && x.curDiffID != "" {
				// Attribute the file to the current layer. Last writer wins, so a file replaced by a higher
				// layer is credited to that higher layer, matching the squashed view producers read.
				rel := filepath.ToSlash(strings.TrimPrefix(target, x.dest+string(os.PathSeparator)))
				x.layers[rel] = x.curDiffID
			}
		default:
			// symlink / hardlink / device / fifo: skipped (a link could redirect a later read/write outside dest).
		}
	}
	return nil
}

// applyWhiteout removes what a ".wh." marker deletes. ".wh..wh..opq" clears the marker's parent directory's
// lower-layer contents (opaque, via clearDir which removes children only – never the directory itself, so a
// root-level opaque marker cannot delete dest). ".wh.<name>" removes <name> in that directory; a name that
// resolves to ""/"."/".." is not a valid whiteout target and is skipped, so a crafted marker can neither
// delete the assembled-tree root nor (with safeJoin) escape it.
func (x *rootfsExtractor) applyWhiteout(name, base string) error {
	dir := filepath.Dir(name)
	if base == whiteoutOpaque {
		parent, err := safeJoin(x.dest, dir)
		if err != nil {
			return err
		}
		return clearDir(parent)
	}
	victim := strings.TrimPrefix(base, whiteoutPrefix)
	if victim == "" || victim == "." || victim == ".." {
		return nil // not a valid whiteout target – never delete the tree root or a traversal target
	}
	target, err := safeJoin(x.dest, filepath.Join(dir, victim))
	if err != nil {
		return err
	}
	if err := os.RemoveAll(target); err != nil {
		return fmt.Errorf("apply whiteout: %w", err)
	}
	return nil
}

// clearDir removes the direct children of dir (opaque whiteout) without removing dir itself. A missing dir is
// not an error (the opaque layer can precede the directory's creation in the assembly order).
func clearDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return fmt.Errorf("clear opaque dir: %w", err)
		}
	}
	return nil
}
