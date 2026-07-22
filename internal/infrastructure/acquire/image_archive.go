package acquire

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	v1tarball "github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// isLocalImageArchive reports whether ref points at an on-disk container-image archive
// (a `docker save` tarball, optionally gzip-compressed). This is the airgapped path: the
// image was exported to a file and shipped offline (e.g. an SFTP bundle), so there is no
// registry to pull from. Only an existing regular file with an image-archive extension
// qualifies — a bare "alpine:latest" style reference never matches (it has no such suffix
// and is not a path on disk), so registry pulls are unaffected.
func isLocalImageArchive(ref string) bool {
	low := strings.ToLower(strings.TrimSpace(ref))
	if !(strings.HasSuffix(low, ".tar") || strings.HasSuffix(low, ".tar.gz") || strings.HasSuffix(low, ".tgz")) {
		return false
	}
	fi, err := os.Stat(ref)
	return err == nil && fi.Mode().IsRegular()
}

// acquireImageArchive loads a local `docker save` tarball into an OCI layout for SCA, entirely
// in-process (go-containerregistry) — no daemon, no registry, no external crane. This is the
// offline counterpart to acquireImage: identical downstream shape (an OCI layout in Dir that
// syft scans as oci-dir, plus optional rootfs materialization), so the rest of the pipeline is
// unchanged. A gzip-compressed archive (.tar.gz/.tgz) is decompressed once into the workspace
// (re-reading a gzip stream per layer would be O(layers) slow), then loaded seekably.
func (a *Acquirer) acquireImageArchive(_ context.Context, ref string) (*ports.Workspace, error) {
	dir, err := os.MkdirTemp("", "synapse-ws-*")
	if err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(dir) }

	tarPath := ref
	low := strings.ToLower(ref)
	if strings.HasSuffix(low, ".gz") || strings.HasSuffix(low, ".tgz") {
		tarPath = filepath.Join(dir, "image.tar")
		if derr := gunzipTo(ref, tarPath, a.maxWorkspaceBytes); derr != nil {
			_ = cleanup()
			return nil, fmt.Errorf("decompress image archive: %w", derr)
		}
	}

	// nil tag: the archive must contain a single image (the one `docker save <ref>` produced).
	img, err := v1tarball.ImageFromPath(tarPath, nil)
	if err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("read image archive %q: %w", filepath.Base(ref), err)
	}

	layoutDir := filepath.Join(dir, "image") // syft scans this as an oci-dir, same as a crane pull
	lp, err := layout.Write(layoutDir, empty.Index)
	if err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("init oci layout: %w", err)
	}
	if err := lp.AppendImage(img); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("write oci layout: %w", err)
	}

	ws := &ports.Workspace{Dir: layoutDir, Image: readImageInfo(layoutDir, ref), Cleanup: cleanup}
	if a.materializeRootFS {
		rootfs := filepath.Join(dir, "rootfs")
		if err := extractOCIRootFS(context.Background(), layoutDir, rootfs, a.maxWorkspaceBytes); err != nil {
			ws.RootFSNote = truncate(err.Error(), 200)
		} else {
			ws.RootFS = rootfs
		}
	}
	return ws, nil
}

// gunzipTo decompresses src (a gzip file) into dst, bounded by maxBytes as a decompression-bomb
// guard (0/negative ⇒ the MaxWorkspaceBytes default).
func gunzipTo(src, dst string, maxBytes int64) error {
	limit := maxBytes
	if limit <= 0 {
		limit = MaxWorkspaceBytes
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	// +1 so an archive exactly at the cap isn't falsely flagged; >limit is the failure.
	n, err := io.Copy(out, io.LimitReader(gz, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("%w: decompressed image archive exceeds the %d-byte workspace cap", shared.ErrValidation, limit)
	}
	return nil
}
