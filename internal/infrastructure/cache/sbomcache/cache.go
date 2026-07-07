// Package sbomcache is a filesystem-backed, content-addressed cache of generated SBOMs. It implements the
// analyzer-version cache-invalidation idea (learned from Trivy): the cache key folds together a cheap
// digest of the workspace CONTENT and the SBOM producer VERSION, so an unchanged tree re-scanned with the
// same producer reuses the cataloged SBOM, and a producer bump makes every prior entry a miss.
//
// The workspace digest is metadata-based (path + size + mtime), which is deliberately CHEAPER than reading
// and hashing every byte — the whole point is to be faster than the Syft cataloging pass it replaces. That
// matches Trivy's filesystem-cache posture: a content edit that preserves BOTH size and mtime (pathological;
// editors and git checkouts always bump mtime) is the only stale case, and it is bounded by the fact that a
// producer version bump always invalidates. The cache is opt-in.
package sbomcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxDigestFiles = 300000 // cap the metadata walk; a larger tree skips caching rather than stalling
	maxCacheFiles  = 512    // bound the cache directory; oldest entries are pruned past this
)

// Cache stores generated SBOMs under a root directory, one JSON file per key.
type Cache struct {
	root string
}

var _ ports.SBOMCache = (*Cache)(nil)

// New returns a cache rooted at dir. The directory is created lazily on the first Store.
func New(dir string) *Cache { return &Cache{root: dir} }

// envelope preserves SBOM.Raw (which is json:"-" on the domain type) alongside the SBOM, so a cache hit
// hands a downstream detector the EXACT original producer document rather than a lossy reconstruction.
type envelope struct {
	SBOM *sbom.SBOM `json:"sbom"`
	Raw  []byte     `json:"raw,omitempty"`
}

// Load returns the cached SBOM for (dir, producerVersion) when present. Any miss reason (no version,
// uncomputable digest, absent/corrupt file) returns ok=false with no error, so the caller just regenerates.
func (c *Cache) Load(ctx context.Context, dir, producerVersion string) (*sbom.SBOM, bool, error) {
	key := c.key(ctx, dir, producerVersion)
	if key == "" {
		return nil, false, nil
	}
	data, err := os.ReadFile(filepath.Join(c.root, key+".json"))
	if err != nil {
		return nil, false, nil // miss (not found / unreadable) — never fatal
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil || env.SBOM == nil {
		return nil, false, nil // a corrupt entry is a miss, not a failure
	}
	env.SBOM.Raw = env.Raw // restore the non-serialized original document
	return env.SBOM, true, nil
}

// Store caches doc for (dir, producerVersion). Best-effort: an uncomputable key or a write error is
// returned but the caller ignores it (the scan already has its SBOM).
func (c *Cache) Store(ctx context.Context, dir, producerVersion string, doc *sbom.SBOM) error {
	if doc == nil {
		return nil
	}
	key := c.key(ctx, dir, producerVersion)
	if key == "" {
		return nil
	}
	if err := os.MkdirAll(c.root, 0o755); err != nil {
		return fmt.Errorf("sbom cache: mkdir: %w", err)
	}
	data, err := json.Marshal(envelope{SBOM: doc, Raw: doc.Raw})
	if err != nil {
		return fmt.Errorf("sbom cache: marshal: %w", err)
	}
	dst := filepath.Join(c.root, key+".json")
	tmp, err := os.CreateTemp(c.root, key+".*.tmp")
	if err != nil {
		return fmt.Errorf("sbom cache: temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("sbom cache: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("sbom cache: close: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil { // atomic publish
		_ = os.Remove(tmpName)
		return fmt.Errorf("sbom cache: rename: %w", err)
	}
	c.prune()
	return nil
}

// key folds the workspace content digest with the producer version. Returns "" (no caching) when the
// producer version is unknown — never serve an SBOM that can't be soundly version-keyed.
func (c *Cache) key(ctx context.Context, dir, producerVersion string) string {
	if strings.TrimSpace(producerVersion) == "" {
		return ""
	}
	digest := workspaceMetaDigest(ctx, dir)
	if digest == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(digest + "\x00" + producerVersion))
	return hex.EncodeToString(sum[:])
}

// workspaceMetaDigest is a cheap, order-independent fingerprint of the tree: sorted (relpath, size,
// mtime) over regular files, skipping .git. Returns "" if the tree is too large to fingerprint cheaply
// (then the scan just runs uncached) or on context cancellation.
func workspaceMetaDigest(ctx context.Context, dir string) string {
	var lines []string
	count := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // never follow a symlink out of the tree
		}
		if count++; count > maxDigestFiles {
			return errTooLarge
		}
		info, e := d.Info()
		if e != nil {
			return nil
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(path, dir), string(os.PathSeparator))
		lines = append(lines, rel+"\x00"+strconv.FormatInt(info.Size(), 10)+"\x00"+strconv.FormatInt(info.ModTime().UnixNano(), 10))
		return nil
	})
	if err != nil {
		return "" // too large, cancelled, or a walk error → skip caching
	}
	if len(lines) == 0 {
		return "" // empty or missing tree: nothing to key on, and every empty tree would collide → skip
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// errTooLarge stops the digest walk once the tree exceeds the cheap-fingerprint cap.
var errTooLarge = errors.New("workspace too large to fingerprint")

// staleTmpAge is how old an orphaned temp file must be before prune reclaims it; the margin avoids racing a
// concurrent in-flight Store's temp.
const staleTmpAge = time.Hour

// prune reclaims crash-orphaned temp files and keeps the cache directory bounded by deleting the oldest
// entries once it exceeds maxCacheFiles. Best-effort: any error is ignored (an over-full cache is a
// performance issue, not a correctness one).
func (c *Cache) prune() {
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return
	}
	type ent struct {
		name  string
		mtime int64
	}
	now := time.Now()
	files := make([]ent, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		switch {
		case strings.HasSuffix(e.Name(), ".tmp"):
			// A temp orphaned by a crash between CreateTemp and Rename; only reclaim once it's clearly stale.
			if now.Sub(info.ModTime()) > staleTmpAge {
				_ = os.Remove(filepath.Join(c.root, e.Name()))
			}
		case strings.HasSuffix(e.Name(), ".json"):
			files = append(files, ent{e.Name(), info.ModTime().UnixNano()})
		}
	}
	if len(files) <= maxCacheFiles {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mtime < files[j].mtime }) // oldest first
	for _, f := range files[:len(files)-maxCacheFiles] {
		_ = os.Remove(filepath.Join(c.root, f.name))
	}
}
