// Package jarchecksum captures the artifact SHA-1 of JVM components by hashing the JAR files in the prepared
// workspace. Syft computes a JAR digest but omits it from its CycloneDX output, so a Syft-produced SBOM
// carries no checksum for its JAR components – leaving the SBOM checksum quality element at zero and starving
// JarHashResolver, which needs a SHA-1 as input for shaded-JAR coordinate recovery.
//
// This resolver walks the workspace once, streams a SHA-1 over each JAR file (the standard Maven artifact
// SHA-1, matching the `.jar.sha1` sidecar and the coordinate indexes JarHashResolver queries), and sets
// Component.SHA1 + a Checksums entry in place for components that name that JAR and carry no SHA-1 yet. It
// only ever READS files (no exec, no network), skips symlinks (an untrusted workspace could point one out of
// tree), and is bounded against pathological inputs.
package jarchecksum

import (
	"context"
	"crypto/sha1" //nolint:gosec // artifact SHA-1 is the Maven identity form (matches .jar.sha1 + jarhash indexes), not a security primitive
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxJARs     = 20000     // bound the workspace walk (total workspace size is already capped upstream)
	maxJARBytes = 512 << 20 // never stream-hash a file larger than this (defensive)
)

// Resolver hashes workspace JARs to fill in missing component SHA-1s.
type Resolver struct{}

// New returns a resolver.
func New() *Resolver { return &Resolver{} }

var _ ports.JarChecksumResolver = (*Resolver)(nil)

// Resolve sets Component.SHA1 + a SHA1 Checksums entry for each JVM component whose JAR is present under
// wsDir and that has no SHA-1 yet. Matching is by JAR file name (the component Location's base name), so it
// is exact for a normal dependency set; a base name that appears at two different paths is left unmatched
// (never guessed). Returns the number of components whose SHA-1 was set.
func (r *Resolver) Resolve(ctx context.Context, wsDir string, comps []sbom.Component) int {
	if strings.TrimSpace(wsDir) == "" {
		return 0
	}
	// Only walk if at least one component actually needs a SHA-1 and looks like a JAR – avoids the file I/O
	// entirely for non-JVM scans.
	need := false
	for i := range comps {
		if comps[i].SHA1 == "" && isJARName(filepath.Base(comps[i].Location)) {
			need = true
			break
		}
	}
	if !need {
		return 0
	}

	byName, ambiguous := hashWorkspaceJARs(ctx, wsDir)
	set := 0
	for i := range comps {
		c := &comps[i]
		if c.SHA1 != "" {
			continue
		}
		name := filepath.Base(strings.TrimSpace(c.Location))
		if name == "" || ambiguous[name] {
			continue
		}
		if h := byName[name]; h != "" {
			c.SHA1 = h
			if !hasSHA1Checksum(c.Checksums) { // don't duplicate a SHA1 the producer already recorded in Checksums
				c.Checksums = append(c.Checksums, sbom.Checksum{Algorithm: "SHA1", Value: h})
			}
			set++
		}
	}
	return set
}

// hashWorkspaceJARs walks wsDir and returns base-name -> lowercase-hex SHA-1 for each JAR. A base name seen
// at two paths with different digests is marked ambiguous and dropped (we never guess which file a component
// refers to).
func hashWorkspaceJARs(ctx context.Context, wsDir string) (byName map[string]string, ambiguous map[string]bool) {
	byName = map[string]string{}
	ambiguous = map[string]bool{}
	count := 0
	_ = filepath.WalkDir(wsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, never fatal
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() { // skip symlinks etc. – an untrusted workspace must not hash a link out of tree
			return nil
		}
		if !isJARName(d.Name()) {
			return nil
		}
		if count >= maxJARs {
			return filepath.SkipAll
		}
		count++
		h, ok := fileSHA1(path)
		if !ok {
			return nil
		}
		name := d.Name()
		if ambiguous[name] {
			return nil
		}
		if prev, seen := byName[name]; seen {
			if prev != h { // same file name, different bytes at two paths → can't attribute; drop
				ambiguous[name] = true
				delete(byName, name)
			}
			return nil
		}
		byName[name] = h
		return nil
	})
	return byName, ambiguous
}

// fileSHA1 streams a SHA-1 over the file, refusing an over-large file. Returns "" on any error.
func fileSHA1(path string) (string, bool) {
	// This is only an early rejection. openFileNoFollow and the opened-handle Stat below are authoritative.
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxJARBytes {
		return "", false
	}
	f, err := openFileNoFollow(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	fi, err = f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxJARBytes {
		return "", false
	}
	h := sha1.New() //nolint:gosec // Maven artifact identity, not a security hash
	n, err := io.Copy(h, io.LimitReader(f, maxJARBytes+1))
	if err != nil || n > maxJARBytes {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// hasSHA1Checksum reports whether the list already carries a SHA-1 digest.
func hasSHA1Checksum(cks []sbom.Checksum) bool {
	for _, c := range cks {
		if strings.EqualFold(c.Algorithm, "SHA1") {
			return true
		}
	}
	return false
}

// isJARName reports whether a file name is a Java archive.
func isJARName(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".jar") || strings.HasSuffix(n, ".war") || strings.HasSuffix(n, ".ear")
}
