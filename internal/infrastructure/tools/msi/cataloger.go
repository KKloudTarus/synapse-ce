package msi

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Bounds for a directory walk (a scanned tree could be arbitrarily large / hostile).
const (
	maxMSIFiles   = 256
	maxMSIFileLen = 512 << 20 // skip anything larger than 512 MiB (a real installer's tables are tiny)
)

// Cataloger discovers Windows Installer (.msi) artifacts under a workspace directory and recovers each
// installer's product identity from its Property table, emitting one SBOM component per .msi. It never
// executes an installer — it only reads compound-file bytes. Best-effort: an unreadable/corrupt .msi is
// skipped, never fatal to the scan.
type Cataloger struct{}

var _ ports.ArtifactCataloger = (*Cataloger)(nil)

// New returns a Cataloger.
func New() *Cataloger { return &Cataloger{} }

// CatalogArtifacts walks dir for *.msi files and returns a component for each one whose Property table
// yields a product name. Directory-walk and per-file errors are swallowed (best-effort inventory); a
// canceled context stops the walk.
func (c *Cataloger) CatalogArtifacts(ctx context.Context, dir string) ([]sbom.Component, error) {
	if dir == "" {
		return nil, nil
	}
	var out []sbom.Component
	seen := 0
	// Capture the walk error: a canceled/timed-out scan must propagate (never report a partial catalog as
	// success). Per-entry read errors are swallowed inside the callback, so the only non-nil return here is
	// the context error.
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, keep walking
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Only regular files: skip dirs, and — critically — symlinks/devices/FIFOs. A planted
		// `x.msi -> /dev/zero` would otherwise be read forever (OOM), and a FIFO would hang the scan.
		// WalkDir does not follow symlinks, and d.Type() reports the link itself (from Lstat).
		if !d.Type().IsRegular() || !strings.EqualFold(filepath.Ext(path), ".msi") {
			return nil
		}
		if seen >= maxMSIFiles {
			return filepath.SkipAll
		}
		seen++
		if comp, ok := catalogFile(path, dir); ok {
			out = append(out, comp)
		}
		return nil
	})
	return out, walkErr
}

// catalogFile parses one .msi and builds a component. ok is false when the file is too large, unreadable,
// not a valid MSI, or carries no product name.
func catalogFile(path, root string) (sbom.Component, bool) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > maxMSIFileLen {
		return sbom.Component{}, false
	}
	data, err := os.ReadFile(path) //nolint:gosec // path comes from a bounded WalkDir over the scan workspace
	if err != nil {
		return sbom.Component{}, false
	}
	info, err := Parse(data)
	if err != nil {
		return sbom.Component{}, false
	}
	name := info.ProductName
	if name == "" {
		return sbom.Component{}, false // no identity recovered — nothing useful to report
	}
	loc := path
	if rel, rerr := filepath.Rel(root, path); rerr == nil {
		loc = rel
	}
	comp := sbom.Component{
		Name:     name,
		Version:  info.ProductVersion,
		PURL:     msiPURL(info),
		Scope:    sbom.ScopeProduction,
		Location: loc,
	}
	if info.Manufacturer != "" {
		comp.Supplier = info.Manufacturer
		comp.SupplierSource = sbom.SupplierDeclared // the MSI Property table is the product's own manifest
	}
	return comp, true
}

// msiPURL builds a best-effort package URL. There is no registered purl type for a Windows Installer product,
// so we use the "generic" type namespaced by the (slugged) manufacturer — enough to identify + dedup the
// artifact in the SBOM. (Generic PURLs are not advisory-matchable; an MSI is cataloged for inventory, not
// CVE lookup, which has no reliable identifier for arbitrary installed products.)
func msiPURL(info Info) string {
	name := slug(info.ProductName)
	if name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:generic/")
	if ns := slug(info.Manufacturer); ns != "" {
		b.WriteString(ns)
		b.WriteString("/")
	}
	b.WriteString(name)
	if v := strings.TrimSpace(info.ProductVersion); v != "" {
		b.WriteString("@")
		b.WriteString(v)
	}
	return b.String()
}

// slug lowercases and reduces a display string to a PURL-safe token (alphanumerics and '.', '-', '_';
// runs of other characters collapse to a single '-').
func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_':
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteRune('-')
				dash = true
			}
		}
	}
	return strings.Trim(b.String(), "-._")
}
