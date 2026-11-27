package acquire

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TargetFloor is the operator's limit on what a tenant may make the server acquire. The engagement
// scope is enforced before execution, but the tenant writes that scope, so it cannot protect the host
// running the server from the tenants it serves. The floor is configuration the tenant cannot write.
//
// The zero value is the strictest floor: no local path or archive is acquirable, and no git or
// registry origin that resolves to private address space is either. A server composition root
// installs it in two places: GuardPaths in front of the whole acquisition chain, for the paths a
// tenant names, and Acquirer.WithTargetFloor, for the origins it dials. The CLI, which scans its own
// checkout for its own operator, installs neither.
type TargetFloor struct {
	localRoots          []string // cleaned, as the operator wrote them; resolved when a target is checked
	archiveRoots        []string
	allowPrivateOrigins bool
}

// NewTargetFloor validates the operator's local roots. A root must be absolute, may not be the
// filesystem root, and, when it exists, must be a directory. It need not exist on every host: a
// dispatch-only API checks submissions against roots that are mounted only on the workers. Roots are
// resolved through their symlinks each time a target is checked, so a root and a target are compared
// as the kernel would open them.
//
// archiveRoots are the server's own archive stores, such as the project upload directory. They are
// not operator input about tenant reach; they name where the server itself writes the archives it
// later acquires, so they need not exist yet and are resolved when a target is checked.
//
// serverDirs are the server's own data directories (uploads, source stores, the audit file's
// directory). The roots apply to every tenant, so a local root that contains one of them, or sits
// inside one, would make every tenant's stored uploads a valid local target for every other tenant.
// Such a root is refused.
func NewTargetFloor(localRoots, archiveRoots, serverDirs []string, allowPrivateOrigins bool) (TargetFloor, error) {
	floor := TargetFloor{allowPrivateOrigins: allowPrivateOrigins}
	var protected []string
	for _, raw := range append(append([]string{}, archiveRoots...), serverDirs...) {
		dir := strings.TrimSpace(raw)
		if dir == "" {
			continue
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		protected = append(protected, resolveExistingPrefix(filepath.Clean(abs)))
	}
	for _, raw := range archiveRoots {
		root := strings.TrimSpace(raw)
		if root == "" {
			continue
		}
		abs, err := filepath.Abs(root)
		if err != nil {
			return TargetFloor{}, fmt.Errorf("%w: archive root %q: %v", shared.ErrValidation, root, err)
		}
		floor.archiveRoots = append(floor.archiveRoots, filepath.Clean(abs))
	}
	for _, raw := range localRoots {
		root := strings.TrimSpace(raw)
		if root == "" {
			continue
		}
		if !filepath.IsAbs(root) {
			return TargetFloor{}, fmt.Errorf("%w: local scan root %q is not an absolute path", shared.ErrValidation, root)
		}
		clean := filepath.Clean(root)
		resolved := resolveExistingPrefix(clean)
		if info, err := os.Stat(resolved); err == nil && !info.IsDir() {
			return TargetFloor{}, fmt.Errorf("%w: local scan root %q is not a directory", shared.ErrValidation, root)
		}
		if isFilesystemRoot(clean) || isFilesystemRoot(resolved) {
			return TargetFloor{}, fmt.Errorf("%w: local scan root %q is the filesystem root, which admits every path on the host", shared.ErrValidation, root)
		}
		for _, dir := range protected {
			if within(resolved, dir) || within(dir, resolved) {
				return TargetFloor{}, fmt.Errorf("%w: local scan root %q overlaps the server data directory %q; every tenant could read what it stores", shared.ErrValidation, root, dir)
			}
		}
		floor.localRoots = append(floor.localRoots, clean)
	}
	return floor, nil
}

func isFilesystemRoot(path string) bool {
	return path == string(filepath.Separator) || path == filepath.VolumeName(path)+string(filepath.Separator)
}

// resolvedRoots returns each local root resolved through its symlinks now. A root missing on this
// host admits nothing here, and one that has come to resolve to the filesystem root is dropped.
func (f TargetFloor) resolvedRoots() []string {
	out := make([]string, 0, len(f.localRoots))
	for _, root := range f.localRoots {
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil || isFilesystemRoot(resolved) {
			continue
		}
		out = append(out, resolved)
	}
	return out
}

// LocalEnabled reports whether any local path is acquirable under this floor.
func (f TargetFloor) LocalEnabled() bool { return len(f.localRoots) > 0 }

// AllowsPrivateOrigins reports whether a git or registry origin in private address space is acquirable.
func (f TargetFloor) AllowsPrivateOrigins() bool { return f.allowPrivateOrigins }

// CheckLocal refuses a local target outside every configured root. The target is resolved through
// its symlinks first, so /allowed/link pointing at /etc is judged as /etc.
func (f TargetFloor) CheckLocal(target string) error {
	if !f.LocalEnabled() {
		return fmt.Errorf("%w: local scan targets are disabled on this server; the operator can allow roots with SYNAPSE_LOCAL_SCAN_ROOTS", shared.ErrValidation)
	}
	clean := filepath.Clean(strings.TrimSpace(target))
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("%w: local target must be an absolute path", shared.ErrValidation)
	}
	// Judge the path as written before touching the filesystem, so a target outside every root
	// gets the same answer whether or not it exists: the refusal is not an existence oracle for
	// the host.
	if !f.lexicallyWithin(clean) {
		return errOutsideRoots
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return fmt.Errorf("%w: local target is not readable", shared.ErrValidation)
	}
	for _, root := range f.resolvedRoots() {
		if within(root, resolved) {
			return nil
		}
	}
	return errOutsideRoots
}

var errOutsideRoots = fmt.Errorf("%w: local target is outside the roots this server allows", shared.ErrValidation)

// lexicallyWithin reports whether path, as written, sits under a root as written or as resolved.
func (f TargetFloor) lexicallyWithin(path string) bool {
	for _, roots := range [][]string{f.localRoots, f.resolvedRoots()} {
		for _, root := range roots {
			if within(root, path) {
				return true
			}
		}
	}
	return false
}

// CheckLocalScope is CheckLocal for a scope entry, which may name a checkout that does not exist yet.
// The longest existing prefix is resolved through its symlinks and the rest is appended as written,
// so /allowed/link/new is judged by where link points.
func (f TargetFloor) CheckLocalScope(target string) error {
	if !f.LocalEnabled() {
		return fmt.Errorf("%w: local scan targets are disabled on this server; the operator can allow roots with SYNAPSE_LOCAL_SCAN_ROOTS", shared.ErrValidation)
	}
	clean := filepath.Clean(strings.TrimSpace(target))
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("%w: local target must be an absolute path", shared.ErrValidation)
	}
	resolved := resolveExistingPrefix(clean)
	for _, root := range f.resolvedRoots() {
		if within(root, resolved) {
			return nil
		}
	}
	// A root that does not exist on this host (an API whose workers mount it) is judged as written.
	for _, root := range f.localRoots {
		if _, err := os.Lstat(root); err != nil && within(root, clean) {
			return nil
		}
	}
	return errOutsideRoots
}

// CheckArchive refuses an archive path outside the server's own archive stores. A tenant never names
// an archive on the server's disk: uploads are written by the server, and the source-upload path
// materializes its own archives behind this check.
func (f TargetFloor) CheckArchive(target string) error {
	clean := filepath.Clean(strings.TrimSpace(target))
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("%w: archive target must be an absolute path", shared.ErrValidation)
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return fmt.Errorf("%w: archive target is not readable", shared.ErrValidation)
	}
	for _, root := range f.archiveRoots {
		resolvedRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		if within(resolvedRoot, resolved) {
			return nil
		}
	}
	return fmt.Errorf("%w: archive target is not one this server stored", shared.ErrValidation)
}

// resolveExistingPrefix resolves the longest prefix of an absolute, clean path that exists, and
// appends the remaining components unchanged.
func resolveExistingPrefix(path string) string {
	rest := ""
	for current := path; ; {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return path
		}
		rest = filepath.Join(filepath.Base(current), rest)
		current = parent
	}
}

// within reports whether path is root or below it.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// privateOrigin reports whether ip is in address space an internal network uses: RFC 1918, the
// RFC 6598 shared space (CGNAT, which also holds Tailscale tailnets), and IPv6 unique local
// addresses. Loopback, link-local and metadata addresses are refused unconditionally elsewhere.
func privateOrigin(ip net.IP) bool {
	if ip.IsPrivate() {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	return ok && cgnat.Contains(addr.Unmap())
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// embeddedIPv4 returns the IPv4 address an IPv6 translation or tunnelling prefix carries, so it can
// be judged as the address it reaches: NAT64 (64:ff9b::/96, 64:ff9b:1::/48), 6to4 (2002::/16) and
// IPv4-compatible (::/96) addresses.
func embeddedIPv4(ip net.IP) (net.IP, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || !addr.Is6() || addr.Is4In6() {
		return nil, false
	}
	b := addr.As16()
	switch {
	case nat64.Contains(addr), nat64Local.Contains(addr), ipv4Compatible.Contains(addr):
		return net.IPv4(b[12], b[13], b[14], b[15]), true
	case sixToFour.Contains(addr):
		return net.IPv4(b[2], b[3], b[4], b[5]), true
	}
	return nil, false
}

var (
	nat64          = netip.MustParsePrefix("64:ff9b::/96")
	nat64Local     = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour      = netip.MustParsePrefix("2002::/16")
	ipv4Compatible = netip.MustParsePrefix("::/96")
)

// refusedOrigin returns why ip may not be an acquisition origin under this floor, or "".
func (f TargetFloor) refusedOrigin(ip net.IP) string {
	if inner, ok := embeddedIPv4(ip); ok && !inner.IsUnspecified() {
		if why := f.refusedOrigin(inner); why != "" {
			return why
		}
	}
	if isInternalAcquisitionIP(ip) {
		return "a loopback/link-local address"
	}
	if !f.allowPrivateOrigins && privateOrigin(ip) {
		return "private address space, which this server does not acquire from; the operator can allow it with SYNAPSE_ALLOW_PRIVATE_ACQUISITION_ORIGINS"
	}
	return ""
}

// GuardPaths puts the floor in front of an acquisition chain. It refuses a local path, a project
// source root, or an archive path that the floor does not admit, before the request reaches the
// chain, and passes every other request through unchanged.
//
// It must be the outermost acquirer. The source-upload acquirer behind it materializes a tenant's
// upload into a server temporary directory and acquires that path as an archive; that request is
// built by the server, never by the tenant, so it must not meet this check.
func GuardPaths(next ports.Acquirer, floor TargetFloor) ports.Acquirer {
	return pathGuard{next: next, floor: floor}
}

type pathGuard struct {
	next  ports.Acquirer
	floor TargetFloor
}

func (g pathGuard) Acquire(ctx context.Context, req ports.AcquireRequest) (*ports.Workspace, error) {
	if err := g.check(req); err != nil {
		return nil, err
	}
	return g.next.Acquire(ctx, req)
}

func (g pathGuard) check(req ports.AcquireRequest) error {
	if req.ProjectSource != nil {
		return g.floor.CheckLocal(req.ProjectSource.Root)
	}
	switch req.Kind {
	case "", ports.TargetLocal:
		return g.floor.CheckLocal(req.Value)
	case ports.TargetArchive:
		return g.floor.CheckArchive(req.Value)
	case ports.TargetImage:
		// An image reference that names an archive on disk is read from the server's disk. The
		// acquirer re-checks at the moment it decides, so a file appearing after this check still
		// meets the floor.
		if isLocalImageArchive(req.Value) {
			return g.floor.CheckLocal(req.Value)
		}
	}
	return nil
}

var _ ports.Acquirer = pathGuard{}
