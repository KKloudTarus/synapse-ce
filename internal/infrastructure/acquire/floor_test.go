package acquire

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestNewTargetFloorValidatesLocalRoots(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		roots   []string
		wantErr string
	}{
		{name: "empty list refuses every local target", roots: nil},
		{name: "blank entries are ignored", roots: []string{" ", ""}},
		{name: "an existing directory", roots: []string{dir}},
		{name: "a relative root", roots: []string{"srv/code"}, wantErr: "not an absolute path"},
		// A root may be mounted only on the workers; the API still starts and judges it as written.
		{name: "a root that does not exist on this host", roots: []string{filepath.Join(dir, "missing")}},
		{name: "a file, not a directory", roots: []string{file}, wantErr: "not a directory"},
		{name: "the filesystem root", roots: []string{fsRoot(dir)}, wantErr: "filesystem root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTargetFloor(tc.roots, nil, nil, false)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want a validation error naming %q", err, tc.wantErr)
			}
		})
	}
}

func TestTargetFloorCheckLocal(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "repo")
	outside := t.TempDir()
	if err := os.MkdirAll(inside, 0o750); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the root that points outside it must be judged by where it points.
	escape := filepath.Join(root, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// A sibling whose name extends the root's must not count as inside it.
	sibling := root + "-sibling"
	if err := os.MkdirAll(sibling, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sibling) })

	floor, err := NewTargetFloor([]string{root}, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		floor  TargetFloor
		target string
		want   string
	}{
		{name: "the root itself", floor: floor, target: root},
		{name: "a directory below the root", floor: floor, target: inside},
		{name: "an uncleaned path below the root", floor: floor, target: inside + "/../repo/"},
		{name: "a directory outside every root", floor: floor, target: outside, want: "outside the roots"},
		{name: "a symlink escaping the root", floor: floor, target: escape, want: "outside the roots"},
		{name: "a dot-dot escape", floor: floor, target: inside + "/../../", want: "outside the roots"},
		{name: "a sibling sharing the root's prefix", floor: floor, target: sibling, want: "outside the roots"},
		{name: "a system directory", floor: floor, target: filepath.Join(fsRoot(root), "etc"), want: "outside the roots"},
		{name: "a relative path", floor: floor, target: "repo", want: "absolute path"},
		{name: "a path below the root that does not exist", floor: floor, target: filepath.Join(root, "missing"), want: "not readable"},
		{name: "no roots configured", floor: TargetFloor{}, target: inside, want: "disabled on this server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.floor.CheckLocal(tc.target)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused %q: %v", tc.target, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("CheckLocal(%q) = %v, want a validation error naming %q", tc.target, err, tc.want)
			}
		})
	}
}

func TestTargetFloorCheckArchive(t *testing.T) {
	store := t.TempDir()
	stored := filepath.Join(store, "p1", "src.zip")
	if err := os.MkdirAll(filepath.Dir(stored), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stored, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "other.zip")
	if err := os.WriteFile(elsewhere, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	floor, err := NewTargetFloor(nil, []string{store}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := floor.CheckArchive(stored); err != nil {
		t.Fatalf("an archive in the server's store was refused: %v", err)
	}
	for _, target := range []string{elsewhere, "/etc/passwd", "rel.zip"} {
		if err := floor.CheckArchive(target); err == nil {
			t.Fatalf("CheckArchive(%q) admitted a path the server did not store", target)
		}
	}
	// A store that does not exist yet admits nothing, and does not fail construction.
	late, err := NewTargetFloor(nil, []string{filepath.Join(store, "later")}, nil, false)
	if err != nil {
		t.Fatalf("a not-yet-created archive store failed construction: %v", err)
	}
	if late.CheckArchive(stored) == nil {
		t.Fatal("a missing store admitted an archive")
	}
}

type recordingAcquirer struct{ got []ports.AcquireRequest }

func (r *recordingAcquirer) Acquire(_ context.Context, req ports.AcquireRequest) (*ports.Workspace, error) {
	r.got = append(r.got, req)
	return &ports.Workspace{}, nil
}

func TestGuardPathsChecksTenantPathsAndPassesTheRestThrough(t *testing.T) {
	root := t.TempDir()
	floor, err := NewTargetFloor([]string{root}, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		req     ports.AcquireRequest
		refused bool
	}{
		{name: "local inside the root", req: ports.AcquireRequest{Kind: ports.TargetLocal, Value: root}},
		{name: "empty kind is local", req: ports.AcquireRequest{Value: "/etc"}, refused: true},
		{name: "local outside the root", req: ports.AcquireRequest{Kind: ports.TargetLocal, Value: "/etc"}, refused: true},
		{name: "archive the server did not store", req: ports.AcquireRequest{Kind: ports.TargetArchive, Value: "/etc/x.zip"}, refused: true},
		{name: "project source root outside", req: ports.AcquireRequest{Kind: ports.TargetLocal, Value: "/etc/x", ProjectSource: &ports.ProjectSourceSelection{ProjectID: "p", Root: "/etc", Subdirectory: "x"}}, refused: true},
		// An upload names no path; the source-upload acquirer behind the guard builds one itself.
		{name: "upload passes through", req: ports.AcquireRequest{Kind: ports.TargetUpload, Value: "sha256:abc"}},
		{name: "git passes through", req: ports.AcquireRequest{Kind: ports.TargetGit, Value: "https://example.com/r.git"}},
		{name: "image passes through", req: ports.AcquireRequest{Kind: ports.TargetImage, Value: "alpine:3"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := &recordingAcquirer{}
			_, err := GuardPaths(next, floor).Acquire(context.Background(), tc.req)
			if tc.refused {
				if err == nil || !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("err = %v, want a validation refusal", err)
				}
				if len(next.got) != 0 {
					t.Fatal("a refused request reached the chain behind the guard")
				}
				return
			}
			if err != nil || len(next.got) != 1 {
				t.Fatalf("err = %v, forwarded = %d; want the request passed through", err, len(next.got))
			}
		})
	}
}

func TestTargetFloorRefusedOrigin(t *testing.T) {
	strict := TargetFloor{}
	open := TargetFloor{allowPrivateOrigins: true}
	cases := []struct {
		ip           string
		strictRefuse bool
		openRefuse   bool
	}{
		{ip: "8.8.8.8"},
		{ip: "2606:4700::1111"},
		{ip: "10.20.0.11", strictRefuse: true},
		{ip: "172.16.5.4", strictRefuse: true},
		{ip: "192.168.1.10", strictRefuse: true},
		{ip: "100.64.0.1", strictRefuse: true},      // CGNAT, Tailscale
		{ip: "100.127.255.254", strictRefuse: true}, // CGNAT upper edge
		{ip: "100.128.0.1"},                         // just past CGNAT
		{ip: "fd12:3456::1", strictRefuse: true},    // IPv6 ULA
		{ip: "::ffff:10.0.0.1", strictRefuse: true}, // 4-in-6 private
		{ip: "127.0.0.1", strictRefuse: true, openRefuse: true},
		{ip: "169.254.169.254", strictRefuse: true, openRefuse: true},
		{ip: "100.100.100.200", strictRefuse: true, openRefuse: true}, // Alibaba metadata, inside CGNAT
		{ip: "fd00:ec2::254", strictRefuse: true, openRefuse: true},   // AWS IPv6 metadata, inside ULA
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if got := strict.refusedOrigin(ip) != ""; got != tc.strictRefuse {
			t.Errorf("strict floor refuses %s = %v, want %v", tc.ip, got, tc.strictRefuse)
		}
		if got := open.refusedOrigin(ip) != ""; got != tc.openRefuse {
			t.Errorf("permissive floor refuses %s = %v, want %v", tc.ip, got, tc.openRefuse)
		}
	}
}

func TestAcquirerOriginFloorRefusesPrivateGitAndRegistryHosts(t *testing.T) {
	withFloor := New().WithTargetFloor(TargetFloor{})
	if err := withFloor.rejectInternalHost("10.0.0.5"); err == nil || !strings.Contains(err.Error(), "private address space") {
		t.Fatalf("a private git host passed the strict floor: %v", err)
	}
	if err := New().WithTargetFloor(TargetFloor{allowPrivateOrigins: true}).rejectInternalHost("10.0.0.5"); err != nil {
		t.Fatalf("a private git host was refused with private origins allowed: %v", err)
	}
	// Without a floor (the CLI), private space stays reachable and loopback stays refused.
	if err := New().rejectInternalHost("10.0.0.5"); err != nil {
		t.Fatalf("the floorless acquirer refused private space: %v", err)
	}
	if err := New().rejectInternalHost("127.0.0.1"); err == nil {
		t.Fatal("the floorless acquirer admitted loopback")
	}
	// The dial-time check a registry transport uses agrees with the host check.
	if withFloor.refuseIP(net.ParseIP("192.168.0.9")) == "" {
		t.Fatal("the registry dial check admitted private space under the strict floor")
	}
	if New().refuseIP(net.ParseIP("192.168.0.9")) != "" {
		t.Fatal("the floorless registry dial check refused private space")
	}
}

func TestTargetFloorCheckLocalScope(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	floor, err := NewTargetFloor([]string{root}, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		target  string
		refused bool
	}{
		{name: "a checkout that does not exist yet, under the root", target: filepath.Join(root, "not-cloned", "yet")},
		{name: "a missing path under a symlink that leaves the root", target: filepath.Join(link, "new"), refused: true},
		{name: "a missing path outside every root", target: filepath.Join(fsRoot(root), "srv", "elsewhere", "repo"), refused: true},
		{name: "a relative path", target: "repo", refused: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := floor.CheckLocalScope(tc.target)
			if (err != nil) != tc.refused {
				t.Fatalf("CheckLocalScope(%q) = %v, refused want %v", tc.target, err, tc.refused)
			}
		})
	}
	if err := (TargetFloor{}).CheckLocalScope(root); err == nil {
		t.Fatal("a floor with no roots admitted a local scope entry")
	}
}

// TestImageArchiveOnDiskMeetsTheFloor pins the bypass the #1701 review found: an image target naming
// a docker-save tarball is read from the server's disk, so it is a local target.
func TestImageArchiveOnDiskMeetsTheFloor(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideTar := filepath.Join(outside, "bundle.tar")
	if err := os.WriteFile(outsideTar, []byte("not really a tar"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A relative reference that walks out of the working directory, as the review demonstrated.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(wd, outsideTar)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := NewTargetFloor([]string{root}, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	acq := New().WithTargetFloor(floor)
	for _, ref := range []string{outsideTar, relative} {
		if _, err := acq.Acquire(context.Background(), ports.AcquireRequest{Kind: ports.TargetImage, Value: ref}); err == nil || !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("acquirer read image archive %q outside the floor: %v", ref, err)
		}
		next := &recordingAcquirer{}
		if _, err := GuardPaths(next, floor).Acquire(context.Background(), ports.AcquireRequest{Kind: ports.TargetImage, Value: ref}); err == nil || len(next.got) != 0 {
			t.Fatalf("guard passed image archive %q outside the floor: %v", ref, err)
		}
	}
	// A registry reference is not a file and is not judged by the path floor.
	next := &recordingAcquirer{}
	if _, err := GuardPaths(next, floor).Acquire(context.Background(), ports.AcquireRequest{Kind: ports.TargetImage, Value: "docker.io/library/alpine:3.19"}); err != nil || len(next.got) != 1 {
		t.Fatalf("a registry reference was refused by the path floor: %v", err)
	}
}

func TestTargetFloorRefusesEmbeddedPrivateIPv4AndUnresolvableHosts(t *testing.T) {
	strict := TargetFloor{}
	for _, ip := range []string{"64:ff9b::a00:5", "64:ff9b:1::c0a8:101", "2002:a00:5::1", "::10.0.0.5", "64:ff9b::7f00:1"} {
		if strict.refusedOrigin(net.ParseIP(ip)) == "" {
			t.Errorf("%s carries a private or loopback IPv4 and was admitted", ip)
		}
	}
	if why := strict.refusedOrigin(net.ParseIP("64:ff9b::808:808")); why != "" {
		t.Errorf("NAT64 to a public address was refused: %s", why)
	}
	if err := New().WithTargetFloor(TargetFloor{}).rejectInternalHost("does-not-resolve.invalid"); err == nil {
		t.Fatal("an unresolvable host passed the strict floor")
	}
}

func TestTargetFloorIsNotAnExistenceOracle(t *testing.T) {
	root := t.TempDir()
	floor, err := NewTargetFloor([]string{root}, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	existing := t.TempDir()
	missing := filepath.Join(existing, "nothing-here")
	a, b := floor.CheckLocal(existing), floor.CheckLocal(missing)
	if a == nil || b == nil || a.Error() != b.Error() {
		t.Fatalf("an existing and a missing path outside the roots are told apart: %v / %v", a, b)
	}
}

func TestNewTargetFloorRefusesRootsOverlappingServerData(t *testing.T) {
	data := t.TempDir()
	uploads := filepath.Join(data, "uploads")
	if err := os.MkdirAll(uploads, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTargetFloor([]string{data}, []string{uploads}, nil, false); err == nil || !strings.Contains(err.Error(), "overlaps the server data directory") {
		t.Fatalf("a root containing the upload store was accepted: %v", err)
	}
	if _, err := NewTargetFloor([]string{uploads}, nil, []string{data}, false); err == nil {
		t.Fatal("a root inside a server data directory was accepted")
	}
	if _, err := NewTargetFloor([]string{t.TempDir()}, []string{uploads}, []string{data}, false); err != nil {
		t.Fatalf("a disjoint root was refused: %v", err)
	}
}

// fsRoot returns the filesystem root of the volume holding path: "/" on Unix, `C:\` on Windows.
func fsRoot(path string) string {
	return filepath.VolumeName(path) + string(filepath.Separator)
}

func TestTargetFloorJudgesARootMissingOnThisHostAsWritten(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "mounted-on-workers")
	floor, err := NewTargetFloor([]string{missing}, nil, nil, false)
	if err != nil {
		t.Fatalf("a root absent on this host failed construction: %v", err)
	}
	if err := floor.CheckLocalScope(filepath.Join(missing, "app")); err != nil {
		t.Fatalf("a scope entry under a root absent on this host was refused: %v", err)
	}
	if err := floor.CheckLocalScope(filepath.Join(filepath.Dir(missing), "elsewhere")); err == nil {
		t.Fatal("a scope entry outside the roots was admitted")
	}
	// Execution reads the disk, so on a host without the root nothing under it is acquirable.
	if err := floor.CheckLocal(filepath.Join(missing, "app")); err == nil {
		t.Fatal("a target under a root absent on this host was admitted for acquisition")
	}
}
