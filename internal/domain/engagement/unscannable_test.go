package engagement

import (
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestAScopeOfTheFilesystemRootIsRefused is the one that matters. The scope gate is this server's
// authorization boundary and a tenant writes the scope, so a repo entry of "/" made the gate agree
// to every path on the host: localPathContains("/", "/etc") is true, and the audit log recorded the
// scan as authorized because by the gate's own rules it was.
func TestAScopeOfTheFilesystemRootIsRefused(t *testing.T) {
	t.Parallel()
	_, err := NormalizeTarget(Target{Kind: TargetRepo, Value: "/"}, true)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a repo scope of the filesystem root = %v, want a refusal", err)
	}
	if err != nil && !strings.Contains(err.Error(), "every path on the server") {
		t.Fatalf("refusal does not say why: %v", err)
	}
}

func TestSystemDirectoriesCannotBeARepository(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"/etc", "/etc/nginx", "/etc/../etc", "/proc", "/proc/self/environ", "/sys/class",
		"/dev", "/boot", "/root", "/root/.ssh", "/run/secrets", "/var/run/docker.sock",
		"//etc", "/etc/",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := NormalizeTarget(Target{Kind: TargetRepo, Value: value}, true); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%q was accepted as a repository target: %v", value, err)
			}
		})
	}
}

// A refusal that also refuses the legitimate case is worse than none: the product's whole purpose is
// scanning a checkout on disk.
func TestAnOrdinaryCheckoutIsStillAcceptable(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"/srv/repos/app", "/home/dev/project", "/workspace/src", "/opt/code/service",
		"https://github.com/owner/repo", "git@github.com:owner/repo.git", "owner/repo",
		"/var/lib/jenkins/workspace/build", "c:/src/app",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeTarget(Target{Kind: TargetRepo, Value: value}, true)
			if err != nil {
				t.Fatalf("%q was refused: %v", value, err)
			}
			if got.Value != value {
				t.Fatalf("%q was rewritten to %q", value, got.Value)
			}
		})
	}
}

// The refusal has to hold for a scan request too, not only for the scope entry that authorizes it.
// Otherwise an engagement scoped to a legitimate root could still be asked to scan a system path,
// and the containment would rest on localPathContains alone.
func TestASystemPathIsRefusedAsAScanTargetAsWellAsAScopeEntry(t *testing.T) {
	t.Parallel()
	if _, err := NormalizeTarget(Target{Kind: TargetRepo, Value: "/etc"}, false); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a scan request for /etc = %v, want a refusal", err)
	}
}

// With the root gone, a scope still has to be able to contain the thing it names, and still has to
// refuse what it does not.
func TestScopeContainmentStillWorksForARealRoot(t *testing.T) {
	t.Parallel()
	root, err := NormalizeTarget(Target{Kind: TargetRepo, Value: "/srv/repos"}, true)
	if err != nil {
		t.Fatalf("scope entry: %v", err)
	}
	s := Scope{InScope: []Target{root}}
	if !s.AllowsTarget(Target{Kind: TargetRepo, Value: "/srv/repos/app"}) {
		t.Fatal("a path inside the scope was refused")
	}
	if s.AllowsTarget(Target{Kind: TargetRepo, Value: "/srv/other"}) {
		t.Fatal("a path outside the scope was allowed")
	}
	if s.AllowsTarget(Target{Kind: TargetRepo, Value: "/etc"}) {
		t.Fatal("a system path was allowed by a scope that does not contain it")
	}
}

func TestUnscannablePathsIsACopy(t *testing.T) {
	t.Parallel()
	first := UnscannablePaths()
	if len(first) == 0 {
		t.Fatal("no unscannable paths are declared")
	}
	first[0].Why = "mutated"
	if UnscannablePaths()[0].Why == "mutated" {
		t.Fatal("UnscannablePaths hands out the package's own table")
	}
}
