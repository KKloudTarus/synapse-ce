package engagement

import (
	"strings"
)

// UnscannablePath is one local path a repo target may never name, with the reason an operator sees.
type UnscannablePath struct {
	Prefix string
	Why    string
}

// unscannablePaths are the locations on the machine running the server that a repository scope can
// never legitimately mean.
//
// The scope gate is the server's authorization boundary, and a tenant writes the scope. A repo scope
// of "/" was accepted and then matched every local path through localPathContains, so a caller with
// the operate capability could put the engagement's scope at the filesystem root and have the server
// scan /etc, /root or /proc. The gate recorded that as authorized, because by its own rules it was.
//
// Refusing these is the same move unreachableRanges makes for network targets: a blocklist is weak
// as a general defence, but a blocklist of things that are definitionally not the thing being named
// is honest. None of these is a repository. The filesystem root is not one either, and it is the
// entry that turns the gate into a no-op.
//
// This is a floor, not the whole answer. A deployment that serves tenants it does not trust needs an
// operator-controlled allowlist of roots rather than a denylist of system directories, because
// nothing here stops a scope of "/srv" on a server that keeps its own data there. That decision has
// a configuration variable and a rollout behind it and is tracked separately.
var unscannablePaths = []UnscannablePath{
	{"/", "the filesystem root is not a repository, and naming it would put every path on the server in scope"},
	{"/etc", "system configuration"},
	{"/proc", "the kernel's process interface"},
	{"/sys", "the kernel's device interface"},
	{"/dev", "device nodes"},
	{"/boot", "the boot partition"},
	{"/root", "the superuser's home"},
	{"/run", "runtime state, which holds sockets and credentials"},
	{"/var/run", "runtime state, which holds sockets and credentials"},
}

// UnscannablePaths returns the local paths a repo target may never name.
func UnscannablePaths() []UnscannablePath {
	out := make([]UnscannablePath, len(unscannablePaths))
	copy(out, unscannablePaths)
	return out
}

// unscannablePath reports the entry that refuses this local path, if any. A path is refused when it
// IS one of them or sits underneath one: /etc/nginx is system configuration just as /etc is.
//
// A value that is not a local absolute path is not this function's business and comes back allowed;
// a repo target is just as often a URL or an owner/name pair.
func unscannablePath(value string) (UnscannablePath, bool) {
	cleaned, ok := cleanLocalScopePath(value)
	if !ok {
		return UnscannablePath{}, false
	}
	// A Windows path carries a drive letter, so the Unix system directories below say nothing about
	// it. The root case is still worth refusing there, and cleanLocalScopePath leaves "c:/" intact.
	if len(cleaned) >= 2 && cleaned[1] == ':' {
		if strings.TrimSuffix(cleaned, "/") == strings.TrimSuffix(cleaned[:2], "/") || cleaned == cleaned[:2]+"/" {
			return UnscannablePath{Prefix: cleaned, Why: unscannablePaths[0].Why}, true
		}
		return UnscannablePath{}, false
	}
	for _, p := range unscannablePaths {
		if p.Prefix == "/" {
			if cleaned == "/" {
				return p, true
			}
			continue
		}
		if cleaned == p.Prefix || strings.HasPrefix(cleaned, p.Prefix+"/") {
			return p, true
		}
	}
	return UnscannablePath{}, false
}

// localRepoPath reports whether a repo target value is a local absolute path rather than a remote
// identifier. It exists so the refusal above only ever applies to the values it is about.
func localRepoPath(value string) bool {
	_, ok := cleanLocalScopePath(value)
	if !ok {
		return false
	}
	return !strings.Contains(value, "://")
}
