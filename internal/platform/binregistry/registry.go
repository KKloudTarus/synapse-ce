// Package binregistry verifies tool-binary integrity before execution (F5). The audit
// found tools were trusted purely by PATH: a replaced /usr/local/bin/naabu would be run
// (with whatever the spec grants). The registry pins each tool's sha256 – from operator-
// supplied expected hashes (authoritative, supply-chain) and/or trust-on-first-use – and
// the SandboxRunner refuses to execute a binary whose hash does not match its pin.
package binregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ErrIntegrity means a binary's on-disk hash does not match its pin – execution is refused.
var ErrIntegrity = errors.New("binary integrity check failed")

// Registry pins resolved binary paths to expected sha256 hashes.
type Registry struct {
	mu       sync.Mutex
	expected map[string]string // authoritative pins (resolved path -> hex sha256) from config
	seen     map[string]string // trust-on-first-use pins recorded at first execution
	tofu     bool              // when true, pin-on-first-use and detect any later change
}

// New builds a registry. expected maps a binary path (or bare name) to its hex sha256 – an
// authoritative pin that must match. tofu enables trust-on-first-use for binaries with no
// expected pin: the first hash seen is recorded and every later run must match it (detects
// runtime replacement). With tofu=false and no expected pin, a binary is allowed unverified.
func New(expected map[string]string, tofu bool) *Registry {
	cp := make(map[string]string, len(expected))
	for k, v := range expected {
		cp[k] = strings.ToLower(strings.TrimSpace(v))
	}
	return &Registry{expected: cp, seen: map[string]string{}, tofu: tofu}
}

// Verify hashes the binary at path (symlinks resolved), checks it against its pin, and returns
// the resolved path. The returned path is always absolute, so callers can bind and execute it
// verbatim rather than resolving the input again. Returns ErrIntegrity on a mismatch; records a
// TOFU pin on first sight when enabled.
func (r *Registry) Verify(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("%w: cannot resolve %q: %v", ErrIntegrity, path, err)
	}
	// EvalSymlinks preserves relative-ness: a bare name that host PATH resolution left unresolved
	// would resolve against the process CWD and come back relative, and the sandbox binds/execs only
	// absolute paths - so bwrap would re-resolve the bare name against its own PATH and run a file
	// this never hashed. Refuse a non-absolute result so the verify==exec invariant is total.
	if !filepath.IsAbs(resolved) {
		return "", fmt.Errorf("%w: resolved path %q is not absolute", ErrIntegrity, resolved)
	}
	sum, err := hashFile(resolved)
	if err != nil {
		return "", fmt.Errorf("%w: cannot hash %q: %v", ErrIntegrity, resolved, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Authoritative pin keyed by resolved path or by basename (so config can pin "naabu").
	if want, ok := r.expected[resolved]; ok {
		if err := matchOrErr(resolved, want, sum); err != nil {
			return "", err
		}
		return resolved, nil
	}
	if want, ok := r.expected[filepath.Base(resolved)]; ok {
		if err := matchOrErr(resolved, want, sum); err != nil {
			return "", err
		}
		return resolved, nil
	}
	if r.tofu {
		if first, ok := r.seen[resolved]; ok {
			if err := matchOrErr(resolved, first, sum); err != nil {
				return "", err
			}
			return resolved, nil
		}
		r.seen[resolved] = sum // pin on first use
	}
	return resolved, nil
}

func matchOrErr(path, want, got string) error {
	if want != got {
		return fmt.Errorf("%w: %q hash %s != pinned %s", ErrIntegrity, path, got, want)
	}
	return nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
