package reachproof

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

// CacheKey binds EVERYTHING that can change a reachability verdict, so a cached whole-graph result is reused
// only when every verdict-affecting input is unchanged (EPIC #1042 0.7). The soundness bar is that a
// STALE-KEY NEGATIVE can never be served: a not_reachable served after an input changed would hide a
// now-reachable vulnerability. Two protections enforce it: (1) Complete() requires every field to be bound,
// and an incomplete key is never used (the caller recomputes); (2) Fingerprint() hashes the whole tuple, so
// any changed input yields a different key and misses the cache.
//
// SourceHash is a content hash (Merkle) of the analyzed source tree; Symbols are the affected symbols
// queried (an advisory revision that changes them changes the key); Tier is the analysis tier; Analyzer
// version and CoverageModel version bind the analyzer + coverage semantics; EnvFingerprint is a
// caller-supplied hash of the remaining verdict-affecting environment (dependency/lock graph, symbol-catalog
// version, language/toolchain version, build tags + GOOS/GOARCH, entrypoint policy, resolver config,
// generated-source inputs, sandbox/build mode). The caller MUST fold all of those into EnvFingerprint; if it
// cannot, it leaves EnvFingerprint empty and the key is incomplete, so nothing is cached (recompute).
type CacheKey struct {
	SourceHash      string
	Symbols         []string
	Tier            judgment.ReachabilityTier
	AnalyzerVersion string
	CoverageModel   string
	EnvFingerprint  string
}

// Complete reports whether every verdict-affecting input is bound. An incomplete key must NEVER be used to
// read or write the cache, because a missing input could let a stale negative be served.
func (k CacheKey) Complete() bool {
	return strings.TrimSpace(k.SourceHash) != "" &&
		k.Tier.Valid() &&
		strings.TrimSpace(k.AnalyzerVersion) != "" &&
		strings.TrimSpace(k.CoverageModel) != "" &&
		strings.TrimSpace(k.EnvFingerprint) != ""
}

// Fingerprint is the stable content-addressed key over the whole tuple. Symbols are sorted + de-duplicated
// so subject ordering never changes the key, and every field is length-prefixed so no two distinct tuples
// can collide by concatenation. Callers must gate on Complete() first; Fingerprint of an incomplete key is
// still deterministic but must not be used.
func (k CacheKey) Fingerprint() string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			var lenbuf [8]byte
			n := len(p)
			for i := 7; i >= 0; i-- {
				lenbuf[i] = byte(n)
				n >>= 8
			}
			h.Write(lenbuf[:])
			h.Write([]byte(p))
		}
	}
	syms := append([]string(nil), k.Symbols...)
	sort.Strings(syms)
	uniq := syms[:0]
	var last string
	for i, s := range syms {
		if i == 0 || s != last {
			uniq = append(uniq, s)
			last = s
		}
	}
	write("reachcache-v1", k.SourceHash, string(k.Tier), k.AnalyzerVersion, k.CoverageModel, k.EnvFingerprint)
	write(uniq...)
	return hex.EncodeToString(h.Sum(nil))
}
