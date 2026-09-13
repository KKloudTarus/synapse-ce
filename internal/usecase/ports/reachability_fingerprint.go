package ports

import "context"

// ReachabilitySourceFingerprinter produces the per-target verdict-affecting inputs of a reachability cache
// key (EPIC #1042, 0.7): a content hash of the analyzed source tree, and a fingerprint of the remaining
// per-target environment (dependency/lock graph, resolver config, generated-source inputs, build/sandbox
// mode). It is the boundary that lets the reachproof coordinator (a usecase) stay filesystem-free while the
// hash is computed in infrastructure.
//
// SOUNDNESS: both returned values MUST change whenever a reachability verdict for that target could change,
// so a changed input never reuses a cached graph. When it cannot compute a trustworthy hash the
// implementation returns an error or an empty sourceHash, and the coordinator DISABLES the cache for that
// run (recompute) rather than risk serving a stale-key negative. It therefore never fabricates a hash.
type ReachabilitySourceFingerprinter interface {
	FingerprintSource(ctx context.Context, targetRef string) (sourceHash, envFingerprint string, err error)
}
