# Versioned Go-binary reachability proposal

This is review material for a successor reachability benchmark contract. It is not an oracle, baseline, checkpoint, ratchet, accepted candidate, or trusted controller input. The checked-in trusted contract remains at 83 cases and 95 execution cells, and its historical assets are unchanged.

## Why a new contract is needed

`synapse-worker` now wires the Go-binary entry-call coordinator with raise-only behavior. The frozen production inventory still marks its `go`/`binary` worker binding `not_wired`. The frozen `go-binary-input` fixture instead names an unversioned `example.invalid/reachbench/go-binary` module and symbols; all five historical Go-binary measurements returned `no_analysis`. Merely enabling the worker binding expands the matrix to 100 cells and invalidates the frozen inventory and snapshot bindings. The historical measurements cannot be interpreted as the new analyzer's recall.

## Reproducible diagnostic input

`internal/infrastructure/reachbench/testdata/go_binary_versioned/` contains source for three Linux/amd64 binaries. `go.mod` and `go.sum` pin `golang.org/x/net@v0.59.0` and its indirect `golang.org/x/text@v0.42.0` dependency. `direct.go.txt` calls `golang.org/x/net/idna.ToASCII` from `main`; `retained.go.txt` keeps a function that calls the same symbol in the binary but never invokes it from `main`; `retained_called.go.txt` invokes that retained function. Build with Go 1.27.0, `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64`, `GOTOOLCHAIN=local`, and `go build -trimpath`. The package test checks build identity and retained symbol presence, then executes the production Go-binary capture adapter.

The proposal manifest has SHA-256 `45d843717dd17ad919396479ed95e6670eff356b8fb183e82ad9144402864ccf`. Its `files_sha256` map pins the five input files. This digest identifies the proposal bytes only; it is not a trusted full-contract fingerprint. Source SHA and toolchain identity must accompany any review run. The package test runs on the repository's Go toolchain; a Linux Docker run can use `golang:1.27.0` with the repository mounted at `/work`.

| Diagnostic case | Query | Production observation |
| --- | --- | --- |
| Direct call | Exact `pkg:golang/golang.org/x/net@v0.59.0` and `idna.ToASCII` | Reachable, non-suppressing judgment |
| Retained but uncalled | Same exact query against retained binary | No judgment |
| Retained and called | Same exact query against companion binary | Reachable, non-suppressing judgment |
| Unversioned identity | `pkg:golang/golang.org/x/net` against direct binary | No judgment |
| Wrong version | `pkg:golang/golang.org/x/net@v0.58.0` against direct binary | No judgment |

No judgment is a lack of positive proof. It is not a `not_reachable` claim or a downstream suppression observation. The retained but uncalled binary has the exact dependency build identity and a retained `main.controlUnreached` symbol; the companion demonstrates that the production analyzer can prove its path when invoked. The retained but uncalled case may remain without entrypoint coverage because the raise-only call walker conservatively declines a path with no positive proof. The test also asks the unchanged trusted-template validator to accept a worker-enabled inventory and confirms it rejects the altered inventory.

## Proposed successor scope

The inventory correction would mark the `go`/`binary` worker binding enabled. A new corpus and oracle must use exact module/version identities and independently reviewed source evidence for the positive call, retained but uncalled symbol, opaque call, and unavailable analysis controls. The five diagnostics above are candidate evidence for that review; they do not yet replace the five historical case IDs or determine their new labels. In particular, an unversioned or wrong-version query demonstrates identity rejection, not a sound unreachable result for an opaque call.

After independent oracle review, derive a complete successor contract fingerprint from inventory, fixtures, corpus, oracle, policy, exceptions, and active snapshot together. Rebind a separately reviewed baseline and maintainer disposition, then run the trusted worker cells at the exact candidate source and input identities. The old 95-cell assets must remain byte-identical and verifiable under their original contract. Unknown or mixed contracts, and an old checkpoint attached to the new inventory, must fail closed before any successor candidate can be accepted.
