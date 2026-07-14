//go:build !cgo

package astwalk

import "context"

// FunctionsFor / MetricsFor are the CGO-free stubs: no tree-sitter grammar is compiled in, so the sidecar
// reports the backend as unavailable and callers fall back to their own counting. This is the build the
// distroless-parity CI step (`CGO_ENABLED=0 go build ./cmd/...`) compiles.
func FunctionsFor(ctx context.Context, root string) (Result, error) {
	return Result{}, ErrUnavailable
}

func MetricsFor(ctx context.Context, root string) (Metrics, error) {
	return Metrics{}, ErrUnavailable
}

func BugsFor(ctx context.Context, root string) (Bugs, error) {
	return Bugs{}, ErrUnavailable
}

func QualityFor(ctx context.Context, root string) (Quality, error) {
	return Quality{}, ErrUnavailable
}
