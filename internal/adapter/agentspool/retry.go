package agentspool

import (
	"context"
	"math/rand/v2"
	"time"
)

const (
	minSaturationRetryDelay = 200 * time.Millisecond
	maxSaturationRetryDelay = 300 * time.Millisecond
)

func saturationRetryDelay() time.Duration {
	window := maxSaturationRetryDelay - minSaturationRetryDelay
	//nolint:gosec // Retry jitter is intentionally non-cryptographic.
	return minSaturationRetryDelay + time.Duration(rand.Int64N(int64(window)+1))
}

func waitForSpoolCapacity(ctx context.Context) error {
	timer := time.NewTimer(saturationRetryDelay())
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
