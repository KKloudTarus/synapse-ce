package siem

import "time"

// RetryAt is the next attempt time for a retryable failure. attempt is the
// number of failures so far, starting at 1. Jitter is rng in [0, 1). A
// positive Retry-After replaces a shorter computed delay. The result is
// bounded by MaxRetry.
func RetryAt(now time.Time, attempt int, retryAfter time.Duration, rng func() float64) time.Time {
	if attempt < 1 {
		attempt = 1
	}
	delay := BaseRetry
	for i := 1; i < attempt && delay < MaxRetry; i++ {
		delay *= 2
	}
	if delay > MaxRetry {
		delay = MaxRetry
	}
	unit := 0.0
	if rng != nil {
		unit = rng()
	}
	if unit < 0 {
		unit = 0
	}
	if unit > 1 {
		unit = 1
	}
	// Full jitter keeps a thundering herd off the same second.
	jittered := time.Duration(float64(delay) * unit)
	if jittered < time.Millisecond {
		jittered = time.Millisecond
	}
	if retryAfter > jittered {
		jittered = retryAfter
	}
	if jittered > MaxRetry {
		jittered = MaxRetry
	}
	return now.Add(jittered)
}
