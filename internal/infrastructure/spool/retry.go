package spool

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RetryReason is a stable label for transport metrics and logs. The A3 wire
// client consumes this policy; A2 owns it because retry timing determines how
// quickly the durable spool grows while a control plane is unavailable.
type RetryReason string

const (
	RetryNone          RetryReason = "none"
	RetryRateLimited   RetryReason = "rate_limited"
	RetryServerFailure RetryReason = "server_failure"
	RetryTimeout       RetryReason = "request_timeout"
	RetryNetwork       RetryReason = "network_failure"
	RetryPermanent     RetryReason = "permanent_failure"
)

// RetryDecision tells a future transport whether and when to retry a batch.
type RetryDecision struct {
	Retry  bool
	Delay  time.Duration
	Reason RetryReason
}

// RetryPolicy implements capped exponential backoff with full jitter. Random
// is injectable for deterministic tests; values outside [0,1] are clamped.
type RetryPolicy struct {
	Base   time.Duration
	Max    time.Duration
	Random func() float64
}

// DefaultRetryPolicy is intentionally moderate: retries begin quickly, while
// the cap prevents a long outage from creating synchronized request storms.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{Base: 500 * time.Millisecond, Max: 30 * time.Second, Random: rand.Float64}
}

func (p RetryPolicy) validate() error {
	if p.Base <= 0 || p.Max <= 0 || p.Base > p.Max {
		return fmt.Errorf("%w: retry base/max must be positive and base <= max", shared.ErrValidation)
	}
	if p.Random == nil {
		return fmt.Errorf("%w: retry random source is required", shared.ErrValidation)
	}
	return nil
}

// Delay returns full-jitter exponential backoff for a zero-based attempt.
func (p RetryPolicy) Delay(attempt uint) (time.Duration, error) {
	if err := p.validate(); err != nil {
		return 0, err
	}
	exponent := attempt
	if exponent > 62 {
		exponent = 62
	}
	capDelay := float64(p.Base) * math.Pow(2, float64(exponent))
	if capDelay > float64(p.Max) || math.IsInf(capDelay, 1) {
		capDelay = float64(p.Max)
	}
	random := p.Random()
	if math.IsNaN(random) {
		return 0, fmt.Errorf("%w: retry random source returned NaN", shared.ErrValidation)
	}
	if random < 0 {
		random = 0
	}
	if random > 1 {
		random = 1
	}
	return time.Duration(random * capDelay), nil
}

// ClassifyHTTP applies the A2 retry contract. 429 and Retry-After take
// precedence; 408 and 5xx retry with jitter; other 4xx are permanent. A valid
// Retry-After delta/date is capped to Max to keep configuration authoritative.
func (p RetryPolicy) ClassifyHTTP(status int, retryAfter string, now time.Time, attempt uint) (RetryDecision, error) {
	if err := p.validate(); err != nil {
		return RetryDecision{}, err
	}
	if status >= 200 && status < 300 {
		return RetryDecision{Reason: RetryNone}, nil
	}
	reason := RetryPermanent
	retry := false
	switch {
	case status == http.StatusTooManyRequests:
		reason, retry = RetryRateLimited, true
	case status == http.StatusRequestTimeout:
		reason, retry = RetryTimeout, true
	case status >= 500 && status <= 599:
		reason, retry = RetryServerFailure, true
	}
	if !retry {
		return RetryDecision{Reason: reason}, nil
	}
	if delay, ok := parseRetryAfter(retryAfter, now); ok {
		if delay > p.Max {
			delay = p.Max
		}
		return RetryDecision{Retry: true, Delay: delay, Reason: reason}, nil
	}
	delay, err := p.Delay(attempt)
	return RetryDecision{Retry: true, Delay: delay, Reason: reason}, err
}

// NetworkFailure applies backoff to a transport error which has no HTTP response.
func (p RetryPolicy) NetworkFailure(attempt uint) (RetryDecision, error) {
	delay, err := p.Delay(attempt)
	return RetryDecision{Retry: true, Delay: delay, Reason: RetryNetwork}, err
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseUint(value, 10, 31); err == nil {
		return time.Duration(seconds) * time.Second, true
	}
	date, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := date.Sub(now)
	if delay < 0 {
		delay = 0
	}
	return delay, true
}
