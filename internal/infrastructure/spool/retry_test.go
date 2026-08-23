package spool

import (
	"math"
	"net/http"
	"testing"
	"time"
)

func TestRetryDelayUsesCappedFullJitter(t *testing.T) {
	policy := RetryPolicy{Base: time.Second, Max: 10 * time.Second, Random: func() float64 { return 0.5 }}
	tests := []struct {
		attempt uint
		want    time.Duration
	}{
		{0, 500 * time.Millisecond},
		{1, time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 5 * time.Second},
		{63, 5 * time.Second},
	}
	for _, tt := range tests {
		got, err := policy.Delay(tt.attempt)
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("attempt %d delay = %s, want %s", tt.attempt, got, tt.want)
		}
	}
}

func TestRetryDelayClampsRandomSource(t *testing.T) {
	low := RetryPolicy{Base: time.Second, Max: time.Second, Random: func() float64 { return -7 }}
	if got, _ := low.Delay(0); got != 0 {
		t.Errorf("negative random delay = %s", got)
	}
	high := RetryPolicy{Base: time.Second, Max: time.Second, Random: func() float64 { return 9 }}
	if got, _ := high.Delay(0); got != time.Second {
		t.Errorf("over-one random delay = %s", got)
	}
	nan := RetryPolicy{Base: time.Second, Max: time.Second, Random: func() float64 { return math.NaN() }}
	if _, err := nan.Delay(0); err == nil {
		t.Fatal("NaN random source accepted")
	}
}

func TestRetryPolicyRejectsInvalidConfiguration(t *testing.T) {
	for _, policy := range []RetryPolicy{
		{},
		{Base: 2 * time.Second, Max: time.Second, Random: func() float64 { return 0 }},
		{Base: time.Second, Max: time.Second},
	} {
		if _, err := policy.Delay(0); err == nil {
			t.Errorf("invalid policy accepted: %#v", policy)
		}
	}
}

func TestClassifyHTTPRetryContract(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	policy := RetryPolicy{Base: time.Second, Max: 20 * time.Second, Random: func() float64 { return 0.25 }}
	tests := []struct {
		name       string
		status     int
		retryAfter string
		retry      bool
		delay      time.Duration
		reason     RetryReason
	}{
		{"success", http.StatusNoContent, "", false, 0, RetryNone},
		{"bad request", http.StatusBadRequest, "", false, 0, RetryPermanent},
		{"unauthorized", http.StatusUnauthorized, "", false, 0, RetryPermanent},
		{"timeout", http.StatusRequestTimeout, "", true, 250 * time.Millisecond, RetryTimeout},
		{"rate delta", http.StatusTooManyRequests, "7", true, 7 * time.Second, RetryRateLimited},
		{"rate date", http.StatusTooManyRequests, now.Add(9 * time.Second).Format(http.TimeFormat), true, 9 * time.Second, RetryRateLimited},
		{"rate cap", http.StatusTooManyRequests, "999", true, 20 * time.Second, RetryRateLimited},
		{"server", http.StatusServiceUnavailable, "", true, 250 * time.Millisecond, RetryServerFailure},
		{"invalid retry after", http.StatusBadGateway, "tomorrow", true, 250 * time.Millisecond, RetryServerFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := policy.ClassifyHTTP(tt.status, tt.retryAfter, now, 0)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Retry != tt.retry || decision.Delay != tt.delay || decision.Reason != tt.reason {
				t.Fatalf("decision = %#v, want retry=%v delay=%s reason=%s", decision, tt.retry, tt.delay, tt.reason)
			}
		})
	}
}

func TestRetryAfterPastDateRetriesImmediately(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	policy := RetryPolicy{Base: time.Second, Max: time.Minute, Random: func() float64 { return 1 }}
	decision, err := policy.ClassifyHTTP(http.StatusTooManyRequests, now.Add(-time.Hour).Format(http.TimeFormat), now, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Retry || decision.Delay != 0 {
		t.Fatalf("past Retry-After = %#v", decision)
	}
}

func TestNetworkFailureUsesSameBackoff(t *testing.T) {
	policy := RetryPolicy{Base: 2 * time.Second, Max: 10 * time.Second, Random: func() float64 { return 0.5 }}
	decision, err := policy.NetworkFailure(2)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Retry || decision.Reason != RetryNetwork || decision.Delay != 4*time.Second {
		t.Fatalf("network decision = %#v", decision)
	}
}
