package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestVulnDetailRetriesTransientStatus(t *testing.T) {
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		// First call: a transient 429; second call: success. The retry must bridge the gap.
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(osvVuln{ID: r.PathValue("id")})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc := New(srv.URL, srv.Client())
	v, err := sc.vulnDetail(context.Background(), "CVE-2026-0001")
	if err != nil {
		t.Fatalf("vulnDetail should have retried past the 429: %v", err)
	}
	if v.ID != "CVE-2026-0001" {
		t.Fatalf("id = %q, want CVE-2026-0001", v.ID)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 calls (one retry), got %d", got)
	}
}

func TestVulnDetailGivesUpAfterRetries(t *testing.T) {
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable) // always down
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc := New(srv.URL, srv.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := sc.vulnDetail(ctx, "CVE-2026-0002"); err == nil {
		t.Fatal("a persistently-503 source must return an error (so the degrade policy can skip it)")
	}
	if got := calls.Load(); got != maxRetries+1 {
		t.Fatalf("expected %d attempts, got %d", maxRetries+1, got)
	}
}

func TestIsRetryableStatus(t *testing.T) {
	retryable := []int{429, 500, 502, 503, 504}
	for _, c := range retryable {
		if !isRetryableStatus(c) {
			t.Errorf("status %d should be retryable", c)
		}
	}
	for _, c := range []int{200, 400, 401, 403, 404, 422} {
		if isRetryableStatus(c) {
			t.Errorf("status %d should NOT be retryable", c)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	if got := retryAfter("2"); got != 2*time.Second {
		t.Errorf("retryAfter(2) = %v, want 2s", got)
	}
	if got := retryAfter("99999"); got != maxBackoff {
		t.Errorf("retryAfter cap = %v, want %v", got, maxBackoff)
	}
	if got := retryAfter(""); got != 0 {
		t.Errorf("retryAfter(empty) = %v, want 0", got)
	}
	if got := retryAfter("Wed, 21 Oct 2026 07:28:00 GMT"); got != 0 {
		t.Errorf("retryAfter(http-date) = %v, want 0 (only integer seconds honored)", got)
	}
}
