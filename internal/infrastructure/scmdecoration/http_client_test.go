package scmdecoration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestJSONHTTPClientHonorsRetryAfterOnRateLimit(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client := newJSONHTTPClient(server.Client(), server.URL)
	var slept time.Duration
	client.sleep = func(_ context.Context, delay time.Duration) error { slept = delay; return nil }
	if err := client.doJSON(context.Background(), http.MethodPost, "/write", nil, map[string]string{"x": "y"}, nil, false); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || slept != 7*time.Second {
		t.Fatalf("calls/sleep = %d/%s, want 2/7s", calls, slept)
	}
}

func TestJSONHTTPClientHonorsPrimaryRateLimitResetOnForbidden(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client := newJSONHTTPClient(server.Client(), server.URL)
	var slept time.Duration
	client.sleep = func(_ context.Context, delay time.Duration) error { slept = delay; return nil }
	if err := client.doJSON(context.Background(), http.MethodPost, "/write", nil, map[string]string{"x": "y"}, nil, false); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || slept != defaultRetryCap {
		t.Fatalf("calls/sleep = %d/%s, want 2/%s", calls, slept, defaultRetryCap)
	}
}

func TestJSONHTTPClientDoesNotRetryUnauthorized(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	client := newJSONHTTPClient(server.Client(), server.URL)
	client.sleep = func(_ context.Context, _ time.Duration) error {
		t.Fatal("401 must not be retried")
		return nil
	}
	err := client.doJSON(context.Background(), http.MethodGet, "/read", nil, nil, nil, true)
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || calls != 1 {
		t.Fatalf("error/calls = %v/%d, want HTTP 401 after one request", err, calls)
	}
}

func TestJSONHTTPClientRejectsMalformedJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":`))
	}))
	defer server.Close()
	client := newJSONHTTPClient(server.Client(), server.URL)
	var output map[string]any
	err := client.doJSON(context.Background(), http.MethodGet, "/read", nil, nil, &output, true)
	if err == nil || !strings.Contains(err.Error(), "decode forge response") {
		t.Fatalf("error = %v, want malformed JSON decode failure", err)
	}
}

func TestJSONHTTPClientCapsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 32)))
	}))
	defer server.Close()
	client := newJSONHTTPClient(server.Client(), server.URL)
	client.responseCap = 8
	err := client.doJSON(context.Background(), http.MethodGet, "/read", nil, nil, nil, true)
	if err == nil || !strings.Contains(err.Error(), "8-byte limit") {
		t.Fatalf("error = %v", err)
	}
}
