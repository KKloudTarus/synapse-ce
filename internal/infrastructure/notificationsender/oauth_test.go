package notificationsender

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type oauthRoundTripper struct {
	mu     sync.Mutex
	calls  int
	status int
}

type smtpTokenTransport struct {
	endpoint string
	token    string
	calls    int
}

func (r *smtpTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls++
	if req.Method != http.MethodPost || req.URL.String() != r.endpoint {
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header), Request: req}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"access_token":%q,"expires_in":300}`, r.token))), Header: make(http.Header), Request: req}, nil
}

type expiringSMTPTokenTransport struct{ calls int }

func (r *expiringSMTPTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls++
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"access_token":"access-%d","expires_in":60}`, r.calls))), Header: make(http.Header), Request: req}, nil
}

type blockedSMTPTokenTransport struct {
	started chan struct{}
	release chan struct{}
	expires int
	mu      sync.Mutex
	calls   int
}

func (r *blockedSMTPTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.calls++
	if r.calls == 1 {
		close(r.started)
	}
	r.mu.Unlock()
	select {
	case <-r.release:
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"access_token":"blocked-access","expires_in":%d}`, r.expires))), Header: make(http.Header), Request: req}, nil
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

type smtpTTLTokenTransport struct {
	ttl   string
	calls int
}

func (r *smtpTTLTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls++
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"access_token":"ttl-%d",%s}`, r.calls, r.ttl))), Header: make(http.Header), Request: req}, nil
}

func (r *oauthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	if req.Method != http.MethodPost || req.URL.String() != googleSMTPTokenURL {
		return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header), Request: req}, nil
	}
	return &http.Response{StatusCode: r.status, Body: io.NopCloser(strings.NewReader(`{"access_token":"access-only","expires_in":300}`)), Header: make(http.Header), Request: req}, nil
}

func TestSMTPGoogleOAuthRefreshCachesByTenantRevision(t *testing.T) {
	roundTrip := &oauthRoundTripper{status: http.StatusOK}
	sender := New(SMTPConfig{}, time.Second)
	sender.http = &http.Client{Transport: roundTrip}
	sender.now = func() time.Time { return time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC) }
	relay := SMTPConfig{Host: "smtp.gmail.com", OAuthProvider: "google", OAuthClientID: "client", OAuthClientSecret: "private", OAuthRefreshToken: "refresh", OAuthCacheKey: "tenant:7"}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := sender.smtpOAuthToken(context.Background(), relay)
			if err != nil || token != "access-only" {
				t.Errorf("token=%q err=%v", token, err)
			}
		}()
	}
	wg.Wait()
	if roundTrip.calls != 1 {
		t.Fatalf("refresh calls=%d", roundTrip.calls)
	}
	if _, err := sender.smtpOAuthToken(context.Background(), SMTPConfig{Host: "smtp.gmail.com", OAuthProvider: "google", OAuthClientID: "client", OAuthClientSecret: "private", OAuthRefreshToken: "refresh", OAuthCacheKey: "tenant:8"}); err != nil {
		t.Fatal(err)
	}
	if roundTrip.calls != 2 {
		t.Fatalf("cross-revision cache reuse calls=%d", roundTrip.calls)
	}
}

func TestSMTPMicrosoftOAuthPinsDirectoryEndpoint(t *testing.T) {
	endpoint, form, err := oauthSMTPRequest(SMTPConfig{Host: "smtp.office365.com", OAuthProvider: "microsoft", OAuthClientID: "client", OAuthClientSecret: "private", OAuthDirectoryID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"})
	if err != nil || endpoint != "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/oauth2/v2.0/token" || form.Get("scope") != "https://outlook.office365.com/.default" {
		t.Fatalf("endpoint=%q form=%v err=%v", endpoint, form, err)
	}
	if _, _, err := oauthSMTPRequest(SMTPConfig{Host: "smtp.evil.test", OAuthProvider: "google", OAuthClientID: "client", OAuthClientSecret: "private", OAuthRefreshToken: "secret"}); err == nil {
		t.Fatal("un-pinned Google host accepted")
	}
}

func TestSMTPGoogleOAuthRefreshesNearExpiry(t *testing.T) {
	transport := &expiringSMTPTokenTransport{}
	sender := New(SMTPConfig{}, time.Second)
	sender.http = &http.Client{Transport: transport}
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	sender.now = func() time.Time { return now }
	relay := SMTPConfig{Host: "smtp.gmail.com", OAuthProvider: "google", OAuthClientID: "test-client", OAuthClientSecret: "test-client-secret", OAuthRefreshToken: "test-refresh-token", OAuthCacheKey: "tenant:1"}
	first, err := sender.smtpOAuthToken(context.Background(), relay)
	if err != nil || first != "access-1" {
		t.Fatalf("first token failed: err=%v", err)
	}
	now = now.Add(31 * time.Second)
	second, err := sender.smtpOAuthToken(context.Background(), relay)
	if err != nil || second != "access-2" || transport.calls != 2 {
		t.Fatalf("near-expiry token was reused: err=%v calls=%d", err, transport.calls)
	}
}

func TestSMTPGoogleOAuthRefreshLeavesOtherCachedTenantUnblockedAndWaitersCancellable(t *testing.T) {
	transport := &blockedSMTPTokenTransport{started: make(chan struct{}), release: make(chan struct{}), expires: 10}
	var releaseOnce sync.Once
	defer func() { releaseOnce.Do(func() { close(transport.release) }) }()
	sender := New(SMTPConfig{}, time.Second)
	sender.http = &http.Client{Transport: transport}
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	sender.now = func() time.Time { return now }
	fast := SMTPConfig{Host: "smtp.gmail.com", OAuthProvider: "google", OAuthClientID: "test-client", OAuthClientSecret: "test-client-secret", OAuthRefreshToken: "test-refresh-token", OAuthCacheKey: "fast"}
	slow := fast
	slow.OAuthCacheKey = "slow"
	sender.oauthTokens["fast:google"] = smtpOAuthToken{value: "cached-access", expires: now.Add(time.Hour)}
	leader := make(chan error, 1)
	go func() {
		_, err := sender.smtpOAuthToken(context.Background(), slow)
		leader <- err
	}()
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("slow refresh did not start")
	}
	fastResult := make(chan error, 1)
	go func() {
		got, err := sender.smtpOAuthToken(context.Background(), fast)
		if err == nil && got != "cached-access" {
			err = errors.New("cached token was not returned")
		}
		fastResult <- err
	}()
	select {
	case err := <-fastResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("cached tenant was blocked by another tenant refresh")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sender.smtpOAuthToken(cancelled, slow); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled same-key waiter error = %v", err)
	}
	sameKey := make(chan error, 1)
	go func() {
		_, err := sender.smtpOAuthToken(context.Background(), slow)
		sameKey <- err
	}()
	select {
	case err := <-sameKey:
		t.Fatalf("same-key waiter finished before refresh: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(transport.release) })
	if err := <-leader; err != nil {
		t.Fatalf("coalesced refresh leader failed: %v", err)
	}
	if err := <-sameKey; err != nil {
		t.Fatalf("coalesced refresh waiter failed: %v", err)
	}
	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()
	if calls != 1 {
		t.Fatalf("same-key refresh calls = %d, want 1", calls)
	}
}

func TestSMTPGoogleOAuthShortTTLIsNotReused(t *testing.T) {
	transport := &smtpTTLTokenTransport{ttl: `"expires_in":10`}
	sender := New(SMTPConfig{}, time.Second)
	sender.http = &http.Client{Transport: transport}
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	sender.now = func() time.Time { return now }
	relay := SMTPConfig{Host: "smtp.gmail.com", OAuthProvider: "google", OAuthClientID: "test-client", OAuthClientSecret: "test-client-secret", OAuthRefreshToken: "test-refresh-token", OAuthCacheKey: "tenant:short"}
	if _, err := sender.smtpOAuthToken(context.Background(), relay); err != nil {
		t.Fatal(err)
	}
	now = now.Add(15 * time.Second)
	if _, err := sender.smtpOAuthToken(context.Background(), relay); err != nil || transport.calls != 2 {
		t.Fatalf("short token reused: err=%v calls=%d", err, transport.calls)
	}
}

func TestSMTPGoogleOAuthRejectsMissingOrNonPositiveExpiry(t *testing.T) {
	for _, ttl := range []string{"", `"expires_in":0`} {
		t.Run(ttl, func(t *testing.T) {
			transport := &smtpTTLTokenTransport{ttl: ttl}
			sender := New(SMTPConfig{}, time.Second)
			sender.http = &http.Client{Transport: transport}
			relay := SMTPConfig{Host: "smtp.gmail.com", OAuthProvider: "google", OAuthClientID: "test-client", OAuthClientSecret: "test-client-secret", OAuthRefreshToken: "test-refresh-token", OAuthCacheKey: "tenant:invalid-expiry"}
			if _, err := sender.smtpOAuthToken(context.Background(), relay); err == nil {
				t.Fatal("invalid expiry accepted")
			}
		})
	}
}
