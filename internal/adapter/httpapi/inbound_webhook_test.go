package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	hookIDA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	hookIDB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

type fakeHookStore struct {
	mu       sync.Mutex
	records  map[string]ports.InboundWebhookEndpoint
	admitted map[string]int
	events   map[string]bool
	fail     bool
	decision *int
}

func (s *fakeHookStore) LookupInboundWebhook(_ context.Context, id string) (ports.InboundWebhookEndpoint, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return ports.InboundWebhookEndpoint{}, false, errors.New("db unavailable: do not echo")
	}
	e, ok := s.records[id]
	return e, ok, nil
}
func (s *fakeHookStore) AdmitInboundWebhook(_ context.Context, id ports.InboundWebhookIdentity, version int, usedPrevious bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return -1, errors.New("db unavailable: do not echo")
	}
	if s.decision != nil {
		return *s.decision, nil
	}
	e, ok := s.records[id.PublicID]
	if !ok || !e.Enabled || e.RevokedAt != nil || e.TenantID != id.TenantID ||
		e.OwnerKind != id.OwnerKind || e.OwnerID != id.OwnerID || e.CurrentVersion != version {
		return -1, nil
	}
	if usedPrevious && (e.PreviousSealed == "" || !e.PreviousExpiresAt.After(time.Now())) {
		return -1, nil
	}
	if s.admitted[id.PublicID] >= e.RatePerMinute {
		return 0, nil
	}
	s.admitted[id.PublicID]++
	return 1, nil
}
func (s *fakeHookStore) ClaimInboundWebhookEvent(_ context.Context, id ports.InboundWebhookIdentity, provider, eventID string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return false, errors.New("db unavailable: do not echo")
	}
	key := id.TenantID.String() + "|" + id.PublicID + "|" + provider + "|" + eventID
	if s.events[key] {
		return false, nil
	}
	s.events[key] = true
	return true, nil
}

func (s *fakeHookStore) ReleaseInboundWebhookEvent(_ context.Context, id ports.InboundWebhookIdentity, provider, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := id.TenantID.String() + "|" + id.PublicID + "|" + provider + "|" + eventID
	delete(s.events, key)
	return nil
}

type verifiedHook struct {
	tenant    shared.ID
	id        string
	provider  string
	eventType string
	eventID   string
	ref       string
	sha       string
	fork      bool
	body      string
}
type captureHookReceiver struct {
	mu   sync.Mutex
	seen []verifiedHook
	err  error
}

func (c *captureHookReceiver) ReceiveInboundWebhook(ctx context.Context, id ports.InboundWebhookIdentity, event ports.InboundWebhookEvent) error {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() || tenant != id.TenantID {
		return errors.New("receiver missing or mismatched authenticated tenant")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = append(c.seen, verifiedHook{tenant: tenant, id: id.PublicID, provider: event.Provider, eventType: event.EventType, eventID: event.EventID, ref: event.Ref, sha: event.SHA, fork: event.Fork, body: string(event.Body)})
	return c.err
}
func (c *captureHookReceiver) snapshot() []verifiedHook {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]verifiedHook(nil), c.seen...)
}

func hookSecret(i byte) []byte { return bytes.Repeat([]byte{i}, 32) }
func webhookSig(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
func setupHook(t *testing.T) (http.Handler, *fakeHookStore, *captureHookReceiver, *vault.Cipher) {
	return setupHookWithObserver(t, nil)
}

func setupHookWithObserver(t *testing.T, observer HTTPObserver) (http.Handler, *fakeHookStore, *captureHookReceiver, *vault.Cipher) {
	t.Helper()
	cipher, err := vault.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	mk := func(tenant shared.ID, publicID, owner string, secret []byte) ports.InboundWebhookEndpoint {
		key, err := cipher.Seal(secret, ports.InboundWebhookAAD(tenant, publicID, "integration", owner, 1))
		if err != nil {
			t.Fatal(err)
		}
		return ports.InboundWebhookEndpoint{
			PublicID: publicID, TenantID: tenant, OwnerKind: "integration", OwnerID: owner,
			CurrentVersion: 1, CurrentSealed: key, Enabled: true, RatePerMinute: 20,
		}
	}
	store := &fakeHookStore{records: map[string]ports.InboundWebhookEndpoint{
		hookIDA: mk("tenant-A", hookIDA, "integration-A", hookSecret('a')),
		hookIDB: mk("tenant-B", hookIDB, "integration-B", hookSecret('b')),
	}, admitted: map[string]int{}, events: map[string]bool{}}
	receiver := &captureHookReceiver{}
	// Route through the real root Handler, not only the isolated hook function.
	// The human resolver deliberately rejects every bearer credential.
	auth := NewAuthenticator(func(context.Context, string) (Principal, error) { return Principal{}, errTestCredentialInvalid })
	rt := &Router{log: discardLog(), auth: auth}
	rt.httpObserver = observer
	rt.SetInboundWebhookPlane(store, cipher, receiver)
	return rt.Handler(), store, receiver, cipher
}
func requestHook(h http.Handler, method, path string, body []byte, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if sig != "" {
		req.Header.Set(inboundWebhookSignature, sig)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
func assertHookCode(t *testing.T, got *httptest.ResponseRecorder, want int) {
	t.Helper()
	if got.Code != want {
		t.Fatalf("HTTP %d, want %d; body=%q", got.Code, want, got.Body.String())
	}
}

func assertHookNoStore(t *testing.T, got *httptest.ResponseRecorder) {
	t.Helper()
	if got.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("hook response Cache-Control = %q, want no-store", got.Header().Get("Cache-Control"))
	}
}

func TestInboundWebhookGitHubSignatureMetadataAndReplay(t *testing.T) {
	h, store, receiver, _ := setupHook(t)
	body := []byte(`{"ref":"refs/heads/main","after":"0123456789abcdef0123456789abcdef01234567"}`)
	store.mu.Lock()
	e := store.records[hookIDA]
	e.Provider = "github"
	store.records[hookIDA] = e
	store.mu.Unlock()
	path := "/api/v1/hooks/" + hookIDA
	request := func(delivery string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set(githubSignatureHeader, webhookSig(hookSecret('a'), body))
		req.Header.Set(githubEventHeader, "push")
		req.Header.Set(githubDeliveryHeader, delivery)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	assertHookCode(t, request("delivery-1"), http.StatusAccepted)
	assertHookCode(t, request("delivery-1"), http.StatusAccepted)
	seen := receiver.snapshot()
	if len(seen) != 1 || seen[0].provider != "github" || seen[0].eventType != "push" ||
		seen[0].eventID != "delivery-1" || seen[0].ref != "main" ||
		seen[0].sha != "0123456789abcdef0123456789abcdef01234567" || seen[0].fork || seen[0].body != "" {
		t.Fatalf("github receiver = %#v", seen)
	}
	// The legacy Synapse signature must not authenticate a GitHub endpoint.
	assertHookCode(t, requestHook(h, http.MethodPost, path, body, webhookSig(hookSecret('a'), body)), http.StatusUnauthorized)
}

func TestInboundWebhookGitHubForkPullRequest(t *testing.T) {
	h, store, receiver, _ := setupHook(t)
	store.mu.Lock()
	e := store.records[hookIDA]
	e.Provider = "github"
	store.records[hookIDA] = e
	store.mu.Unlock()

	sha := strings.Repeat("b", 40)
	body := []byte(`{"repository":{"clone_url":"https://attacker.invalid/ignored.git"},"pull_request":{"head":{"ref":"contrib/fix","sha":"` + sha + `","repo":{"id":22}},"base":{"repo":{"id":11}}}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hooks/"+hookIDA, bytes.NewReader(body))
	req.Header.Set(githubSignatureHeader, webhookSig(hookSecret('a'), body))
	req.Header.Set(githubEventHeader, "pull_request")
	req.Header.Set(githubDeliveryHeader, "fork-delivery")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertHookCode(t, rec, http.StatusAccepted)

	seen := receiver.snapshot()
	if len(seen) != 1 || !seen[0].fork || seen[0].ref != "contrib/fix" || seen[0].sha != sha || seen[0].body != "" {
		t.Fatalf("github fork receiver = %#v", seen)
	}
}

func TestInboundWebhookGitHubReceiverFailureIsRetryable(t *testing.T) {
	h, store, receiver, _ := setupHook(t)
	store.mu.Lock()
	e := store.records[hookIDA]
	e.Provider = "github"
	store.records[hookIDA] = e
	store.mu.Unlock()
	receiver.err = errors.New("queue unavailable")

	sha := strings.Repeat("c", 40)
	body := []byte(`{"ref":"refs/heads/main","after":"` + sha + `"}`)
	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hooks/"+hookIDA, bytes.NewReader(body))
		req.Header.Set(githubSignatureHeader, webhookSig(hookSecret('a'), body))
		req.Header.Set(githubEventHeader, "push")
		req.Header.Set(githubDeliveryHeader, "retry-delivery")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	assertHookCode(t, request(), http.StatusServiceUnavailable)
	receiver.mu.Lock()
	receiver.err = nil
	receiver.mu.Unlock()
	assertHookCode(t, request(), http.StatusAccepted)
	if len(receiver.snapshot()) != 2 {
		t.Fatal("failed receiver delivery remained permanently claimed")
	}
}

func TestInboundWebhookHostileCrossTenantAndNoHumanFallback(t *testing.T) {
	h, store, receiver, _ := setupHook(t)
	body := []byte("raw provider data; tenant_id=tenant-B")
	pathA := "/api/v1/hooks/" + hookIDA
	pathB := "/api/v1/hooks/" + hookIDB
	sigA := webhookSig(hookSecret('a'), body)
	assertHookCode(t, requestHook(h, http.MethodPost, pathA, body, sigA), http.StatusAccepted)
	// Even a perfectly valid HMAC for tenant A cannot route, publish or read
	// a tenant B integration; a body/query/header tenant override is ignored.
	rejected := []string{
		pathB, pathB + "?tenant_id=tenant-A", pathA + "?tenant_id=tenant-B",
	}
	for _, path := range rejected {
		got := requestHook(h, http.MethodPost, path, body, sigA)
		assertHookCode(t, got, http.StatusUnauthorized)
		if strings.Contains(got.Body.String(), "tenant") {
			t.Fatal("error disclosed tenant identity")
		}
	}
	// A human API token must not authenticate this plane.
	assertHookCode(t, requestHook(h, http.MethodPost, pathA, body, ""), http.StatusUnauthorized)
	assertHookCode(t, requestHook(h, http.MethodPost, pathB, body, webhookSig(hookSecret('b'), body)), http.StatusAccepted)
	// The route is method aware; siblings and GET stay on the human chain.
	assertHookCode(t, requestHook(h, http.MethodGet, pathA, nil, ""), http.StatusUnauthorized)
	assertHookCode(t, requestHook(h, http.MethodPost, pathA+"/other", body, sigA), http.StatusUnauthorized)
	seen := receiver.snapshot()
	if len(seen) != 2 || seen[0].tenant != "tenant-A" || seen[1].tenant != "tenant-B" {
		t.Fatalf("verified receiver unexpectedly received: %#v", seen)
	}
	store.mu.Lock()
	a, b := store.admitted[hookIDA], store.admitted[hookIDB]
	store.mu.Unlock()
	if a != 1 || b != 1 {
		t.Fatalf("cross-tenant calls consumed admission: A=%d B=%d", a, b)
	}
}

func TestInboundWebhookUniformFailuresAndHeaderChecks(t *testing.T) {
	h, store, receiver, _ := setupHook(t)
	body := []byte("payload")
	good := webhookSig(hookSecret('a'), body)
	unknown := "/api/v1/hooks/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	a := "/api/v1/hooks/" + hookIDA
	invalids := []*httptest.ResponseRecorder{
		requestHook(h, http.MethodPost, unknown, body, good),
		requestHook(h, http.MethodPost, a, body, webhookSig(hookSecret('b'), body)),
		requestHook(h, http.MethodPost, a, body, "sha256=invalid"),
		requestHook(h, http.MethodPost, a, body, ""),
	}
	store.mu.Lock()
	e := store.records[hookIDA]
	e.Enabled = false
	store.records[hookIDA] = e
	store.mu.Unlock()
	invalids = append(invalids, requestHook(h, http.MethodPost, a, body, good))
	store.mu.Lock()
	e.Enabled = true
	now := time.Now()
	e.RevokedAt = &now
	store.records[hookIDA] = e
	store.mu.Unlock()
	invalids = append(invalids, requestHook(h, http.MethodPost, a, body, good))
	for i, got := range invalids {
		assertHookCode(t, got, http.StatusUnauthorized)
		if uniformHookBody(t, got) != uniformHookBody(t, invalids[0]) {
			t.Errorf("negative path %d exposes a distinct response", i)
		}
	}
	// Repeated or ambiguous signatures must not be accepted.
	store.mu.Lock()
	e.RevokedAt = nil
	store.records[hookIDA] = e
	store.mu.Unlock()
	req := httptest.NewRequest(http.MethodPost, a, bytes.NewReader(body))
	req.Header.Add(inboundWebhookSignature, good)
	req.Header.Add(inboundWebhookSignature, good)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertHookCode(t, rec, http.StatusUnauthorized)
	if len(receiver.snapshot()) != 0 {
		t.Fatal("unauthenticated body reached provider receiver")
	}
	// A corrupted sealed key must fail closed without panicking or exposing
	// vault diagnostics in the authentication response.
	store.mu.Lock()
	e.CurrentSealed = "corrupted-ciphertext"
	store.records[hookIDA] = e
	store.mu.Unlock()
	corrupt := requestHook(h, http.MethodPost, a, body, good)
	assertHookCode(t, corrupt, http.StatusUnauthorized)
	if uniformHookBody(t, corrupt) != uniformHookBody(t, invalids[0]) {
		t.Fatal("corrupted vault ciphertext revealed a distinct error")
	}
}

func TestInboundWebhookBodyLimitAndAdmission(t *testing.T) {
	h, store, receiver, _ := setupHook(t)
	a := "/api/v1/hooks/" + hookIDA
	oversized := bytes.Repeat([]byte{'x'}, inboundWebhookBodyLimit+1)
	tooLarge := requestHook(h, http.MethodPost, a, oversized, webhookSig(hookSecret('a'), oversized))
	assertHookCode(t, tooLarge, http.StatusRequestEntityTooLarge)
	assertHookNoStore(t, tooLarge)
	// The 1 MiB limit also applies to unknown endpoints and requests without
	// credentials: read and bound raw bytes BEFORE the authentication lookup.
	assertHookCode(t,
		requestHook(h, http.MethodPost, "/api/v1/hooks/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", oversized, ""),
		http.StatusRequestEntityTooLarge)
	exact := bytes.Repeat([]byte{'x'}, inboundWebhookBodyLimit)
	assertHookCode(t, requestHook(h, http.MethodPost, a, exact, webhookSig(hookSecret('a'), exact)), http.StatusAccepted)
	store.mu.Lock()
	e := store.records[hookIDA]
	e.RatePerMinute = 1
	store.records[hookIDA] = e
	store.mu.Unlock()
	got := requestHook(h, http.MethodPost, a, exact, webhookSig(hookSecret('a'), exact))
	assertHookCode(t, got, http.StatusTooManyRequests)
	assertHookNoStore(t, got)
	if got.Header().Get("Retry-After") == "" {
		t.Fatal("429 omitted Retry-After")
	}
	if len(receiver.snapshot()) != 1 {
		t.Fatal("rate-limited body reached receiver")
	}
}

func TestInboundWebhookUnexpectedAdmissionFailsClosed(t *testing.T) {
	h, store, receiver, _ := setupHook(t)
	body := []byte("payload")
	unexpected := 2
	store.mu.Lock()
	store.decision = &unexpected
	store.mu.Unlock()

	got := requestHook(h, http.MethodPost, "/api/v1/hooks/"+hookIDA, body, webhookSig(hookSecret('a'), body))
	assertHookCode(t, got, http.StatusServiceUnavailable)
	assertHookNoStore(t, got)
	if len(receiver.snapshot()) != 0 {
		t.Fatal("unexpected admission decision reached provider receiver")
	}
}

func TestInboundWebhookObservationUsesRoutePattern(t *testing.T) {
	observer := &fakeHTTPObserver{}
	h, _, _, _ := setupHookWithObserver(t, observer)
	body := []byte("payload")
	got := requestHook(h, http.MethodPost, "/api/v1/hooks/"+hookIDA, body, webhookSig(hookSecret('a'), body))
	assertHookCode(t, got, http.StatusAccepted)

	calls := observer.snapshot()
	if len(calls) != 1 {
		t.Fatalf("observed %d hook requests, want 1", len(calls))
	}
	if calls[0].route != "POST /api/v1/hooks/{public_id}" || strings.Contains(calls[0].route, hookIDA) {
		t.Fatalf("hook observation exposed raw endpoint ID in route %q", calls[0].route)
	}
}

func TestInboundWebhookKeyRotationAndNoSilentAcceptance(t *testing.T) {
	h, store, receiver, cipher := setupHook(t)
	body := []byte("rotation")
	a := "/api/v1/hooks/" + hookIDA
	store.mu.Lock()
	e := store.records[hookIDA]
	e.CurrentVersion = 2
	e.PreviousSealed = e.CurrentSealed
	e.PreviousExpiresAt = time.Now().Add(23 * time.Hour)
	current, err := cipher.Seal(hookSecret('n'), ports.InboundWebhookAAD(e.TenantID, e.PublicID, e.OwnerKind, e.OwnerID, 2))
	if err != nil {
		t.Fatal(err)
	}
	e.CurrentSealed = current
	store.records[hookIDA] = e
	store.mu.Unlock()
	assertHookCode(t, requestHook(h, http.MethodPost, a, body, webhookSig(hookSecret('a'), body)), http.StatusAccepted)
	assertHookCode(t, requestHook(h, http.MethodPost, a, body, webhookSig(hookSecret('n'), body)), http.StatusAccepted)
	store.mu.Lock()
	e.PreviousExpiresAt = time.Now().Add(-time.Minute)
	store.records[hookIDA] = e
	store.mu.Unlock()
	assertHookCode(t, requestHook(h, http.MethodPost, a, body, webhookSig(hookSecret('a'), body)), http.StatusUnauthorized)
	if len(receiver.snapshot()) != 2 {
		t.Fatal("expired overlap key reached receiver")
	}
	// A receiver not yet registered must not report a successful ingestion.
	auth := NewAuthenticator(func(context.Context, string) (Principal, error) { return Principal{}, errTestCredentialInvalid })
	rt := &Router{log: discardLog(), auth: auth}
	rt.SetInboundWebhookPlane(store, cipher, nil)
	assertHookCode(t, requestHook(rt.Handler(), http.MethodPost, a, body, webhookSig(hookSecret('n'), body)), http.StatusServiceUnavailable)
	store.mu.Lock()
	store.fail = true
	store.mu.Unlock()
	got := requestHook(h, http.MethodPost, a, body, webhookSig(hookSecret('n'), body))
	assertHookCode(t, got, http.StatusServiceUnavailable)
	if strings.Contains(got.Body.String(), "db unavailable") {
		t.Fatal("internal DB error leaked")
	}
}

func TestInboundWebhookEndpointAADIsTenantAndVersionBound(t *testing.T) {
	_, store, _, cipher := setupHook(t)
	e := store.records[hookIDA]
	if _, err := cipher.Open(e.CurrentSealed, ports.InboundWebhookAAD("tenant-B", e.PublicID, e.OwnerKind, e.OwnerID, 1)); err == nil {
		t.Fatal("cross-tenant vault ciphertext was reusable")
	}
	if _, err := cipher.Open(e.CurrentSealed, ports.InboundWebhookAAD(e.TenantID, e.PublicID, e.OwnerKind, e.OwnerID, 2)); err == nil {
		t.Fatal("previous vault ciphertext was reusable under another version")
	}
}

// uniformHookBody returns a hook error body without its request_id. The id is the per-request
// correlation value already sent as X-Request-ID, so it reveals nothing about why a request failed;
// every other byte of the body must be identical across failure causes.
func uniformHookBody(t *testing.T, got *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
		t.Fatalf("hook error body is not JSON: %v", err)
	}
	if id, _ := body["request_id"].(string); id != got.Header().Get("X-Request-ID") {
		t.Fatalf("hook request_id %q does not match X-Request-ID %q", id, got.Header().Get("X-Request-ID"))
	}
	delete(body, "request_id")
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func gitLabSigningSecret(fill byte) []byte {
	raw := bytes.Repeat([]byte{fill}, sha256.Size)
	return []byte("whsec_" + base64.StdEncoding.EncodeToString(raw))
}

func gitLabSignedHeaders(secret, body []byte, at time.Time, messageID, eventID string) http.Header {
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(string(secret), "whsec_"))
	timestamp := fmt.Sprintf("%d", at.Unix())
	mac := hmac.New(sha256.New, raw)
	_, _ = mac.Write([]byte(messageID + "." + timestamp + "."))
	_, _ = mac.Write(body)
	header := make(http.Header)
	header.Set(gitLabWebhookIDHeader, messageID)
	header.Set(gitLabTimestampHeader, timestamp)
	header.Set(gitLabSignatureHeader, "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	header.Set(gitLabEventHeader, "Push Hook")
	header.Set(gitLabEventUUIDHeader, eventID)
	return header
}

func requestHookHeaders(h http.Handler, path string, body []byte, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestInboundGitLabSigningTokenWindowAndPrecedence(t *testing.T) {
	h, store, receiver, cipher := setupHook(t)
	body := []byte(`{"ref":"refs/heads/main","checkout_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	secret := gitLabSigningSecret('s')
	store.mu.Lock()
	e := store.records[hookIDA]
	e.Provider = "gitlab"
	sealed, err := cipher.Seal(secret, ports.InboundWebhookAAD(e.TenantID, e.PublicID, e.OwnerKind, e.OwnerID, e.CurrentVersion))
	if err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	e.CurrentSealed = sealed
	store.records[hookIDA] = e
	store.mu.Unlock()

	path := "/api/v1/hooks/" + hookIDA
	eventID := "13792a34-cac6-4fda-95a8-c58e00a3954e"
	headers := gitLabSignedHeaders(secret, body, time.Now(), "f5e5f430-f57b-4e6e-9fac-d9128cd7232f", eventID)
	assertHookCode(t, requestHookHeaders(h, path, body, headers), http.StatusAccepted)
	// Transport authentication deliberately does not own provider replay
	// semantics. A second authenticated delivery reaches the provider receiver;
	// the GitLab receiver's event deduper is tested in scmwebhook.
	assertHookCode(t, requestHookHeaders(h, path, body, headers), http.StatusAccepted)
	seen := receiver.snapshot()
	if got := len(seen); got != 2 {
		t.Fatalf("authenticated deliveries reaching receiver = %d, want 2", got)
	}
	if seen[0].eventID != headers.Get(gitLabWebhookIDHeader) {
		t.Fatalf("signed delivery replay id = %q, want signed message ID", seen[0].eventID)
	}

	stale := gitLabSignedHeaders(secret, body, time.Now().Add(-6*time.Minute), "another-message-id", "23792a34-cac6-4fda-95a8-c58e00a3954e")
	assertHookCode(t, requestHookHeaders(h, path, body, stale), http.StatusUnauthorized)

	// Presence of a signing header selects signing-token verification. A valid
	// legacy token cannot downgrade an invalid signature.
	bad := gitLabSignedHeaders(secret, body, time.Now(), "bad-signature-message", "33792a34-cac6-4fda-95a8-c58e00a3954e")
	bad.Set(gitLabSignatureHeader, "v1,"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, sha256.Size)))
	bad.Set(gitLabLegacyAuthHeader, string(secret))
	assertHookCode(t, requestHookHeaders(h, path, body, bad), http.StatusUnauthorized)
}

func TestInboundGitLabLegacyTokenReceiverRetry(t *testing.T) {
	h, store, receiver, cipher := setupHook(t)
	body := []byte(`{"ref":"refs/heads/main","checkout_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
	secret := bytes.Repeat([]byte{'l'}, 32)
	store.mu.Lock()
	e := store.records[hookIDA]
	e.Provider = "gitlab"
	sealed, err := cipher.Seal(secret, ports.InboundWebhookAAD(e.TenantID, e.PublicID, e.OwnerKind, e.OwnerID, e.CurrentVersion))
	if err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	e.CurrentSealed = sealed
	store.records[hookIDA] = e
	store.mu.Unlock()

	headers := make(http.Header)
	headers.Set(gitLabLegacyAuthHeader, string(secret))
	headers.Set(gitLabEventHeader, "Push Hook")
	legacyEventID := "43792a34-cac6-4fda-95a8-c58e00a3954e"
	headers.Set(gitLabEventUUIDHeader, legacyEventID)
	path := "/api/v1/hooks/" + hookIDA

	receiver.err = errors.New("temporary receiver failure")
	assertHookCode(t, requestHookHeaders(h, path, body, headers), http.StatusServiceUnavailable)
	receiver.err = nil
	// A provider receiver failure is surfaced as 503 so GitLab can retry.
	assertHookCode(t, requestHookHeaders(h, path, body, headers), http.StatusAccepted)
	seen := receiver.snapshot()
	if got := len(seen); got != 2 {
		t.Fatalf("receiver calls across failed retry = %d, want 2", got)
	}
	if seen[0].eventID != legacyEventID {
		t.Fatalf("legacy delivery replay id = %q, want event UUID %q", seen[0].eventID, legacyEventID)
	}
}

func TestInboundGitLabInvalidPayloadIs400AndRetryable(t *testing.T) {
	h, store, receiver, cipher := setupHook(t)
	body := []byte(`{"ref":"refs/heads/main","checkout_sha":"not-a-sha"}`)
	secret := bytes.Repeat([]byte{'v'}, 32)
	store.mu.Lock()
	e := store.records[hookIDA]
	e.Provider = "gitlab"
	sealed, err := cipher.Seal(secret, ports.InboundWebhookAAD(e.TenantID, e.PublicID, e.OwnerKind, e.OwnerID, e.CurrentVersion))
	if err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	e.CurrentSealed = sealed
	store.records[hookIDA] = e
	store.mu.Unlock()

	headers := make(http.Header)
	headers.Set(gitLabLegacyAuthHeader, string(secret))
	headers.Set(gitLabEventHeader, "Push Hook")
	headers.Set(gitLabEventUUIDHeader, "53792a34-cac6-4fda-95a8-c58e00a3954e")
	receiver.err = fmt.Errorf("%w: invalid GitLab webhook sha", shared.ErrValidation)
	path := "/api/v1/hooks/" + hookIDA
	assertHookCode(t, requestHookHeaders(h, path, body, headers), http.StatusBadRequest)

	receiver.err = nil
	// A 400 from provider parsing releases the event claim. If a corrected
	// request is redelivered with the same provider event UUID, it is processed.
	assertHookCode(t, requestHookHeaders(h, path, body, headers), http.StatusAccepted)
	if got := len(receiver.snapshot()); got != 2 {
		t.Fatalf("receiver calls across validation retry = %d, want 2", got)
	}
}
