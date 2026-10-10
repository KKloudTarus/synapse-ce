package teamsbot

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	testAppID    = "11111111-2222-3333-4444-555555555555"
	testPassword = "bot-password-secret-value"
)

func TestValidServiceURL(t *testing.T) {
	for _, ok := range []string{"https://smba.trafficmanager.net/amer/", "https://smba.trafficmanager.net/teams/", "https://smba.infra.gcc.teams.microsoft.com/", "https://SMBA.trafficmanager.net:443/emea/"} {
		if !ValidServiceURL(ok) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{"http://smba.trafficmanager.net/amer/", "https://evil.example/", "https://smba.trafficmanager.net.evil.example/", "https://smba.trafficmanager.net:8443/", "https://user@smba.trafficmanager.net/", "https://smba.trafficmanager.net/?x=1", "https://127.0.0.1/", ""} {
		if ValidServiceURL(bad) {
			t.Errorf("%s accepted", bad)
		}
	}
}

// fakeMicrosoft is a token endpoint and a Bot Connector in one server.
type fakeMicrosoft struct {
	*httptest.Server
	mu         sync.Mutex
	tokens     int
	tokenForm  url.Values
	posts      []string
	auths      []string
	connector  func(w http.ResponseWriter)
	tokenReply func(w http.ResponseWriter)
}

func newFakeMicrosoft(t *testing.T) *fakeMicrosoft {
	t.Helper()
	f := &fakeMicrosoft{}
	f.connector = func(w http.ResponseWriter) { w.WriteHeader(201); _, _ = io.WriteString(w, `{"id":"activity-1"}`) }
	f.tokenReply = func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"access_token":"connector-token","expires_in":3600}`) }
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			f.tokens++
			f.tokenForm, _ = url.ParseQuery(string(body))
			f.tokenReply(w)
			return
		}
		f.posts = append(f.posts, r.URL.EscapedPath()+" "+string(body))
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		f.connector(w)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeMicrosoft) client(cfg Config) *Client {
	c := New(cfg, f.Client()).WithLoginBase(f.Client(), f.URL)
	c.validService = func(raw string) bool { return strings.HasPrefix(raw, f.URL) }
	return c
}

func ref(f *fakeMicrosoft) ports.TeamsConversationRef {
	return ports.TeamsConversationRef{ServiceURL: f.URL + "/amer/", ConversationID: "a:1Xy/conv", UserObjectID: "0a0b0c0d-1111-2222-3333-444455556666"}
}

func TestSendGetsATokenOnceAndPostsTheActivity(t *testing.T) {
	f := newFakeMicrosoft(t)
	c := f.client(Config{AppID: testAppID, AppPassword: testPassword, TenantID: "99999999-8888-7777-6666-555555555555"})
	for i := 0; i < 2; i++ {
		id, err := c.Send(context.Background(), ref(f), []byte(`{"type":"message","text":"hi"}`))
		if err != nil || id != "activity-1" {
			t.Fatalf("send = %q %v", id, err)
		}
	}
	if f.tokens != 1 {
		t.Fatalf("token requests = %d, want 1 (cached)", f.tokens)
	}
	if f.tokenForm.Get("client_id") != testAppID || f.tokenForm.Get("client_secret") != testPassword || f.tokenForm.Get("scope") != "https://api.botframework.com/.default" || f.tokenForm.Get("grant_type") != "client_credentials" {
		t.Fatalf("token form = %v", f.tokenForm)
	}
	if !strings.HasPrefix(f.posts[0], "/amer/v3/conversations/a:1Xy%2Fconv/activities ") || f.auths[0] != "Bearer connector-token" {
		t.Fatalf("post = %q auth = %q", f.posts[0], f.auths[0])
	}
}

func TestSendClassifiesConnectorReplies(t *testing.T) {
	cases := []struct {
		status    int
		header    string
		code      string
		retryable bool
		after     time.Duration
	}{
		{404, "", "teams_conversation_gone", false, 0},
		{403, "", "teams_conversation_gone", false, 0},
		{401, "", "teams_401", true, 0},
		{429, "12", "http_429", true, 12 * time.Second},
		{503, "", "http_503", true, 0},
		{400, "", "http_400", false, 0},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			f := newFakeMicrosoft(t)
			f.connector = func(w http.ResponseWriter) {
				if tc.header != "" {
					w.Header().Set("Retry-After", tc.header)
				}
				w.WriteHeader(tc.status)
			}
			_, err := f.client(Config{AppID: testAppID, AppPassword: testPassword}).Send(context.Background(), ref(f), []byte(`{}`))
			got := AsError(err)
			if got.Code != tc.code || got.Retryable != tc.retryable || got.RetryAfter != tc.after {
				t.Fatalf("error = %+v", got)
			}
			if result := got.TeamsResult(); result.ErrorCode != tc.code || strings.Contains(fmt.Sprintf("%+v", result), testPassword) {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestTokenFailuresNeverLeakThePassword(t *testing.T) {
	f := newFakeMicrosoft(t)
	f.tokenReply = func(w http.ResponseWriter) { w.WriteHeader(401); _, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"`+testPassword+`"}`) }
	_, err := f.client(Config{AppID: testAppID, AppPassword: testPassword}).Send(context.Background(), ref(f), []byte(`{}`))
	if got := AsError(err); got.Code != "teams_token_401" || got.Retryable || strings.Contains(err.Error(), testPassword) {
		t.Fatalf("error = %+v (%v)", got, err)
	}
	if _, err := New(Config{}, f.Client()).Send(context.Background(), ports.TeamsConversationRef{ServiceURL: "https://smba.trafficmanager.net/amer/", ConversationID: "c"}, []byte(`{}`)); AsError(err).Code != "teams_bot_not_configured" {
		t.Fatalf("unconfigured: %v", err)
	}
}

func TestSendRefusesAForeignServiceURL(t *testing.T) {
	f := newFakeMicrosoft(t)
	c := New(Config{AppID: testAppID, AppPassword: testPassword}, f.Client())
	_, err := c.Send(context.Background(), ports.TeamsConversationRef{ServiceURL: "https://evil.example/", ConversationID: "c"}, []byte(`{}`))
	if AsError(err).Code != "teams_conversation_invalid" || f.tokens != 0 || len(f.posts) != 0 {
		t.Fatalf("err = %v tokens=%d posts=%d", err, f.tokens, len(f.posts))
	}
}

// signedToken builds an RS256 JWT with key and claims.
func signedToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	input := enc(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifierChecksIssuerAudienceKeyAndServiceURL(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifierWithKeys(testAppID, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{key.Public()}})
	service := "https://smba.trafficmanager.net/amer/"
	now := time.Now()
	claims := func(mutate func(map[string]any)) map[string]any {
		c := map[string]any{"iss": "https://api.botframework.com", "aud": testAppID, "exp": now.Add(time.Hour).Unix(), "nbf": now.Add(-time.Minute).Unix(), "serviceurl": service}
		if mutate != nil {
			mutate(c)
		}
		return c
	}
	if err := v.Verify(context.Background(), "Bearer "+signedToken(t, key, claims(nil)), service); err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	refused := map[string]string{
		"wrong key":         "Bearer " + signedToken(t, other, claims(nil)),
		"wrong audience":    "Bearer " + signedToken(t, key, claims(func(c map[string]any) { c["aud"] = "another-bot" })),
		"wrong issuer":      "Bearer " + signedToken(t, key, claims(func(c map[string]any) { c["iss"] = "https://sts.windows.net/x/" })),
		"expired":           "Bearer " + signedToken(t, key, claims(func(c map[string]any) { c["exp"] = now.Add(-time.Hour).Unix() })),
		"other service url": "Bearer " + signedToken(t, key, claims(func(c map[string]any) { c["serviceurl"] = "https://smba.trafficmanager.net/emea/" })),
		"no service url":    "Bearer " + signedToken(t, key, claims(func(c map[string]any) { delete(c, "serviceurl") })),
		"no bearer":         signedToken(t, key, claims(nil)),
		"empty":             "",
		"garbage":           "Bearer not.a.token",
		"oversized":         "Bearer " + strings.Repeat("a", 9000),
	}
	for name, header := range refused {
		if err := v.Verify(context.Background(), header, service); err != ErrUnauthorized {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
