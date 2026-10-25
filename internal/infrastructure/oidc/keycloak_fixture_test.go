//go:build keycloak_integration

package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/html"
)

const keycloakImage = "quay.io/keycloak/keycloak@sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b"

// keycloakFixture is deliberately process-local: its TLS front door is the only issuer exposed
// to the provider and its container has no persisted volume or published non-loopback port.
type keycloakFixture struct {
	t                     *testing.T
	proxy                 *httptest.Server
	backendMu             sync.RWMutex
	backend               *url.URL
	container             string
	network               string
	realm                 string
	realmB                string
	clientID              string
	clientSecret          string
	callbackURL           string
	issuer                string
	users                 map[string]string
	substituteMu          sync.Mutex
	substituteAAuthWithB  bool
	substituteATokenWithB bool
	substituteACertsWithB bool
}

func newKeycloakFixture(t *testing.T, relativePath string) *keycloakFixture {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("keycloak integration requires docker")
	}
	f := &keycloakFixture{t: t, realm: "synapse" + keycloakRandom(t, 8), realmB: "synapse" + keycloakRandom(t, 8), clientID: "synapse" + keycloakRandom(t, 8), clientSecret: keycloakRandom(t, 32), users: make(map[string]string)}
	f.proxy = httptest.NewUnstartedServer(http.HandlerFunc(f.serveProxy))
	f.proxy.StartTLS()
	t.Cleanup(f.proxy.Close)
	base := strings.TrimSuffix(f.proxy.URL, "/")
	f.callbackURL = base + "/callback"
	path := strings.TrimSuffix(relativePath, "/")
	f.issuer = base + path + "/realms/" + f.realm
	f.network = "synapse-kc-" + keycloakRandom(t, 8)
	f.container = "synapse-kc-" + keycloakRandom(t, 8)
	runID := os.Getenv("SYNAPSE_KEYCLOAK_RUN_ID")
	if runID == "" {
		runID = keycloakRandom(t, 16)
	}
	if len(runID) != 32 {
		t.Fatal("SYNAPSE_KEYCLOAK_RUN_ID must be 32 hexadecimal characters")
	}
	if _, err := hex.DecodeString(runID); err != nil {
		t.Fatal("SYNAPSE_KEYCLOAK_RUN_ID must be 32 hexadecimal characters")
	}
	label := "com.synapse.keycloak-conformance.run=" + runID
	f.docker(t.Context(), "network", "create", "--internal", "--label", label, f.network)
	t.Cleanup(func() { f.dockerCleanup("network", "rm", f.network) })

	users := []keycloakRealmUser{f.realmUser("recipient@example.test"), f.realmUser("unknown@example.test")}
	client := keycloakRealmClient{ClientID: f.clientID, Secret: f.clientSecret, Enabled: true, Protocol: "openid-connect", PublicClient: false, StandardFlowEnabled: true, RedirectURIs: []string{f.callbackURL}, WebOrigins: []string{base}, Attributes: map[string]string{"pkce.code.challenge.method": "S256"}}
	realmA, err := json.Marshal(keycloakRealm{Realm: f.realm, Enabled: true, Clients: []keycloakRealmClient{client}, Users: users})
	if err != nil {
		t.Fatal("encode Keycloak realm A")
	}
	realmB, err := json.Marshal(keycloakRealm{Realm: f.realmB, Enabled: true, Clients: []keycloakRealmClient{client}, Users: users})
	if err != nil {
		t.Fatal("encode Keycloak realm B")
	}
	tempDir, err := os.MkdirTemp("", "synapse-keycloak-realms-")
	if err != nil {
		t.Fatal("create Keycloak realm import directory")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Error("remove temporary Keycloak realm imports")
		}
	})
	importA, importB := filepath.Join(tempDir, "realm-a.json"), filepath.Join(tempDir, "realm-b.json")
	if err := os.WriteFile(importA, realmA, 0o600); err != nil {
		t.Fatal("write Keycloak realm A import")
	}
	if err := os.WriteFile(importB, realmB, 0o600); err != nil {
		t.Fatal("write Keycloak realm B import")
	}

	hostname := base + path
	// The shell is static: it only waits for the root-only chown marker, then starts Keycloak.
	// Realm data and generated credentials are never interpolated into an argv or shell string.
	createArgs := []string{"create", "--name", f.container, "--label", label, "--network", f.network, "--memory", "1g", "--cpus", "2", "--pids-limit", "256", "-e", "KC_HTTP_ENABLED=true", "-e", "KC_PROXY_HEADERS=xforwarded", "-e", "KC_HOSTNAME=" + hostname}
	if path != "" {
		createArgs = append(createArgs, "-e", "KC_HTTP_RELATIVE_PATH="+path)
	}
	createArgs = append(createArgs, "--entrypoint", "/bin/sh", keycloakImage, "-ec", "i=0; while [ ! -f /tmp/import-ready ]; do i=$((i+1)); [ $i -le 30 ] || exit 1; sleep 1; done; exec /opt/keycloak/bin/kc.sh start-dev --import-realm")
	f.docker(t.Context(), createArgs...)
	t.Cleanup(func() { f.dockerCleanup("rm", "-f", f.container) })
	f.docker(t.Context(), "cp", importA, f.container+":/tmp/realm-a.json")
	f.docker(t.Context(), "cp", importB, f.container+":/tmp/realm-b.json")
	f.docker(t.Context(), "start", f.container)
	f.docker(t.Context(), "exec", "--user", "0", f.container, "/bin/sh", "-ec", "mkdir -p /opt/keycloak/data/import; mv /tmp/realm-a.json /opt/keycloak/data/import/realm-a.json; mv /tmp/realm-b.json /opt/keycloak/data/import/realm-b.json; chown 1000:0 /opt/keycloak/data/import/realm-a.json /opt/keycloak/data/import/realm-b.json; touch /tmp/import-ready")
	containerIP := strings.TrimSpace(f.docker(t.Context(), "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", f.container))
	if net.ParseIP(containerIP) == nil {
		t.Fatal("read Keycloak isolated network address")
	}
	backend, err := url.Parse("http://" + net.JoinHostPort(containerIP, "8080"))
	if err != nil {
		t.Fatal("parse Keycloak backend")
	}
	f.backendMu.Lock()
	f.backend = backend
	f.backendMu.Unlock()
	f.waitReady()
	return f
}

func (f *keycloakFixture) realmUser(email string) keycloakRealmUser {
	password := f.users[email]
	if password == "" {
		password = keycloakRandom(f.t, 24)
		f.users[email] = password
	}
	return keycloakRealmUser{Username: email, Email: email, FirstName: "Synapse", LastName: "Test", Enabled: true, EmailVerified: true, Credentials: []keycloakRealmCredential{{Type: "password", Value: password, Temporary: false}}}
}

func (f *keycloakFixture) serveProxy(w http.ResponseWriter, r *http.Request) {
	f.backendMu.RLock()
	backend := f.backend
	f.backendMu.RUnlock()
	if backend == nil {
		http.Error(w, "provider starting", http.StatusServiceUnavailable)
		return
	}
	f.substituteMu.Lock()
	authSubstitute := f.substituteAAuthWithB && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/realms/"+f.realm+"/protocol/openid-connect/auth")
	tokenSubstitute := f.substituteATokenWithB && r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/realms/"+f.realm+"/protocol/openid-connect/token")
	certsSubstitute := f.substituteACertsWithB && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/realms/"+f.realm+"/protocol/openid-connect/certs")
	if authSubstitute {
		f.substituteAAuthWithB = false
		r.URL.Path = strings.Replace(r.URL.Path, "/realms/"+f.realm+"/", "/realms/"+f.realmB+"/", 1)
		r.URL.RawPath = ""
	}
	if tokenSubstitute {
		f.substituteATokenWithB = false
		r.URL.Path = strings.Replace(r.URL.Path, "/realms/"+f.realm+"/", "/realms/"+f.realmB+"/", 1)
		r.URL.RawPath = ""
	}
	if certsSubstitute {
		f.substituteACertsWithB = false
		r.URL.Path = strings.Replace(r.URL.Path, "/realms/"+f.realm+"/", "/realms/"+f.realmB+"/", 1)
		r.URL.RawPath = ""
	}
	f.substituteMu.Unlock()
	originalHost := r.Host
	proxy := httputil.NewSingleHostReverseProxy(backend)
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		req.Host = backend.Host
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", originalHost)
		req.Header.Set("X-Forwarded-Port", "443")
	}
	proxy.ErrorHandler = func(http.ResponseWriter, *http.Request, error) {
		http.Error(w, "provider unavailable", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}

func (f *keycloakFixture) waitReady() {
	deadline := time.Now().Add(2 * time.Minute)
	client := f.proxy.Client()
	client.Timeout = 15 * time.Second
	for time.Now().Before(deadline) {
		if strings.TrimSpace(f.docker(f.t.Context(), "inspect", "--format", "{{.State.Running}}", f.container)) != "true" {
			f.t.Fatal("Keycloak exited before readiness")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.issuer+"/.well-known/openid-configuration", nil)
		response, err := client.Do(req)
		cancel()
		if err == nil && response != nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	f.t.Fatal("Keycloak did not become ready")
}

func (f *keycloakFixture) provider() *Provider {
	client := f.proxy.Client()
	client.Timeout = 15 * time.Second
	return newProvider(Config{Issuer: f.issuer, ClientID: f.clientID, ClientSecret: f.clientSecret, RedirectURL: f.callbackURL}, f.issuer, client)
}

func (f *keycloakFixture) providerB() *Provider {
	client := f.proxy.Client()
	client.Timeout = 15 * time.Second
	issuer := strings.Replace(f.issuer, "/realms/"+f.realm, "/realms/"+f.realmB, 1)
	return newProvider(Config{Issuer: issuer, ClientID: f.clientID, ClientSecret: f.clientSecret, RedirectURL: f.callbackURL}, issuer, client)
}

func (f *keycloakFixture) substituteNextAFlowWithB() {
	f.substituteMu.Lock()
	defer f.substituteMu.Unlock()
	f.substituteAAuthWithB = true
	f.substituteATokenWithB = true
}

func (f *keycloakFixture) substituteNextAFlowAndCertsWithB() {
	f.substituteMu.Lock()
	defer f.substituteMu.Unlock()
	f.substituteAAuthWithB = true
	f.substituteATokenWithB = true
	f.substituteACertsWithB = true
}

// authorize performs an actual browser authorization-code login. It accepts only redirects and
// forms on the fixed TLS issuer, and never includes a credential in a returned error.
func (f *keycloakFixture) authorize(ctx context.Context, authorizationURL, email string) (string, string) {
	f.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		f.t.Fatal("create browser cookie jar")
	}
	client := &http.Client{Transport: f.proxy.Client().Transport, Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	current, err := url.Parse(authorizationURL)
	if err != nil || !f.sameOrigin(current) {
		f.t.Fatal("invalid provider authorization URL")
	}
	for range 8 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			f.t.Fatal("create provider authorization request")
		}
		response, err := client.Do(req)
		if err != nil {
			f.t.Fatal("provider authorization request failed")
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			next := f.redirect(response, current)
			_ = response.Body.Close()
			if next.Path == "/callback" {
				code, state := next.Query().Get("code"), next.Query().Get("state")
				if code == "" || state == "" {
					f.t.Fatal("provider callback missing code or state")
				}
				return code, state
			}
			current = next
			continue
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			f.t.Fatal("provider authorization returned unexpected status")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
		_ = response.Body.Close()
		if readErr != nil || len(body) > 1<<20 {
			f.t.Fatal("provider login form is unavailable")
		}
		action, values, ok := keycloakForm(body)
		if !ok {
			f.t.Fatal("provider login form is invalid")
		}
		formURL, err := current.Parse(action)
		if err != nil || !f.sameOrigin(formURL) {
			f.t.Fatal("provider login form action is invalid")
		}
		values.Set("username", email)
		values.Set("password", f.users[email])
		post, err := http.NewRequestWithContext(ctx, http.MethodPost, formURL.String(), strings.NewReader(values.Encode()))
		if err != nil {
			f.t.Fatal("create provider login submission")
		}
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err = client.Do(post)
		if err != nil {
			f.t.Fatal("provider login submission failed")
		}
		if response.StatusCode < 300 || response.StatusCode >= 400 {
			_ = response.Body.Close()
			f.t.Fatal("provider login was rejected")
		}
		next := f.redirect(response, formURL)
		_ = response.Body.Close()
		if next.Path == "/callback" {
			code, state := next.Query().Get("code"), next.Query().Get("state")
			if code == "" || state == "" {
				f.t.Fatal("provider callback missing code or state")
			}
			return code, state
		}
		current = next
	}
	f.t.Fatal("provider authorization did not reach callback")
	return "", ""
}

func (f *keycloakFixture) redirect(response *http.Response, base *url.URL) *url.URL {
	location, err := response.Location()
	if err != nil {
		f.t.Fatal("provider redirect is invalid")
	}
	next := base.ResolveReference(location)
	if !f.sameOrigin(next) {
		f.t.Fatal("provider redirect leaves fixed issuer")
	}
	return next
}

func (f *keycloakFixture) sameOrigin(u *url.URL) bool {
	base, err := url.Parse(f.proxy.URL)
	return err == nil && u.User == nil && u.Scheme == base.Scheme && u.Host == base.Host
}

func (f *keycloakFixture) docker(ctx context.Context, args ...string) string {
	f.t.Helper()
	commandContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, "docker", args...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		f.t.Fatalf("Keycloak docker %s failed: %v", args[0], err)
	}
	return stdout.String()
}

func (f *keycloakFixture) dockerCleanup(args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", args...).Run(); err != nil {
		f.t.Errorf("Keycloak docker cleanup %s failed", args[0])
	}
}

func keycloakRandom(t *testing.T, bytesN int) string {
	t.Helper()
	b := make([]byte, bytesN)
	if _, err := rand.Read(b); err != nil {
		t.Fatal("generate Keycloak fixture value")
	}
	return hex.EncodeToString(b)
}

type keycloakRealm struct {
	Realm   string                `json:"realm"`
	Enabled bool                  `json:"enabled"`
	Clients []keycloakRealmClient `json:"clients"`
	Users   []keycloakRealmUser   `json:"users"`
}
type keycloakRealmClient struct {
	ClientID            string            `json:"clientId"`
	Secret              string            `json:"secret"`
	Enabled             bool              `json:"enabled"`
	Protocol            string            `json:"protocol"`
	PublicClient        bool              `json:"publicClient"`
	StandardFlowEnabled bool              `json:"standardFlowEnabled"`
	RedirectURIs        []string          `json:"redirectUris"`
	WebOrigins          []string          `json:"webOrigins"`
	Attributes          map[string]string `json:"attributes"`
}
type keycloakRealmUser struct {
	Username      string                    `json:"username"`
	Email         string                    `json:"email"`
	FirstName     string                    `json:"firstName"`
	LastName      string                    `json:"lastName"`
	Enabled       bool                      `json:"enabled"`
	EmailVerified bool                      `json:"emailVerified"`
	Credentials   []keycloakRealmCredential `json:"credentials"`
}
type keycloakRealmCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

func keycloakForm(body []byte) (string, url.Values, bool) {
	node, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return "", nil, false
	}
	var form *html.Node
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if form != nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "form" && htmlAttr(n, "id") == "kc-form-login" {
			form = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(node)
	if form == nil || htmlAttr(form, "action") == "" {
		return "", nil, false
	}
	values := make(url.Values)
	var inputs func(*html.Node)
	inputs = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			if name := htmlAttr(n, "name"); name != "" {
				values.Set(name, htmlAttr(n, "value"))
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			inputs(c)
		}
	}
	inputs(form)
	return htmlAttr(form, "action"), values, true
}

func htmlAttr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}
