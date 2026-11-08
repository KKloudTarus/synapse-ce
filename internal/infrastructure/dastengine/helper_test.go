//go:build !windows

package dastengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/dastchecks"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const dastHelperTestProcess = "SYNAPSE_DAST_HELPER_TEST_PROCESS"

func TestRunHelperProcess(t *testing.T) {
	if os.Getenv(dastHelperTestProcess) != "1" {
		return
	}
	if err := RunHelper(context.Background(), os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Exit before the testing package writes its own PASS output to stdout; the
	// parent expects stdout to contain only the helper's JSON result.
	os.Exit(0)
}

func TestRunHelperAuthSchemesAndSecretFreeProof(t *testing.T) {
	const secret = "plain-secret-must-not-leak"
	for _, scheme := range []dastsession.Scheme{dastsession.SchemeForm, dastsession.SchemeBasic, dastsession.SchemeBearer, dastsession.SchemeHeader, dastsession.SchemeCookie} {
		t.Run(string(scheme), func(t *testing.T) {
			var mu sync.Mutex
			var requests []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests = append(requests, r.URL.Path)
				mu.Unlock()
				ok := false
				switch scheme {
				case dastsession.SchemeForm:
					if r.URL.Path == "/login" {
						ok = r.FormValue("credential") == secret
					} else {
						cookie, err := r.Cookie("session")
						ok = err == nil && cookie.Value == "s"
					}
				case dastsession.SchemeBasic:
					user, password, present := r.BasicAuth()
					ok = present && user == secret && password == "second"
				case dastsession.SchemeBearer:
					ok = r.Header.Get("Authorization") == "Bearer "+secret
				case dastsession.SchemeHeader:
					ok = r.Header.Get("credential") == secret
				case dastsession.SchemeCookie:
					cookie, err := r.Cookie("credential")
					ok = err == nil && cookie.Value == secret
				}
				if !ok {
					http.Error(w, "bad auth "+secret, http.StatusUnauthorized)
					return
				}
				if r.URL.Path == "/login" {
					http.SetCookie(w, &http.Cookie{Name: "session", Value: "s"})
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("live " + secret))
			}))
			defer server.Close()
			bindings := []dastsession.CredentialBinding{{Name: "credential", Reference: "first"}}
			if scheme == dastsession.SchemeBasic {
				bindings = append(bindings, dastsession.CredentialBinding{Name: "password", Reference: "second"})
			}
			plan := ports.DASTPlan{Target: server.URL, Session: dastsession.Config{Scheme: scheme, Credentials: bindings, LoginRequest: dastsession.Request{Method: "POST", Path: "/login"}, CheckRequest: dastsession.Request{Method: "GET", Path: "/live"}, Success: dastsession.SuccessSignal{StatusCode: 200, BodyContains: "live"}, MaxReauth: 1}, Requests: []dastsurface.Request{{Method: "GET", URL: server.URL + "/profile?view=summary"}}}
			outcome, raw := runHelper(t, plan, map[string]string{"credential": secret, "password": "second"}, func(ports.DASTRequest) bool { return true })
			if outcome.Incomplete || len(outcome.Observations) != 1 {
				t.Fatalf("outcome = %#v, raw=%s", outcome, raw)
			}
			if strings.Contains(raw, secret) || strings.Contains(outcome.Observations[0].URL, secret) {
				t.Fatalf("secret leaked in output: %s", raw)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(requests) < 3 {
				t.Fatalf("requests=%v, want login/liveness/probe", requests)
			}
		})
	}
}

func TestRunHelperWrongCredentialsAndReauthExhaustion(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"wrong credentials": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad plain-secret-must-not-leak", http.StatusUnauthorized)
		},
		"reauth exhausted": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/login" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("live"))
				return
			}
			http.Error(w, "dead", http.StatusUnauthorized)
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			plan := func() ports.DASTPlan {
				p := testPlan(server.URL, dastsession.SchemeBearer)
				p.Session.Success = dastsession.SuccessSignal{StatusCode: 200}
				return p
			}()
			outcome, raw := runHelper(t, plan, map[string]string{"credential": "plain-secret-must-not-leak"}, func(ports.DASTRequest) bool { return true })
			if !outcome.Incomplete || strings.Contains(raw, "plain-secret-must-not-leak") {
				t.Fatalf("outcome=%#v raw=%s", outcome, raw)
			}
		})
	}
}

func TestRunHelperAvoidsLogoutAndSeparatelyAuthorizesRedirect(t *testing.T) {
	var mu sync.Mutex
	var logoutCalls, redirectCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		switch r.URL.Path {
		case "/logout":
			logoutCalls++
		case "/go":
			redirectCalls++
		}
		mu.Unlock()
		if r.URL.Path == "/go" {
			w.Header().Set("Location", "/other")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	plan := testPlan(server.URL, dastsession.SchemeBearer)
	plan.Requests = []dastsurface.Request{{Method: "GET", URL: server.URL + "/logout"}, {Method: "GET", URL: server.URL + "/go"}}
	outcome, _ := runHelper(t, plan, map[string]string{"credential": "x"}, func(request ports.DASTRequest) bool { return !strings.HasSuffix(request.URL, "/other") })
	mu.Lock()
	defer mu.Unlock()
	if logoutCalls != 0 || redirectCalls != 1 || !outcome.Incomplete || outcome.Reason != "request_not_authorized" {
		t.Fatalf("logout=%d redirects=%d outcome=%#v", logoutCalls, redirectCalls, outcome)
	}
}

func TestRunHelperRateLimit(t *testing.T) {
	var mu sync.Mutex
	var starts []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	plan := testPlan(server.URL, dastsession.SchemeBearer)
	plan.Requests = []dastsurface.Request{{Method: "GET", URL: server.URL + "/one"}, {Method: "GET", URL: server.URL + "/two"}, {Method: "GET", URL: server.URL + "/three"}}
	outcome, _ := runHelper(t, plan, map[string]string{"credential": "x"}, func(ports.DASTRequest) bool { return true })
	if outcome.Incomplete || len(outcome.Observations) != 3 {
		t.Fatalf("outcome=%#v", outcome)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(starts) < 7 || starts[len(starts)-1].Sub(starts[0]) < 350*time.Millisecond {
		t.Fatalf("rate was not bounded: %v", starts)
	}
}

func TestRunHelperCrawlWallClockCancelsBlockedIO(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	plan := testPlan(server.URL, dastsession.SchemeBearer)
	plan.Requests = nil
	plan.Crawl = &ports.DASTCrawlPlan{Target: server.URL, Seeds: []dastsurface.Request{{Method: "GET", URL: server.URL + "/slow"}}, Depth: 4, Pages: 10, Requests: 20, WallClock: time.Second}
	started := time.Now()
	outcome, _ := runHelper(t, plan, map[string]string{"credential": "token"}, func(ports.DASTRequest) bool { return true })
	if !outcome.Incomplete || outcome.Reason != "wall_clock" || time.Since(started) > 5*time.Second {
		t.Fatalf("elapsed=%s outcome=%+v", time.Since(started), outcome)
	}
}

func TestRunHelperCrawlKeepsOneAuthenticatedSession(t *testing.T) {
	var mu sync.Mutex
	loginCalls := 0
	requests := map[string]int{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/login":
			mu.Lock()
			loginCalls++
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "derived-session", Path: "/"})
			_, _ = w.Write([]byte("live"))
		case "/live":
			if cookie, err := r.Cookie("session"); err != nil || cookie.Value != "derived-session" {
				http.Error(w, "lost", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("live"))
		case "/one":
			_, _ = w.Write([]byte(`<a href="/two">next</a>`))
		case "/two":
			_, _ = w.Write([]byte("done"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	plan := testPlan(server.URL, dastsession.SchemeBearer)
	plan.Requests = nil
	plan.Crawl = &ports.DASTCrawlPlan{Target: server.URL, Seeds: []dastsurface.Request{{Method: "GET", URL: server.URL + "/one"}}, Depth: 4, Pages: 10, Requests: 20, WallClock: 3 * time.Second}
	outcome, raw := runHelper(t, plan, map[string]string{"credential": "token"}, func(ports.DASTRequest) bool { return true })
	if outcome.Incomplete || len(outcome.Observations) != 2 || len(outcome.Surface.Requests) != 2 {
		t.Fatalf("outcome=%+v", outcome)
	}
	mu.Lock()
	defer mu.Unlock()
	if loginCalls != 1 || requests["/one"] != 1 || requests["/two"] != 1 {
		t.Fatalf("login=%d requests=%v", loginCalls, requests)
	}
	if strings.Contains(raw, "derived-session") {
		t.Fatalf("crawl output leaked derived session: %s", raw)
	}
}

func TestRunHelperCrawlSharesBoundedReauthentication(t *testing.T) {
	var mu sync.Mutex
	loginCalls, generation, liveCalls := 0, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/login":
			loginCalls++
			generation++
			http.SetCookie(w, &http.Cookie{Name: "session", Value: strconv.Itoa(generation), Path: "/"})
			_, _ = w.Write([]byte("live"))
		case "/live":
			liveCalls++
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != strconv.Itoa(generation) || generation == 1 && liveCalls > 1 {
				http.Error(w, "expired", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("live"))
		case "/one":
			_, _ = w.Write([]byte(`<a href="/two">next</a>`))
		case "/two":
			_, _ = w.Write([]byte("done"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	plan := testPlan(server.URL, dastsession.SchemeBearer)
	plan.Session.MaxReauth = 2
	plan.Requests = nil
	plan.Crawl = &ports.DASTCrawlPlan{Target: server.URL, Seeds: []dastsurface.Request{{Method: "GET", URL: server.URL + "/one"}}, Depth: 4, Pages: 10, Requests: 20, WallClock: 3 * time.Second}
	outcome, _ := runHelper(t, plan, map[string]string{"credential": "token"}, func(ports.DASTRequest) bool { return true })
	mu.Lock()
	defer mu.Unlock()
	if outcome.Incomplete || len(outcome.Observations) != 2 || loginCalls != 2 || liveCalls < 3 {
		t.Fatalf("outcome=%+v login_calls=%d live_calls=%d", outcome, loginCalls, liveCalls)
	}
}

func TestRunHelperCrawlReportsDeniedPathsAsSkipped(t *testing.T) {
	var mu sync.Mutex
	logoutCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logout" {
			mu.Lock()
			logoutCalls++
			mu.Unlock()
		}
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	plan := testPlan(server.URL, dastsession.SchemeBearer)
	plan.Requests = nil
	plan.Crawl = &ports.DASTCrawlPlan{Target: server.URL, Seeds: []dastsurface.Request{{Method: "GET", URL: server.URL + "/logout"}}, Depth: 4, Pages: 10, Requests: 20, WallClock: time.Second}
	outcome, _ := runHelper(t, plan, map[string]string{"credential": "token"}, func(ports.DASTRequest) bool { return true })
	mu.Lock()
	defer mu.Unlock()
	if outcome.Incomplete || logoutCalls != 0 || len(outcome.Surface.Requests) != 1 || len(outcome.Coverage.Entries) != 1 || outcome.Coverage.Entries[0].Status != dastsurface.CoverageSkipped || outcome.Coverage.Entries[0].Reason != "deny_path" {
		t.Fatalf("logout_calls=%d outcome=%+v", logoutCalls, outcome)
	}
}

func testPlan(target string, scheme dastsession.Scheme) ports.DASTPlan {
	return ports.DASTPlan{Target: target, Session: dastsession.Config{Scheme: scheme, Credentials: []dastsession.CredentialBinding{{Name: "credential", Reference: "credential"}}, LoginRequest: dastsession.Request{Method: "POST", Path: "/login"}, CheckRequest: dastsession.Request{Method: "GET", Path: "/live"}, Success: dastsession.SuccessSignal{StatusCode: 200, BodyContains: "live"}, MaxReauth: 1}, Requests: []dastsurface.Request{{Method: "GET", URL: target + "/one"}}}
}

func runHelper(t *testing.T, plan ports.DASTPlan, credentials map[string]string, allow func(ports.DASTRequest) bool) (ports.DASTOutcome, string) {
	t.Helper()
	input, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	requestR, requestW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	decisionR, decisionW, err := os.Pipe()
	if err != nil {
		_ = requestR.Close()
		_ = requestW.Close()
		t.Fatal(err)
	}
	dummy, err := os.Open(os.DevNull)
	if err != nil {
		_ = requestR.Close()
		_ = requestW.Close()
		_ = decisionR.Close()
		_ = decisionW.Close()
		t.Fatal(err)
	}
	defer func() {
		_ = dummy.Close()
		_ = requestR.Close()
		_ = requestW.Close()
		_ = decisionR.Close()
		_ = decisionW.Close()
	}()

	authDone := make(chan error, 1)
	go func() {
		defer func() { _ = decisionW.Close() }()
		decoder, encoder := json.NewDecoder(requestR), json.NewEncoder(decisionW)
		for {
			var request ports.DASTRequest
			if err := decoder.Decode(&request); err != nil {
				if errors.Is(err, io.EOF) {
					authDone <- nil
				} else {
					authDone <- err
				}
				return
			}
			if err := encoder.Encode(ports.DASTAuthorization{Allowed: allow(request)}); err != nil {
				authDone <- err
				return
			}
		}
	}()

	cmd := exec.Command(os.Args[0], "-test.run=^TestRunHelperProcess$")
	cmd.Env = append(os.Environ(),
		dastHelperTestProcess+"=1",
		"SYNAPSE_DAST_AUTH_REQUEST_FD=4",
		"SYNAPSE_DAST_AUTH_DECISION_FD=5",
	)
	for name, value := range credentials {
		cmd.Env = append(cmd.Env, secretEnvName(name)+"="+value)
	}
	cmd.Stdin = bytes.NewReader(input)
	var output, stderr bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &stderr
	// Match production's descriptor layout: the sandbox owns fd 3, then the
	// authorization request and decision channels arrive as fd 4 and fd 5.
	cmd.ExtraFiles = []*os.File{dummy, requestW, decisionR}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// The child owns its duplicated copies now. Closing the parent copies is what
	// lets the authorization goroutine observe EOF when the helper exits.
	_ = dummy.Close()
	_ = requestW.Close()
	_ = decisionR.Close()
	waitErr := cmd.Wait()
	authErr := <-authDone
	if waitErr != nil {
		t.Fatalf("RunHelper subprocess: %v: %s", waitErr, stderr.String())
	}
	if authErr != nil {
		t.Fatalf("DAST authorization harness: %v", authErr)
	}
	var outcome ports.DASTOutcome
	if err := json.Unmarshal(output.Bytes(), &outcome); err != nil {
		t.Fatalf("decode helper output: %v: %s", err, output.String())
	}
	return outcome, output.String()
}

func TestRunHelperRedactsResponseSecretsAndDerivedCookies(t *testing.T) {
	const secret = "raw-vault-secret"
	const derived = "derived-session-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: derived})
		}
		w.Header().Set("Location", "/next?access_token="+secret)
		w.Header().Set("X-Api-Key", secret)
		w.Header().Add("Set-Cookie", "id=x; Secure; Debug-Token="+secret)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("live token=" + secret + " cookie=" + derived + " authorization: Bearer " + secret))
	}))
	defer server.Close()
	outcome, raw := runHelper(t, testPlan(server.URL, dastsession.SchemeBearer), map[string]string{"credential": secret}, func(ports.DASTRequest) bool { return true })
	if outcome.Incomplete || len(outcome.Observations) != 1 || strings.Contains(raw, secret) || strings.Contains(raw, derived) || strings.Contains(outcome.Observations[0].BodyExcerpt, secret) || strings.Contains(outcome.Observations[0].BodyExcerpt, derived) {
		t.Fatalf("secret leaked: %#v raw=%s", outcome, raw)
	}
}

func TestRunHelperRedactsIssuedCookiesAcrossCrawlAndReauthentication(t *testing.T) {
	const loginSecret = "issued-login<+/token"
	const liveSecret = "issued-live-secret"
	const laterSecret = "issued-later-secret"
	const rotatedSecret = "issued-rotated-secret"
	var mu sync.Mutex
	var login, live int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/login":
			login++
			value := loginSecret
			if login > 1 {
				value = rotatedSecret
			}
			http.SetCookie(w, &http.Cookie{Name: "auth", Value: value, Path: "/"})
			_, _ = w.Write([]byte("live"))
		case "/live":
			live++
			if live == 2 {
				http.Error(w, "expired", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "live", Value: liveSecret, Path: "/"})
			_, _ = w.Write([]byte("live"))
		case "/one":
			encoded, _ := json.Marshal(loginSecret)
			_, _ = fmt.Fprintf(w, `<a href="/two">next</a> {"session":"unissued-session-value","token":"unissued-token-value","echo":%s,"escaped":%s} %s %s %s %s`, encoded, strings.ReplaceAll(string(encoded), "/", `\/`), loginSecret, url.QueryEscape(loginSecret), laterSecret, rotatedSecret)
		case "/two":
			http.SetCookie(w, &http.Cookie{Name: "later", Value: laterSecret, Path: "/"})
			_, _ = fmt.Fprintf(w, `{"echo":"%s","marker":"synapse-auth-weakness","sources":["app.js"]}`, laterSecret)
		}
	}))
	defer server.Close()
	plan := testPlan(server.URL, dastsession.SchemeBearer)
	plan.Requests = nil
	plan.Crawl = &ports.DASTCrawlPlan{Target: server.URL, Seeds: []dastsurface.Request{{Method: "GET", URL: server.URL + "/one"}}, Depth: 4, Pages: 10, Requests: 20, WallClock: 10 * time.Second}
	outcome, raw := runHelper(t, plan, map[string]string{"credential": "vault-credential-value"}, func(ports.DASTRequest) bool { return true })
	mu.Lock()
	defer mu.Unlock()
	if outcome.Incomplete || len(outcome.Observations) != 2 || login != 2 || live < 3 {
		t.Fatalf("unexpected crawl result: %+v login=%d live=%d", outcome, login, live)
	}
	for _, secret := range []string{loginSecret, url.QueryEscape(loginSecret), `issued-login\u003c+/token`, liveSecret, laterSecret, rotatedSecret, "unissued-session-value", "unissued-token-value"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("serialized outcome contains a credential form")
		}
	}
	if strings.Contains(outcome.Observations[0].BodyExcerpt, "issued-login") {
		t.Fatal("JSON-escaped cookie remains in the excerpt")
	}
	if !strings.Contains(outcome.Observations[1].BodyExcerpt, "synapse-auth-weakness") || !strings.Contains(outcome.Observations[1].BodyExcerpt, `"sources"`) || !outcome.Observations[1].HeadersCaptured {
		t.Fatalf("passive evidence was lost: %+v", outcome.Observations[1])
	}
}

func TestRunHelperCookieTrackingBudgetFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/one" {
			for i := range maxTrackedCookies + 1 {
				http.SetCookie(w, &http.Cookie{Name: fmt.Sprintf("cookie%d", i), Value: fmt.Sprintf("issued-secret-%d", i), Path: "/"})
			}
		}
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	outcome, raw := runHelper(t, testPlan(server.URL, dastsession.SchemeBearer), map[string]string{"credential": "vault-credential-value"}, func(ports.DASTRequest) bool { return true })
	if !outcome.Incomplete || outcome.Reason != "secret_tracking_limit" || len(outcome.Observations) != 0 || strings.Contains(raw, "issued-secret-") {
		t.Fatalf("tracking exhaustion did not fail closed: %+v", outcome)
	}
}

func TestRunHelperKeepsRawDigestAndEvidenceWithShortCookie(t *testing.T) {
	const body = `{"echo":"x","sources":["app.js"],"marker":"synapse-auth-weakness"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/one" {
			http.SetCookie(w, &http.Cookie{Name: "id", Value: "x", Path: "/"})
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	outcome, _ := runHelper(t, testPlan(server.URL, dastsession.SchemeBearer), map[string]string{"credential": "vault-credential-value"}, func(ports.DASTRequest) bool { return true })
	hash := sha256.Sum256([]byte(body))
	if outcome.Incomplete || len(outcome.Observations) != 1 {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	observation := outcome.Observations[0]
	if observation.BodySHA256 != hex.EncodeToString(hash[:]) || observation.BodyBytes != len(body) || !observation.HeadersCaptured || strings.Contains(observation.BodyExcerpt, `"x"`) || !strings.Contains(observation.BodyExcerpt, `"sources"`) || !strings.Contains(observation.BodyExcerpt, "synapse-auth-weakness") {
		t.Fatalf("digest, redaction or passive evidence incorrect: %+v", observation)
	}
}

func TestRunHelperShortCookieKeepsEvidenceAndOrdinaryURLs(t *testing.T) {
	// "on" occurs inside the /one path and "s" inside JSON keys; neither is a reflection of the value.
	const body = `{"version":3,"sources":["app.js"],"mappings":"AAAA","marker":"synapse-auth-weakness","flag":"on","mode":"s"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/one" {
			http.SetCookie(w, &http.Cookie{Name: "lang", Value: "on", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "theme", Value: "s", Path: "/"})
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	outcome, _ := runHelper(t, testPlan(server.URL, dastsession.SchemeBearer), map[string]string{"credential": "vault-credential-value"}, func(ports.DASTRequest) bool { return true })
	if outcome.Incomplete || len(outcome.Observations) != 1 {
		t.Fatalf("short cookie failed an ordinary URL closed: %+v", outcome)
	}
	observation := outcome.Observations[0]
	hash := sha256.Sum256([]byte(body))
	for _, kept := range []string{`"version":3`, `"sources":["app.js"]`, `"mappings":"AAAA"`, "synapse-auth-weakness", `"flag":"[REDACTED]"`, `"mode":"[REDACTED]"`} {
		if !strings.Contains(observation.BodyExcerpt, kept) {
			t.Fatalf("excerpt lacks %q: %q", kept, observation.BodyExcerpt)
		}
	}
	if observation.BodySHA256 != hex.EncodeToString(hash[:]) || observation.BodyBytes != len(body) {
		t.Fatalf("raw body digest changed: %+v", observation)
	}
}

func TestRunHelperCookieTrackingAcceptsExactBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/one" {
			for i := range maxTrackedCookies {
				http.SetCookie(w, &http.Cookie{Name: fmt.Sprintf("cookie%d", i), Value: fmt.Sprintf("issued-secret-%d", i), Path: "/"})
			}
			_, _ = w.Write([]byte(`{"sources":["app.js"]}`))
			return
		}
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	outcome, raw := runHelper(t, testPlan(server.URL, dastsession.SchemeBearer), map[string]string{"credential": "vault-credential-value"}, func(ports.DASTRequest) bool { return true })
	if outcome.Incomplete || len(outcome.Observations) != 1 || strings.Contains(raw, "issued-secret-") || !strings.Contains(outcome.Observations[0].BodyExcerpt, `"sources"`) {
		t.Fatalf("exact tracking budget was not usable: %+v", outcome)
	}
}

func TestRunHelperCookieByteBudgetAndMalformedCookies(t *testing.T) {
	for name, tc := range map[string]struct {
		header     string
		incomplete bool
	}{
		"exact byte budget":     {header: "big=" + strings.Repeat("a", maxTrackedCookieBytes) + "; Path=/"},
		"one byte over budget":  {header: "big=" + strings.Repeat("a", maxTrackedCookieBytes+1) + "; Path=/", incomplete: true},
		"malformed cookie name": {header: "bad name=issued-malformed-value; Path=/", incomplete: true},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/one" {
					w.Header().Add("Set-Cookie", tc.header)
					_, _ = w.Write([]byte(`{"sources":["app.js"]}`))
					return
				}
				_, _ = w.Write([]byte("live"))
			}))
			defer server.Close()
			outcome, raw := runHelper(t, testPlan(server.URL, dastsession.SchemeBearer), map[string]string{"credential": "vault-credential-value"}, func(ports.DASTRequest) bool { return true })
			if tc.incomplete {
				if !outcome.Incomplete || outcome.Reason != "secret_tracking_limit" || len(outcome.Observations) != 0 || strings.Contains(raw, "aaaaaaaa") || strings.Contains(raw, "issued-malformed-value") {
					t.Fatalf("cookie tracking did not fail closed: %+v", outcome)
				}
				return
			}
			if outcome.Incomplete || len(outcome.Observations) != 1 || !strings.Contains(outcome.Observations[0].BodyExcerpt, `"sources"`) {
				t.Fatalf("exact byte budget was not usable: %+v", outcome)
			}
		})
	}
}

func TestRunHelperShortCookieAsURLTokenFailsClosed(t *testing.T) {
	var mu sync.Mutex
	var authorized int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/one" {
			http.SetCookie(w, &http.Cookie{Name: "remember", Value: "1", Path: "/"})
			// Crawl normalization drops query values, so the path is what would carry the value.
			_, _ = w.Write([]byte(`<a href="/orders/1">next</a>`))
			return
		}
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	plan := testPlan(server.URL, dastsession.SchemeBearer)
	plan.Requests = nil
	plan.Crawl = &ports.DASTCrawlPlan{Target: server.URL, Seeds: []dastsurface.Request{{Method: "GET", URL: server.URL + "/one"}}, Depth: 4, Pages: 10, Requests: 20, WallClock: 10 * time.Second}
	outcome, _ := runHelper(t, plan, map[string]string{"credential": "vault-credential-value"}, func(request ports.DASTRequest) bool {
		if strings.Contains(request.URL, "/orders") {
			mu.Lock()
			authorized++
			mu.Unlock()
		}
		return true
	})
	mu.Lock()
	defer mu.Unlock()
	if authorized != 0 || !outcome.Incomplete || outcome.Reason != "secret_tracking_limit" || len(outcome.Observations) != 0 {
		t.Fatalf("whole-token short value in a URL did not fail closed: authorized=%d outcome=%+v", authorized, outcome)
	}
}

func TestRunHelperRedactsPartiallyEscapedReflections(t *testing.T) {
	for _, source := range []string{"operator", "issued-cookie"} {
		t.Run(source, func(t *testing.T) {
			secret := "operator-audit-secret"
			if source == "issued-cookie" {
				secret = "issued-audit-cookie"
			}
			// Each reflection escapes only the first byte, which no literal escape form matches.
			lower, upper := "%"+fmt.Sprintf("%02x", secret[0])+secret[1:], "%"+fmt.Sprintf("%02X", secret[0])+secret[1:]
			// Five nested escape layers exceed the decoding bound and must fail closed too.
			nested := lower
			for range 4 {
				nested = strings.ReplaceAll(nested, "%", "%25")
			}
			body := `<a href="/echo#` + lower + `">next</a> <a href="/echo?` + lower + `=1">query</a> /echo/` + upper +
				` /echo/` + strings.ReplaceAll(lower, "%", "%25") + ` /echo/` + nested +
				` {"sources":["app.js"],"marker":"synapse-auth-weakness"}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/login":
					if source == "issued-cookie" {
						http.SetCookie(w, &http.Cookie{Name: "session", Value: secret, Path: "/"})
					}
				case "/one":
					_, _ = w.Write([]byte(body))
					return
				}
				_, _ = w.Write([]byte("live"))
			}))
			defer server.Close()
			outcome, raw := runHelper(t, testPlan(server.URL, dastsession.SchemeBearer), map[string]string{"credential": "operator-audit-secret"}, func(ports.DASTRequest) bool { return true })
			if outcome.Incomplete || len(outcome.Observations) != 1 {
				t.Fatalf("unexpected outcome: %+v", outcome)
			}
			excerpt := outcome.Observations[0].BodyExcerpt
			if strings.Contains(raw, secret[1:]) {
				t.Fatal("a partially escaped credential survived in the serialized outcome")
			}
			for _, kept := range []string{"next", "query", `"sources":["app.js"]`, "synapse-auth-weakness"} {
				if !strings.Contains(excerpt, kept) {
					t.Fatalf("redaction erased nonsecret evidence %q: %q", kept, excerpt)
				}
			}
			hash := sha256.Sum256([]byte(body))
			if outcome.Observations[0].BodySHA256 != hex.EncodeToString(hash[:]) {
				t.Fatal("raw body digest changed")
			}
		})
	}
}

func TestRunHelperRedactsComposedEscapes(t *testing.T) {
	for name, tc := range map[string]struct {
		secret, body string
		withheld     bool
	}{
		"html decimal reference":        {secret: "operator-audit-secret", body: `<a href="/echo#&#111;perator-audit-secret">next</a> {"sources":["app.js"]}`},
		"html hex reference":            {secret: "operator-audit-secret", body: `<a href="/echo#&#x6F;perator-audit-secret">next</a> {"sources":["app.js"]}`},
		"json then percent":             {secret: "operator-audit-secret", body: `{"echo":"/echo#%6fperator-audit-\u0073ecret","sources":["app.js"]} next`},
		"mixed query spaces":            {secret: "operator audit secret", body: `{"echo":"/echo#%6fperator+audit secret","sources":["app.js"]} next`},
		"mixed spaces without percent":  {secret: "operator audit secret", body: `{"echo":"/echo#operator+audit secret","sources":["app.js"]} next`},
		"literal percent in credential": {secret: "operator%41-audit-secret", body: `<a href="/echo#&#111;perator%41-audit-secret">next</a> {"sources":["app.js"]}`},
		"javascript hex escape":         {secret: "operator-audit-secret", body: `<script>var u = '/echo#\x6fperator-audit-secret';</script> next {"sources":["app.js"]}`},
		// The escape splits the value across tokens, so no span can be located.
		"split across tokens": {secret: "operator audit secret", body: `<p>operator&#32;audit secret</p> next {"sources":["app.js"]}`, withheld: true},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/one" {
					_, _ = w.Write([]byte(tc.body))
					return
				}
				_, _ = w.Write([]byte("live"))
			}))
			defer server.Close()
			outcome, raw := runHelper(t, testPlan(server.URL, dastsession.SchemeBearer), map[string]string{"credential": tc.secret}, func(ports.DASTRequest) bool { return true })
			if tc.withheld {
				if !outcome.Incomplete || outcome.Reason != "secret_tracking_limit" || len(outcome.Observations) != 0 || strings.Contains(raw, "audit") {
					t.Fatal("unlocatable reflection did not refuse the unsafe outcome")
				}
				return
			}
			if outcome.Incomplete || len(outcome.Observations) != 1 {
				t.Fatalf("unexpected outcome: %+v", outcome)
			}
			observation := outcome.Observations[0]
			// Every fixture secret contains "audit" and no nonsecret evidence does, so any
			// surviving fragment of an escaped reflection is visible here.
			if strings.Contains(raw, "audit") {
				t.Fatal("an escaped credential survived in the serialized outcome")
			}
			hash := sha256.Sum256([]byte(tc.body))
			if observation.BodySHA256 != hex.EncodeToString(hash[:]) || observation.BodyBytes != len(tc.body) {
				t.Fatal("raw body digest changed")
			}
			for _, kept := range []string{"next", `"sources":["app.js"]`} {
				if !strings.Contains(observation.BodyExcerpt, kept) {
					t.Fatalf("redaction erased nonsecret evidence %q: %q", kept, observation.BodyExcerpt)
				}
			}
		})
	}
}

func TestRunHelperFailsClosedWhenLaterCookieAppearsInPriorURL(t *testing.T) {
	const secret = "issued-later-url-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/two" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: secret, Path: "/"})
		}
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	plan := testPlan(server.URL, dastsession.SchemeBearer)
	plan.Requests = []dastsurface.Request{{Method: "GET", URL: server.URL + "/" + secret}, {Method: "GET", URL: server.URL + "/two"}}
	outcome, raw := runHelper(t, plan, map[string]string{"credential": "vault-credential-value"}, func(ports.DASTRequest) bool { return true })
	if !outcome.Incomplete || len(outcome.Observations) != 0 || strings.Contains(raw, secret) {
		t.Fatalf("unsafe observation was retained: %+v", outcome)
	}
}

func TestRunHelperRedactsLaterCookiePrefixAtExcerptBoundary(t *testing.T) {
	const secret = "later-cookie-value"
	prefix := secret[:8]
	body := strings.Repeat("a", maxProofBodyBytes-len(prefix)) + secret
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/one":
			_, _ = w.Write([]byte(body))
		case "/two":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: secret, Path: "/"})
			_, _ = w.Write([]byte("live"))
		default:
			_, _ = w.Write([]byte("live"))
		}
	}))
	defer server.Close()
	plan := testPlan(server.URL, dastsession.SchemeBearer)
	plan.Requests = append(plan.Requests, dastsurface.Request{Method: "GET", URL: server.URL + "/two"})
	outcome, _ := runHelper(t, plan, map[string]string{"credential": "vault-credential-value"}, func(ports.DASTRequest) bool { return true })
	if outcome.Incomplete || len(outcome.Observations) != 2 || !outcome.Observations[0].BodyTruncated || strings.Contains(outcome.Observations[0].BodyExcerpt, prefix) {
		t.Fatalf("truncated secret prefix was retained: %+v", outcome)
	}
}

func TestRunHelperRedactionDoesNotAmplifyMarkerOverlappingCookie(t *testing.T) {
	// Both issued values occur inside the redaction marker; each reflection is replaced exactly once.
	body := `<script type="application/json">{"sources":["app.js"],"marker":"synapse-auth-weakness"}</script><pre>` + strings.Repeat("D ", 48) + `REDACTED REDACTED</pre>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/one" {
			http.SetCookie(w, &http.Cookie{Name: "id", Value: "D", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "rid", Value: "REDACTED", Path: "/"})
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	outcome, raw := runHelper(t, testPlan(server.URL, dastsession.SchemeBearer), map[string]string{"credential": "vault-credential-value"}, func(ports.DASTRequest) bool { return true })
	if outcome.Incomplete || len(outcome.Observations) != 1 {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	excerpt := outcome.Observations[0].BodyExcerpt
	hash := sha256.Sum256([]byte(body))
	if len(raw) > 4096 || len(excerpt) > 1024 || strings.Count(excerpt, "[REDACTED]") != 50 ||
		!strings.Contains(excerpt, `"sources":["app.js"]`) || !strings.Contains(excerpt, "synapse-auth-weakness") ||
		outcome.Observations[0].BodySHA256 != hex.EncodeToString(hash[:]) || outcome.Observations[0].BodyBytes != len(body) {
		t.Fatalf("unbounded or unsafe redaction: excerpt=%q output bytes=%d", excerpt, len(raw))
	}
}

func TestRunHelperRejectsSecretURLsBeforeAuthorization(t *testing.T) {
	for _, source := range []string{"operator", "issued-cookie"} {
		for _, carrier := range []string{"link", "redirect"} {
			placements := []string{"path", "query", "escaped-path", "escaped-query-key", "double-escaped-path", "double-escaped-query-key", "nested-escape-path", "entity-path", "js-escape-path"}
			if carrier == "redirect" {
				placements = append(placements, "fragment")
			}
			for _, placement := range placements {
				t.Run(source+"/"+carrier+"/"+placement, func(t *testing.T) {
					const credential = "operator-audit-secret"
					secret := credential
					if source == "issued-cookie" {
						secret = "issued-audit-cookie"
					}
					// Partial escaping of the first byte survives the literal form matchers;
					// escaping that percent again, or nesting past the decoding bound, must not hide it.
					escaped := fmt.Sprintf("%%%02x", secret[0]) + secret[1:]
					doubled := strings.ReplaceAll(escaped, "%", "%25")
					nested := escaped
					for range 4 {
						nested = strings.ReplaceAll(nested, "%", "%25")
					}
					target := "/echo"
					switch placement {
					case "path":
						target += "/" + url.PathEscape(secret)
					case "query":
						target += "?value=" + url.QueryEscape(secret)
					case "escaped-path":
						target += "/" + escaped
					case "escaped-query-key":
						target += "?" + escaped + "=1"
					case "double-escaped-path":
						target += "/" + doubled
					case "double-escaped-query-key":
						target += "?" + doubled + "=1"
					case "nested-escape-path":
						target += "/" + nested
					case "entity-path":
						target += "/%26%23" + strconv.Itoa(int(secret[0])) + "%3B" + secret[1:]
					case "js-escape-path":
						target += fmt.Sprintf("/%%5Cx%02x", secret[0]) + secret[1:]
					case "fragment":
						target += "#" + secret
					}
					var mu sync.Mutex
					var authorized, sent int
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						switch req.URL.Path {
						case "/login":
							if source == "issued-cookie" {
								http.SetCookie(w, &http.Cookie{Name: "session", Value: secret, Path: "/"})
							}
						case "/one":
							if carrier == "redirect" {
								w.Header().Set("Location", target)
								w.WriteHeader(http.StatusFound)
							} else {
								_, _ = fmt.Fprintf(w, `<a href="%s">next</a>`, target)
							}
						default:
							if strings.HasPrefix(req.URL.Path, "/echo") {
								mu.Lock()
								sent++
								mu.Unlock()
							}
						}
						_, _ = w.Write([]byte("live"))
					}))
					defer server.Close()
					plan := testPlan(server.URL, dastsession.SchemeBearer)
					plan.Requests = nil
					plan.Crawl = &ports.DASTCrawlPlan{Target: server.URL, Seeds: []dastsurface.Request{{Method: "GET", URL: server.URL + "/one"}}, Depth: 4, Pages: 10, Requests: 20, WallClock: 10 * time.Second}
					outcome, raw := runHelper(t, plan, map[string]string{"credential": credential}, func(request ports.DASTRequest) bool {
						if strings.Contains(request.URL, "/echo") {
							mu.Lock()
							authorized++
							mu.Unlock()
						}
						return true
					})
					mu.Lock()
					defer mu.Unlock()
					if authorized != 0 || sent != 0 {
						t.Fatalf("secret URL crossed the helper boundary: authorized=%d sent=%d", authorized, sent)
					}
					if !outcome.Incomplete || outcome.Reason != "secret_tracking_limit" || len(outcome.Observations) != 0 || strings.Contains(raw, secret) {
						t.Fatal("unsafe URL did not produce a secret-free incomplete outcome")
					}
				})
			}
		}
	}
}

func TestHelperRateWaitPrecedesAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name       string
		window     time.Duration
		wantDenied bool
	}{
		{"expires during rate wait", 100 * time.Millisecond, true},
		{"still authorized after rate wait", time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			start := time.Now()
			expiry := start.Add(tc.window)
			runner := helperRunner{
				client: server.Client(), last: start, interval: 250 * time.Millisecond,
				authorize: func(context.Context, ports.DASTRequest) error {
					if !time.Now().Before(expiry) {
						return errors.New("authorization expired")
					}
					return nil
				},
			}
			response, err := runner.do(context.Background(), http.MethodGet, server.URL+"/bounded", false)
			if response != nil {
				_ = response.Body.Close()
			}
			if tc.wantDenied {
				if !errors.Is(err, errAuthorizationDenied) || requests.Load() != 0 {
					t.Fatalf("expired authorization dispatched a request: err=%v requests=%d", err, requests.Load())
				}
			} else if err != nil || requests.Load() != 1 {
				t.Fatalf("valid authorization did not dispatch exactly once: err=%v requests=%d", err, requests.Load())
			}
		})
	}
}

func TestHelperCapturedArtifactAndHeaderMarkerEvidence(t *testing.T) {
	const markerValue = "private-marker-header-value"
	for _, tc := range []struct {
		name, body, header, check string
		status, want              int
	}{
		{"served source map", `{"version":3,"sources":["app.ts"],"mappings":"AAAA"}`, "", "sensitive-public-artifact", 200, 1},
		{"empty successful response", "", "", "sensitive-public-artifact", 200, 0},
		{"no content", "", "", "sensitive-public-artifact", 204, 0},
		{"reset content", "", "", "sensitive-public-artifact", 205, 0},
		{"html fallback", "<html>not an artifact</html>", "", "sensitive-public-artifact", 200, 0},
		{"header-only marker", "ordinary response", "X-Synapse-Auth-Weakness", "auth-configured-weakness", 200, 1},
		{"unrelated header suffix", "ordinary response", "X-Synapse-Auth-Weakness-Other", "auth-configured-weakness", 200, 0},
		{"no marker", "ordinary response", "", "auth-configured-weakness", 200, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.header != "" {
					w.Header().Set(tc.header, markerValue)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			runner := helperRunner{
				client:    server.Client(),
				authorize: func(context.Context, ports.DASTRequest) error { return nil },
			}
			observation, err := runner.request(context.Background(), http.MethodGet, server.URL+"/app.js.map")
			if err != nil {
				t.Fatal(err)
			}
			evaluator := dastchecks.NewEvaluator()
			findings, err := evaluator.Evaluate([]ports.DASTObservation{observation}, []string{tc.check})
			if err != nil || len(findings) != tc.want {
				t.Fatalf("selected check %s: findings=%+v want=%d err=%v", tc.check, findings, tc.want, err)
			}
			captured, err := json.Marshal(observation)
			if err != nil || bytes.Contains(captured, []byte(markerValue)) {
				t.Fatalf("header capture exposed a marker value: err=%v", err)
			}
			for _, finding := range findings {
				if finding.CheckID != tc.check || evaluator.VerifyProof(finding.Proof) != nil {
					t.Fatalf("invalid selected finding: %+v", finding)
				}
				proof, err := json.Marshal(finding.Proof)
				if err != nil || bytes.Contains(proof, []byte(markerValue)) {
					t.Fatalf("closed proof exposed a marker value: err=%v", err)
				}
			}
		})
	}
}
