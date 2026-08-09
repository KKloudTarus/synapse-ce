//go:build !windows

package dastengine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestRunHelperAuthSchemesAndSecretFreeProof(t *testing.T) {
	const secret = "plain-secret-must-not-leak"
	for _, scheme := range []dastsession.Scheme{dastsession.SchemeForm, dastsession.SchemeBasic, dastsession.SchemeBearer, dastsession.SchemeHeader, dastsession.SchemeCookie} {
		t.Run(string(scheme), func(t *testing.T) {
			var requests []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.URL.Path)
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
			plan := ports.DASTPlan{Target: server.URL, Session: dastsession.Config{Scheme: scheme, Credentials: bindings, LoginRequest: dastsession.Request{Method: "POST", Path: "/login"}, CheckRequest: dastsession.Request{Method: "GET", Path: "/live"}, Success: dastsession.SuccessSignal{StatusCode: 200, BodyContains: "live"}, MaxReauth: 1}, Requests: []dastsurface.Request{{Method: "GET", URL: server.URL + "/profile?api_key=" + secret}}}
			outcome, raw := runHelper(t, plan, map[string]string{"credential": secret, "password": "second"}, func(request ports.DASTRequest) bool {
				return !strings.Contains(request.URL, "/profile") || !strings.Contains(request.URL, secret)
			})
			if outcome.Incomplete || len(outcome.Observations) != 1 {
				t.Fatalf("outcome = %#v, raw=%s", outcome, raw)
			}
			if strings.Contains(raw, secret) || strings.Contains(outcome.Observations[0].URL, secret) {
				t.Fatalf("secret leaked in output: %s", raw)
			}
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
	var logoutCalls, redirectCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logout":
			logoutCalls++
		case "/go":
			redirectCalls++
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
	if !outcome.Incomplete || outcome.Reason != "wall_clock" || time.Since(started) > 2*time.Second {
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
	logoutCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logout" {
			logoutCalls++
		}
		_, _ = w.Write([]byte("live"))
	}))
	defer server.Close()
	plan := testPlan(server.URL, dastsession.SchemeBearer)
	plan.Requests = nil
	plan.Crawl = &ports.DASTCrawlPlan{Target: server.URL, Seeds: []dastsurface.Request{{Method: "GET", URL: server.URL + "/logout"}}, Depth: 4, Pages: 10, Requests: 20, WallClock: time.Second}
	outcome, _ := runHelper(t, plan, map[string]string{"credential": "token"}, func(ports.DASTRequest) bool { return true })
	if outcome.Incomplete || logoutCalls != 0 || len(outcome.Surface.Requests) != 1 || len(outcome.Coverage.Entries) != 1 || outcome.Coverage.Entries[0].Status != dastsurface.CoverageSkipped || outcome.Coverage.Entries[0].Reason != "deny_path" {
		t.Fatalf("logout_calls=%d outcome=%+v", logoutCalls, outcome)
	}
}

func testPlan(target string, scheme dastsession.Scheme) ports.DASTPlan {
	return ports.DASTPlan{Target: target, Session: dastsession.Config{Scheme: scheme, Credentials: []dastsession.CredentialBinding{{Name: "credential", Reference: "credential"}}, LoginRequest: dastsession.Request{Method: "POST", Path: "/login"}, CheckRequest: dastsession.Request{Method: "GET", Path: "/live"}, Success: dastsession.SuccessSignal{StatusCode: 200, BodyContains: "live"}, MaxReauth: 1}, Requests: []dastsurface.Request{{Method: "GET", URL: target + "/one"}}}
}

func runHelper(t *testing.T, plan ports.DASTPlan, credentials map[string]string, allow func(ports.DASTRequest) bool) (ports.DASTOutcome, string) {
	t.Helper()
	requestR, requestW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	decisionR, decisionW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer requestR.Close()
	defer requestW.Close()
	defer decisionR.Close()
	defer decisionW.Close()
	oldRequest, oldDecision := os.Getenv("SYNAPSE_DAST_AUTH_REQUEST_FD"), os.Getenv("SYNAPSE_DAST_AUTH_DECISION_FD")
	t.Setenv("SYNAPSE_DAST_AUTH_REQUEST_FD", strconv.Itoa(int(requestW.Fd())))
	t.Setenv("SYNAPSE_DAST_AUTH_DECISION_FD", strconv.Itoa(int(decisionR.Fd())))
	for name, value := range credentials {
		t.Setenv(secretEnvName(name), value)
	}
	defer os.Setenv("SYNAPSE_DAST_AUTH_REQUEST_FD", oldRequest)
	defer os.Setenv("SYNAPSE_DAST_AUTH_DECISION_FD", oldDecision)
	go func() {
		decoder, encoder := json.NewDecoder(requestR), json.NewEncoder(decisionW)
		for {
			var request ports.DASTRequest
			if decoder.Decode(&request) != nil {
				return
			}
			if encoder.Encode(ports.DASTAuthorization{Allowed: allow(request)}) != nil {
				return
			}
		}
	}()
	input, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := RunHelper(context.Background(), bytes.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	var outcome ports.DASTOutcome
	if err := json.Unmarshal(output.Bytes(), &outcome); err != nil {
		t.Fatal(err)
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
