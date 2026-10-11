package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identitybff"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
)

type errorContractBody struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
	Retryable *bool  `json:"retryable"`
}

func decodeErrorContract(t *testing.T, rec *httptest.ResponseRecorder) errorContractBody {
	t.Helper()
	var body errorContractBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %v (%q)", err, rec.Body.String())
	}
	if body.Error == "" || body.Code == "" || body.Retryable == nil {
		t.Fatalf("error body misses contract fields: %q", rec.Body.String())
	}
	return body
}

// outageResolver fails like an unreachable users table.
func outageResolver(context.Context, string) (Principal, error) {
	return Principal{}, fmt.Errorf("resolve bearer token: %w: connection refused", authz.ErrAuthenticationUnavailable)
}

type scriptedSession struct{ err error }

func (s scriptedSession) Authenticate(context.Context, string, string, bool) (Principal, error) {
	return Principal{}, s.err
}

func TestAuthenticationOutcomesUseTheErrorContract(t *testing.T) {
	valid := func(_ context.Context, token string) (Principal, error) {
		if token == "good" {
			return Principal{ID: "u1", Role: "readonly", TenantID: "acme"}, nil
		}
		return Principal{}, fmt.Errorf("unknown token: %w", authz.ErrCredentialInvalid)
	}
	cases := []struct {
		name      string
		resolver  Resolver
		session   SessionResolver
		bearer    string
		cookie    bool
		status    int
		code      ErrorCode
		retryable bool
	}{
		{name: "no credential", resolver: valid, status: 401, code: CodeAuthenticationRequired},
		{name: "invalid bearer", resolver: valid, bearer: "bad", status: 401, code: CodeAuthenticationInvalid},
		{name: "bearer store outage", resolver: outageResolver, bearer: "good", status: 503, code: CodeAuthenticationUnavailable, retryable: true},
		{name: "unclassified resolver failure", resolver: func(context.Context, string) (Principal, error) { return Principal{}, errors.New("boom") }, bearer: "good", status: 503, code: CodeAuthenticationUnavailable, retryable: true},
		{name: "invalid session", resolver: valid, session: scriptedSession{err: authz.ErrCredentialInvalid}, cookie: true, status: 401, code: CodeAuthenticationInvalid},
		{name: "session store outage", resolver: valid, session: scriptedSession{err: authz.ErrAuthenticationUnavailable}, cookie: true, status: 503, code: CodeAuthenticationUnavailable, retryable: true},
		{name: "csrf mismatch", resolver: valid, session: scriptedSession{err: authz.ErrCSRFInvalid}, cookie: true, status: 403, code: CodeCSRFInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := NewAuthenticator(tc.resolver)
			if tc.session != nil {
				auth.SetSessionResolver(tc.session)
			}
			rt := &Router{log: discardLog(), auth: auth, aup: newTestAUP(newFakeAUPStore(), &fakeAudit{})}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/me", nil)
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.cookie {
				req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "opaque"})
			}
			rec := httptest.NewRecorder()
			rt.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			body := decodeErrorContract(t, rec)
			if ErrorCode(body.Code) != tc.code || *body.Retryable != tc.retryable {
				t.Fatalf("body = %+v, want code %q retryable %v", body, tc.code, tc.retryable)
			}
			if body.RequestID == "" || body.RequestID != rec.Header().Get("X-Request-ID") {
				t.Fatalf("request_id %q does not match X-Request-ID %q", body.RequestID, rec.Header().Get("X-Request-ID"))
			}
			if tc.status == 503 && rec.Header().Get("Retry-After") == "" {
				t.Error("a retryable outage must carry Retry-After")
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == sessionCookieName {
					t.Fatalf("the authenticator must never touch the session cookie: %#v", c)
				}
			}
		})
	}
}

// Every error path through writeJSON and writeError carries the same contract, including handler
// errors that never named a code.
func TestErrorContractFillsLegacyBodies(t *testing.T) {
	cases := []struct {
		name   string
		write  func(w http.ResponseWriter)
		status int
		code   ErrorCode
	}{
		{"validation", func(w http.ResponseWriter) { writeError(w, discardLog(), shared.ErrValidation) }, 400, CodeValidationFailed},
		{"forbidden", func(w http.ResponseWriter) { writeError(w, discardLog(), shared.ErrForbidden) }, 403, CodePermissionDenied},
		{"not found", func(w http.ResponseWriter) { writeError(w, discardLog(), shared.ErrNotFound) }, 404, CodeNotFound},
		{"conflict", func(w http.ResponseWriter) { writeError(w, discardLog(), shared.ErrConflict) }, 409, CodeConflict},
		{"saturated", func(w http.ResponseWriter) { writeError(w, discardLog(), shared.ErrSaturated) }, 503, CodeSaturated},
		{"internal", func(w http.ResponseWriter) { writeError(w, discardLog(), errors.New("x")) }, 500, CodeInternal},
		{"auth outage wins over forbidden", func(w http.ResponseWriter) {
			writeError(w, discardLog(), fmt.Errorf("%w: %w", authz.ErrAuthenticationUnavailable, shared.ErrForbidden))
		}, 503, CodeAuthenticationUnavailable},
		{"map body", func(w http.ResponseWriter) { writeJSON(w, 400, map[string]string{"error": "bad"}) }, 400, CodeValidationFailed},
		{"plain 401 is never invalid", func(w http.ResponseWriter) { writeJSON(w, 401, errorBody{Error: "no"}) }, 401, CodeAuthenticationRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rec.Header().Set("X-Request-ID", "req-123")
			tc.write(rec)
			body := decodeErrorContract(t, rec)
			if rec.Code != tc.status || ErrorCode(body.Code) != tc.code || body.RequestID != "req-123" || *body.Retryable != tc.code.Retryable() {
				t.Fatalf("got %d %+v, want %d %q", rec.Code, body, tc.status, tc.code)
			}
		})
	}
	for code, contract := range errorCodeContract {
		if contract.Status == 0 {
			t.Errorf("code %q has no status", code)
		}
	}
}

func TestSessionProbeKeepsTheCookieOnOutage(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		status  int
		cleared bool
	}{
		{"invalid session clears", fmt.Errorf("session inactive: %w", authz.ErrCredentialInvalid), 200, true},
		{"dependency outage keeps", fmt.Errorf("get session: %w", authz.ErrAuthenticationUnavailable), 503, false},
		{"unclassified failure keeps", errors.New("boom"), 503, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &Router{log: discardLog(), oidc: oidcTestService{discover: func(context.Context, string) (OIDCSession, error) { return OIDCSession{}, tc.err }}}
			req := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "opaque"})
			rec := httptest.NewRecorder()
			rt.oidcSession(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			cleared := false
			for _, c := range rec.Result().Cookies() {
				if c.Name == sessionCookieName && c.MaxAge < 0 {
					cleared = true
				}
			}
			if cleared != tc.cleared {
				t.Fatalf("cookie cleared = %v, want %v", cleared, tc.cleared)
			}
			if tc.status == 503 {
				if body := decodeErrorContract(t, rec); ErrorCode(body.Code) != CodeAuthenticationUnavailable || !*body.Retryable {
					t.Fatalf("outage body = %+v", body)
				}
			} else if !strings.Contains(rec.Body.String(), `"authenticated":false`) {
				t.Fatalf("invalid session body = %s", rec.Body.String())
			}
		})
	}
}

func TestOIDCCallbackDeniedSubjectIsAccessDenied(t *testing.T) {
	rt := &Router{log: discardLog(), oidcFrontendURL: "https://synapse.example/", oidc: oidcTestService{complete: func(context.Context, string, string, string) (OIDCSession, error) {
		return OIDCSession{}, fmt.Errorf("OIDC subject has no approved link: %w", identitybff.ErrAccessDenied)
	}}}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=s&code=c", nil)
	req.AddCookie(&http.Cookie{Name: nonceCookieName, Value: "n"})
	rec := httptest.NewRecorder()
	rt.oidcCallback(rec, req)
	// The browser returns to the configured dashboard with a fixed reason, never a request-chosen URL.
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://synapse.example/?auth_error=access_denied" {
		t.Fatalf("status = %d, location = %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Fatal("a denied callback set a session cookie")
		}
	}
}

// A dependency outage during the callback returns the browser to the dashboard with a retryable
// reason rather than a raw JSON body on a top-level navigation, and never sets a session.
func TestOIDCCallbackDependencyFailureRedirectsAsUnavailable(t *testing.T) {
	rt := &Router{log: discardLog(), oidcFrontendURL: "https://synapse.example/", oidc: oidcTestService{complete: func(context.Context, string, string, string) (OIDCSession, error) {
		return OIDCSession{}, fmt.Errorf("resolve linked OIDC identity: %w", authz.ErrAuthenticationUnavailable)
	}}}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=s&code=c", nil)
	req.AddCookie(&http.Cookie{Name: nonceCookieName, Value: "n"})
	rec := httptest.NewRecorder()
	rt.oidcCallback(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://synapse.example/?auth_error=unavailable" {
		t.Fatalf("status = %d, location = %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Fatal("a failed callback set a session cookie")
		}
	}
}

// Principals the authorization decision is exercised with.
var (
	bootstrapTestPrincipal = Principal{ID: PrincipalOperator, Role: "admin", Credential: authz.KindBootstrap}
	tenantAdminKey         = Principal{ID: "admin-1", Role: "admin", TenantID: "acme", Credential: authz.KindAPIKey}
	tenantAdminSession     = Principal{ID: "admin-1", Role: "admin", TenantID: "acme", Credential: authz.KindBrowserSession}
	operatorIDWithoutToken = Principal{ID: PrincipalOperator, Role: "admin", TenantID: "default", Credential: authz.KindAPIKey}
	breakGlassAdmin        = Principal{ID: "admin-1", Role: "admin", TenantID: "acme", Credential: authz.KindBreakGlass}
)

func actionOf(route RouteRegistration) authz.Action {
	return authz.Action{Permission: userdom.Permission(permissionValue(route.Permission)), PlatformOnly: route.PlatformOnly, Recovery: authz.RecoveryAction(recoveryValue(route.Recovery))}
}

func permissionValue(name string) string {
	return map[string]string{
		"": "", "PermView": string(userdom.PermView), "PermOperate": string(userdom.PermOperate), "PermTriage": string(userdom.PermTriage),
		"PermReview": string(userdom.PermReview), "PermAdminister": string(userdom.PermAdminister), "PermManageIntegrations": string(userdom.PermManageIntegrations),
	}[name]
}

func recoveryValue(name string) string {
	return map[string]string{
		"": "", "RecoveryLogout": string(authz.RecoveryLogout), "RecoveryReadSelf": string(authz.RecoveryReadSelf), "RecoveryListUsers": string(authz.RecoveryListUsers),
		"RecoveryAssignRole": string(authz.RecoveryAssignRole), "RecoveryDisableUser": string(authz.RecoveryDisableUser), "RecoveryEnableUser": string(authz.RecoveryEnableUser),
		"RecoveryReadIdentity": string(authz.RecoveryReadIdentity), "RecoveryRepairConnection": string(authz.RecoveryRepairConnection), "RecoveryRelaxSSO": string(authz.RecoveryRelaxSSO),
	}[name]
}

// allHumanRoutes parses both human route tables: router.go and the ownership routes.
func allHumanRoutes(t *testing.T) []RouteRegistration {
	t.Helper()
	routes := registeredRoutes(t)
	for _, file := range []string{"ownership_handler.go", "enterprise_handler.go", "enterprise_admin_handler.go"} {
		additional, err := ParseRouteRegistrations(file)
		if err != nil {
			t.Fatal(err)
		}
		routes = append(routes, additional...)
	}
	return routes
}

// Every human route has exactly one classification, and the classification is backed by the
// parsed guard, not a hand-maintained list.
func TestEveryHumanRouteHasExactlyOneClassification(t *testing.T) {
	counts := map[RouteClass]int{}
	seen := map[string]RouteClass{}
	for _, route := range allHumanRoutes(t) {
		class := route.Class(publicSet())
		if class == RouteUnclassified {
			t.Errorf("route %s (line %d) has no classification (guard %q)", route.Pattern, route.Line, route.Guard)
			continue
		}
		if prior, dup := seen[route.Pattern]; dup && prior != class {
			t.Errorf("route %s is registered twice with classifications %s and %s", route.Pattern, prior, class)
		}
		seen[route.Pattern] = class
		counts[class]++
		if class == RoutePermission && permissionValue(route.Permission) == "" {
			t.Errorf("route %s names an unknown permission %q", route.Pattern, route.Permission)
		}
		if route.Recovery != "" && recoveryValue(route.Recovery) == "" {
			t.Errorf("route %s names an unknown recovery action %q", route.Pattern, route.Recovery)
		}
	}
	for _, class := range []RouteClass{RoutePublic, RouteAuthenticated, RoutePermission, RoutePlatformOnly} {
		if counts[class] == 0 {
			t.Errorf("no route is classified %s; the inventory is no longer reading the guards", class)
		}
	}
	t.Logf("route classes: %v", counts)
	// The public list is exactly the router's unauthenticated path set.
	var listed, served []string
	for pattern := range publicRoutePatterns {
		_, path, _ := strings.Cut(pattern, " ")
		listed = append(listed, path)
	}
	for path := range publicPaths() {
		served = append(served, path)
	}
	sort.Strings(listed)
	sort.Strings(served)
	if strings.Join(listed, ",") != strings.Join(served, ",") {
		t.Fatalf("public route inventory %v does not match publicPaths %v", listed, served)
	}
}

func TestPlatformOnlyRoutesAreBootstrapOnly(t *testing.T) {
	platform := 0
	for _, route := range allHumanRoutes(t) {
		if route.Class(publicSet()) != RoutePlatformOnly {
			continue
		}
		platform++
		action := actionOf(route)
		if !authz.Decide(bootstrapTestPrincipal.authz(), action).Allowed {
			t.Errorf("%s: the bootstrap principal is refused", route.Pattern)
		}
		for name, p := range map[string]Principal{"tenant admin key": tenantAdminKey, "tenant admin session": tenantAdminSession, "operator id without the bootstrap credential": operatorIDWithoutToken, "break glass": breakGlassAdmin} {
			if authz.Decide(p.authz(), action).Allowed {
				t.Errorf("%s: %s is allowed", route.Pattern, name)
			}
		}
	}
	if platform < 10 {
		t.Fatalf("found %d platform-only routes; the inventory is no longer reading requirePlatformAdmin", platform)
	}
	// And the guard itself, end to end.
	h := (&Router{}).requirePlatformAdmin(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for name, tc := range map[string]struct {
		p    *Principal
		want int
	}{
		"missing principal":         {nil, http.StatusUnauthorized},
		"bootstrap":                 {&bootstrapTestPrincipal, http.StatusNoContent},
		"operator id, api key kind": {&operatorIDWithoutToken, http.StatusForbidden},
		"tenant admin session":      {&tenantAdminSession, http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		if tc.p != nil {
			req = req.WithContext(context.WithValue(req.Context(), principalKey, *tc.p))
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: requirePlatformAdmin = %d, want %d", name, rec.Code, tc.want)
		}
	}
}

// A break-glass principal reaches exactly the recovery allowlist: the routes tagged with a recovery
// action, and nothing else, not even as an administrator.
func TestBreakGlassReachesOnlyRecoveryRoutes(t *testing.T) {
	wantRecovery := map[string]bool{
		"POST /api/auth/logout": true, "GET /api/v1/me": true, "GET /api/v1/users": true,
		"PATCH /api/v1/users/{id}": true, "POST /api/v1/users/{id}/disable": true, "POST /api/v1/users/{id}/enable": true,
		"GET /api/v1/identity/connections": true, "POST /api/v1/identity/connections/draft": true, "POST /api/v1/identity/connections/test": true, "POST /api/v1/identity/connections/activate": true, "POST /api/v1/identity/connections/disable": true,
		"GET /api/v1/identity/policy": true, "PUT /api/v1/identity/policy": true, "GET /api/v1/identity/recovery/alerts": true,
		"GET /api/v1/identity/roster": true, "POST /api/v1/identity/memberships/change": true,
	}
	gotRecovery := map[string]bool{}
	for _, route := range allHumanRoutes(t) {
		if route.Class(publicSet()) == RoutePublic {
			continue
		}
		allowed := authz.Decide(breakGlassAdmin.authz(), actionOf(route)).Allowed
		if route.Recovery != "" {
			gotRecovery[route.Pattern] = true
		}
		if allowed != (route.Recovery != "") {
			t.Errorf("%s: break glass allowed=%v, recovery tag %q", route.Pattern, allowed, route.Recovery)
		}
	}
	for pattern := range wantRecovery {
		if !gotRecovery[pattern] {
			t.Errorf("recovery route %s is not tagged", pattern)
		}
	}
	for pattern := range gotRecovery {
		if !wantRecovery[pattern] {
			t.Errorf("route %s joined the recovery allowlist; that is a security decision", pattern)
		}
	}
	for _, forbidden := range []string{"POST /api/v1/users", "POST /api/v1/users/{id}/rotate-key", "POST /api/v1/users/{id}/oidc-links"} {
		if gotRecovery[forbidden] {
			t.Errorf("%s must never be a recovery action", forbidden)
		}
	}
}

// Every protected route answers 401 authentication_required when no principal is bound, before any
// handler or service is reached.
func TestProtectedRoutesFailClosedWithoutPrincipal(t *testing.T) {
	rt := integrationSurfaceRouter()
	svc, err := usersuc.NewService(memory.NewUserRepository(), &fakeAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	rt.users = svc
	rt.aup = newTestAUP(newFakeAUPStore(), &fakeAudit{})
	rt.oidc = oidcTestService{}
	mux := rt.routes()
	checked := 0
	for _, route := range registeredRoutes(t) {
		if route.Class(publicSet()) == RoutePublic {
			continue
		}
		method, path := concreteRoute(route.Pattern)
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		if _, pattern := mux.Handler(req); pattern != route.Pattern {
			continue // conditional route not registered on this router
		}
		checked++
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a principal = %d, want 401", route.Pattern, rec.Code)
			continue
		}
		if body := decodeErrorContract(t, rec); ErrorCode(body.Code) != CodeAuthenticationRequired {
			t.Errorf("%s without a principal: code %q", route.Pattern, body.Code)
		}
	}
	if checked < 40 {
		t.Fatalf("checked %d protected routes; the router is no longer registering them", checked)
	}
	if got := PrincipalFrom(context.Background()); got != "" {
		t.Fatalf("PrincipalFrom without a principal = %q; there is no operator fallback", got)
	}
}

// Machine roles are granted nothing on the human plane, whatever the credential kind.
func TestMachineIdentitiesGetNoHumanPermission(t *testing.T) {
	for _, role := range []string{"agent", "mcp", "service", "worker"} {
		for _, perm := range []userdom.Permission{userdom.PermView, userdom.PermOperate, userdom.PermTriage, userdom.PermReview, userdom.PermAdminister, userdom.PermManageIntegrations} {
			p := Principal{ID: "machine", Role: role, TenantID: "acme", Credential: authz.KindAPIKey}
			if authz.Decide(p.authz(), authz.Action{Permission: perm}).Allowed {
				t.Errorf("machine role %q holds %q", role, perm)
			}
		}
	}
}

// The hook plane and the human plane never authenticate each other's credentials.
func TestWebhookAndHumanCredentialPlanesAreSeparate(t *testing.T) {
	h, _, receiver, _ := setupHook(t)
	body := []byte("payload")
	path := "/api/v1/hooks/" + hookIDA

	// A human bearer or cookie on the hook route is not a hook credential.
	for name, set := range map[string]func(*http.Request){
		"bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer human-token") },
		"cookie": func(r *http.Request) { r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "opaque"}) },
	} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
		set(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("hook with a human %s = %d, want 401", name, rec.Code)
		}
	}
	if len(receiver.snapshot()) != 0 {
		t.Fatal("a human credential delivered a hook")
	}

	// A valid hook signature on a human route never creates a principal.
	auth := NewAuthenticator(func(context.Context, string) (Principal, error) { return Principal{}, authz.ErrCredentialInvalid })
	rt := &Router{log: discardLog(), auth: auth, aup: newTestAUP(newFakeAUPStore(), &fakeAudit{})}
	for _, target := range []string{"/api/v1/me", "/api/v1/users", path + "/other"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set(inboundWebhookSignature, webhookSig(hookSecret('a'), body))
		rec := httptest.NewRecorder()
		rt.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with only a hook signature = %d, want 401", target, rec.Code)
		}
	}
}

// OIDC link endpoints: administrator only (integration_admin included in the refusal), confined to
// the configured tenant, and the approved link is listed back.
func TestOIDCLinkEndpoints(t *testing.T) {
	repo := memory.NewUserRepository()
	svc, err := usersuc.NewService(repo, &fakeAudit{}, fixedClock{t: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	identities, err := memory.NewIdentityStore(repo)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(memory.NewTenantTransactionRunner())
	svc.SetIdentityStore(identities)
	if err := svc.SetOIDCLinking("https://issuer.example", "acme"); err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog(), users: svc}
	adminID, _ := seedTenantAdmin(t, svc, "acme", "Admin")
	targetID, _ := decodeUserKey(t, callUsers(t, rt, ctxAsUser(adminID, "admin", "acme"), http.MethodPost, "/api/v1/users", `{"name":"Alice","role":"member"}`))
	path := "/api/v1/users/" + targetID + "/oidc-links"
	body := `{"issuer":"https://issuer.example","subject":"sub-alice"}`

	for _, role := range []string{"integration_admin", "readonly", "consultant", "reviewer"} {
		if rec := callUsers(t, rt, ctxAsUser("x", role, "acme"), http.MethodPost, path, body); rec.Code != http.StatusForbidden {
			t.Errorf("%s linking = %d, want 403", role, rec.Code)
		}
	}
	if rec := callUsers(t, rt, context.Background(), http.MethodPost, path, body); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated linking = %d, want 401", rec.Code)
	}
	if rec := callUsers(t, rt, ctxAsUser(adminID, "admin", "acme"), http.MethodPost, path, `{"issuer":"https://issuer.example","subject":"s","email":"a@example.com"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown fields (email) must be rejected, got %d", rec.Code)
	}
	if rec := callUsers(t, rt, ctxAsUser(adminID, "admin", "acme"), http.MethodPost, "/api/v1/users/"+PrincipalOperator+"/oidc-links", body); rec.Code != http.StatusForbidden {
		t.Errorf("linking the bootstrap operator = %d, want 403", rec.Code)
	}
	rec := callUsers(t, rt, ctxAsUser(adminID, "admin", "acme"), http.MethodPost, path, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin linking = %d %s", rec.Code, rec.Body.String())
	}
	if rec := callUsers(t, rt, ctxAsUser(adminID, "admin", "acme"), http.MethodPost, path, body); rec.Code != http.StatusConflict {
		t.Errorf("duplicate link = %d, want 409", rec.Code)
	}
	list := callUsers(t, rt, ctxAsUser(adminID, "admin", "acme"), http.MethodGet, path, "")
	var got struct {
		Items []oidcLinkView `json:"items"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &got); err != nil || list.Code != http.StatusOK || len(got.Items) != 1 || got.Items[0].Subject != "sub-alice" || got.Items[0].UserID != targetID {
		t.Fatalf("list = %d %s", list.Code, list.Body.String())
	}
	if rec := callUsers(t, rt, ctxAsUser("globex-admin", "admin", "globex"), http.MethodGet, path, ""); rec.Code != http.StatusNotFound {
		t.Errorf("another tenant's admin reading links = %d, want 404", rec.Code)
	}
}

// DELETE of an OIDC link: administrator only (integration_admin and reviewer refused), confined to
// the configured tenant, never the bootstrap operator, and an unknown link is not found.
func TestOIDCUnlinkEndpoint(t *testing.T) {
	repo := memory.NewUserRepository()
	svc, err := usersuc.NewService(repo, &fakeAudit{}, fixedClock{t: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	identities, err := memory.NewIdentityStore(repo)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(memory.NewTenantTransactionRunner())
	svc.SetIdentityStore(identities)
	if err := svc.SetOIDCLinking("https://issuer.example", "acme"); err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog(), users: svc}
	adminID, _ := seedTenantAdmin(t, svc, "acme", "Admin")
	admin := ctxAsUser(adminID, "admin", "acme")
	targetID, _ := decodeUserKey(t, callUsers(t, rt, admin, http.MethodPost, "/api/v1/users", `{"name":"Alice","role":"member"}`))
	links := "/api/v1/users/" + targetID + "/oidc-links"
	created := callUsers(t, rt, admin, http.MethodPost, links, `{"issuer":"https://issuer.example","subject":"sub-alice"}`)
	var link oidcLinkView
	if err := json.Unmarshal(created.Body.Bytes(), &link); err != nil || created.Code != http.StatusCreated {
		t.Fatalf("link = %d %s", created.Code, created.Body.String())
	}
	path := links + "/" + link.ID

	for _, role := range []string{"integration_admin", "reviewer", "readonly", "consultant"} {
		if rec := callUsers(t, rt, ctxAsUser("x", role, "acme"), http.MethodDelete, path, ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s unlinking = %d, want 403", role, rec.Code)
		}
	}
	if rec := callUsers(t, rt, context.Background(), http.MethodDelete, path, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated unlinking = %d, want 401", rec.Code)
	}
	if rec := callUsers(t, rt, ctxAsUser("globex-admin", "admin", "globex"), http.MethodDelete, path, ""); rec.Code != http.StatusForbidden {
		t.Errorf("unlinking from another tenant = %d, want 403", rec.Code)
	}
	if rec := callUsers(t, rt, admin, http.MethodDelete, "/api/v1/users/"+PrincipalOperator+"/oidc-links/"+link.ID, ""); rec.Code != http.StatusForbidden {
		t.Errorf("unlinking the bootstrap operator = %d, want 403", rec.Code)
	}
	if rec := callUsers(t, rt, admin, http.MethodDelete, links+"/no-such-link", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown link = %d, want 404", rec.Code)
	}
	rec := callUsers(t, rt, admin, http.MethodDelete, path, "")
	var removed oidcLinkView
	if err := json.Unmarshal(rec.Body.Bytes(), &removed); err != nil || rec.Code != http.StatusOK || removed.ID != link.ID || removed.Subject != "sub-alice" {
		t.Fatalf("admin unlinking = %d %s", rec.Code, rec.Body.String())
	}
	if rec := callUsers(t, rt, admin, http.MethodDelete, path, ""); rec.Code != http.StatusNotFound {
		t.Errorf("repeated unlink = %d, want 404", rec.Code)
	}
	list := callUsers(t, rt, admin, http.MethodGet, links, "")
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "sub-alice") {
		t.Fatalf("list after unlink = %d %s", list.Code, list.Body.String())
	}
}
