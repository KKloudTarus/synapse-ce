package dastengine

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"

	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastcrawl"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxProofBodyBytes     = 4096
	maxTrackedCookies     = 128
	maxTrackedCookieBytes = 16 << 10
	// Shorter target-issued values (language, consent or feature flags) are redacted only as
	// whole tokens, so a one- or two-byte cookie cannot erase unrelated evidence.
	minSubstringCookieBytes = 8
)

var (
	bodyQuotedSecret   = regexp.MustCompile(`(?i)(["']?(authorization|cookie|set-cookie|token|secret|password|session)["']?[[:space:]]*[:=][[:space:]]*)("(\\.|[^"\\])*"?|'[^']*'?)`)
	bodyUnquotedSecret = regexp.MustCompile(`(?i)(["']?(authorization|cookie|set-cookie|token|secret|password|session)["']?[[:space:]]*[:=][[:space:]]*)[^[:space:]"'&<,;]+`)
	// Decode escape-bearing tokens together; separate decoders miss composed encodings.
	escapeToken = regexp.MustCompile(`[^\s"'<>]+`)
	jsonString  = regexp.MustCompile(`"(\\.|[^"\\])*"`)
)

// RunHelper accepts the public plan on stdin. Its request authorization protocol is
// intentionally separate from stdin so credentials cannot cross the control channel.
func RunHelper(ctx context.Context, in io.Reader, out io.Writer) error {
	var plan ports.DASTPlan
	if err := json.NewDecoder(io.LimitReader(in, 1<<20)).Decode(&plan); err != nil {
		return fmt.Errorf("decode DAST plan: %w", err)
	}
	if err := plan.Session.Validate(); err != nil {
		return fmt.Errorf("validate DAST session: %w", err)
	}
	base, err := url.Parse(plan.Target)
	if err != nil || base == nil || base.Scheme == "" || base.Host == "" || base.User != nil {
		return errors.New("invalid DAST target")
	}
	if plan.RatePerSec <= 0 {
		plan.RatePerSec = ports.DefaultDASTRatePerSec
	}
	if plan.Concurrency <= 0 {
		plan.Concurrency = ports.DefaultDASTConcurrency
	}
	if plan.RatePerSec > ports.DefaultDASTRatePerSec || plan.Concurrency > ports.DefaultDASTConcurrency {
		return errors.New("invalid DAST limits")
	}
	authorize, err := helperAuthorizer()
	if err != nil {
		return err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("create cookie jar: %w", err)
	}
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       ports.DefaultDASTTimeout,
	}
	runner := helperRunner{base: base, client: client, session: plan.Session, authorize: authorize, interval: time.Second / time.Duration(plan.RatePerSec)}
	if err := runner.authenticate(ctx); err != nil {
		if runner.secretFailed {
			return json.NewEncoder(out).Encode(secretTrackingFailure())
		}
		return json.NewEncoder(out).Encode(ports.DASTOutcome{Incomplete: true, Reason: "authentication_failed"})
	}
	if plan.Crawl != nil {
		outcome, err := runCrawl(ctx, &runner, *plan.Crawl)
		if runner.secretFailed {
			return json.NewEncoder(out).Encode(secretTrackingFailure())
		}
		if err != nil {
			return errors.New("DAST crawl failed")
		}
		return json.NewEncoder(out).Encode(runner.sanitizeOutcome(outcome))
	}
	outcome := ports.DASTOutcome{}
	for _, candidate := range plan.Requests {
		observation, incomplete, reason := runner.runCandidate(ctx, candidate)
		if incomplete {
			outcome.Incomplete, outcome.Reason = true, reason
			break
		}
		if observation.URL != "" {
			outcome.Observations = append(outcome.Observations, observation)
		}
	}
	return json.NewEncoder(out).Encode(runner.sanitizeOutcome(outcome))
}

func runCrawl(ctx context.Context, r *helperRunner, plan ports.DASTCrawlPlan) (ports.DASTOutcome, error) {
	if plan.WallClock > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, plan.WallClock)
		defer cancel()
	}
	result, err := dastcrawl.Crawl(ctx, dastcrawl.Input{
		Target: plan.Target, Seeds: plan.Seeds, Robots: plan.Robots, Sitemaps: plan.Sitemaps,
		OpenAPI: plan.OpenAPI, GraphQL: plan.GraphQL,
	}, dastcrawl.Limits{Depth: plan.Depth, Pages: plan.Pages, Requests: plan.Requests, WallClock: plan.WallClock}, func(ctx context.Context, candidates []dastsurface.Request) (ports.DASTOutcome, error) {
		outcome := ports.DASTOutcome{}
		for _, candidate := range candidates {
			if r.session.DeniesPath(requestPath(candidate.ExecutionURL)) {
				outcome.Coverage.Entries = append(outcome.Coverage.Entries, dastsurface.CoverageEntry{
					Request: candidate, Status: dastsurface.CoverageSkipped, Reason: "deny_path", Source: candidate.Source,
				})
				continue
			}
			observation, incomplete, reason := r.runCandidate(ctx, candidate)
			if incomplete {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					reason = "wall_clock"
				}
				outcome.Incomplete, outcome.Reason = true, reason
				return outcome, nil
			}
			if observation.URL != "" {
				outcome.Observations = append(outcome.Observations, observation)
			}
		}
		return outcome, nil
	})
	if err != nil {
		return ports.DASTOutcome{}, err
	}
	reason := result.Reason
	if reason == "context_cancelled" && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		reason = "wall_clock"
	}
	return ports.DASTOutcome{Observations: result.Observations, Surface: result.Surface, Coverage: result.Coverage, Incomplete: result.Incomplete, Reason: reason}, nil
}

var errAuthorizationDenied = errors.New("DAST request authorization denied")

type helperRunner struct {
	base          *url.URL
	client        *http.Client
	session       dastsession.Config
	authorize     func(context.Context, ports.DASTRequest) error
	reauth        int
	interval      time.Duration
	last          time.Time
	cookieSecrets map[string]struct{}
	cookieBytes   int
	secretFailed  bool
	redactor      *outcomeRedactor
}

func (r *helperRunner) runCandidate(ctx context.Context, candidate dastsurface.Request) (ports.DASTObservation, bool, string) {
	request, err := dastsurface.NormalizeRequest(candidate.Method, candidate.URL)
	executionURL := candidate.ExecutionURL
	if executionURL == "" {
		executionURL = candidate.URL
	}
	execution, executionErr := dastsurface.NormalizeRequest(candidate.Method, executionURL)
	if err != nil || executionErr != nil || !sameOrigin(r.base, executionURL) || execution.Key() != request.Key() || r.session.DeniesPath(requestPath(executionURL)) {
		return ports.DASTObservation{}, false, ""
	}
	method := strings.ToUpper(request.Method)
	if method != http.MethodGet && method != http.MethodHead {
		return ports.DASTObservation{}, false, ""
	}
	if err := r.live(ctx); err != nil && !r.reauthenticate(ctx) {
		return ports.DASTObservation{}, true, "session_lost"
	}
	observation, err := r.request(ctx, method, executionURL)
	if err != nil {
		if errors.Is(err, errAuthorizationDenied) {
			return ports.DASTObservation{}, true, "request_not_authorized"
		}
		return ports.DASTObservation{}, true, "request_failed"
	}
	return observation, false, ""
}

func (r *helperRunner) authenticate(ctx context.Context) error {
	loginURL, err := r.resolve(r.session.LoginRequest.Path)
	if err != nil {
		return err
	}
	response, err := r.do(ctx, r.session.LoginRequest.Method, loginURL, true)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	return success(response, r.session.Success)
}

func (r *helperRunner) reauthenticate(ctx context.Context) bool {
	max := r.session.MaxReauth
	if max == 0 {
		max = dastsession.DefaultMaxReauth
	}
	for r.reauth < max {
		r.reauth++
		if r.authenticate(ctx) == nil && r.live(ctx) == nil {
			return true
		}
	}
	return false
}

func (r *helperRunner) live(ctx context.Context) error {
	checkURL, err := r.resolve(r.session.CheckRequest.Path)
	if err != nil {
		return err
	}
	response, err := r.do(ctx, r.session.CheckRequest.Method, checkURL, false)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	return success(response, r.session.Success)
}

func (r *helperRunner) request(ctx context.Context, method, rawURL string) (ports.DASTObservation, error) {
	response, err := r.do(ctx, method, rawURL, false)
	if err != nil {
		return ports.DASTObservation{}, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProofBodyBytes+1))
	if err != nil {
		return ports.DASTObservation{}, errors.New("read DAST response")
	}
	truncated := len(body) > maxProofBodyBytes
	if truncated {
		body = body[:maxProofBodyBytes]
	}
	hash := sha256.Sum256(body)
	return ports.DASTObservation{
		Method: method, URL: proofURL(rawURL), Status: response.StatusCode,
		BodySHA256: hex.EncodeToString(hash[:]), BodyBytes: len(body), BodyTruncated: truncated,
		BodyExcerpt: string(body), Headers: redactHeaders(response.Header), HeadersCaptured: true,
	}, nil
}

func (r *helperRunner) do(ctx context.Context, method, rawURL string, login bool) (*http.Response, error) {
	if r.secretFailed {
		return nil, errors.New("DAST cookie tracking failed")
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), rawURL, nil)
	if err != nil {
		return nil, errors.New("build DAST request")
	}
	if r.rejectSecretURL(req.URL) {
		return nil, errors.New("DAST URL contains a tracked secret")
	}
	if login && r.session.Scheme == dastsession.SchemeForm {
		values := url.Values{}
		for _, binding := range r.session.Credentials {
			field := binding.Field
			if field == "" {
				field = binding.Name
			}
			values.Set(field, os.Getenv(secretEnvName(binding.Name)))
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		encoded := values.Encode()
		req.Body = io.NopCloser(strings.NewReader(encoded))
		req.ContentLength = int64(len(encoded))
	}
	r.applyAuth(req)
	if !r.last.IsZero() {
		if delay := r.interval - time.Since(r.last); delay > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	if err := r.authorize(ctx, canonicalRequest(req)); err != nil {
		return nil, errAuthorizationDenied
	}
	r.last = time.Now()
	response, err := r.client.Do(req)
	if err != nil {
		if errors.Is(err, errAuthorizationDenied) {
			return nil, errAuthorizationDenied
		}
		return nil, errors.New("send DAST request")
	}
	if !r.trackCookies(response.Header.Values("Set-Cookie")) {
		_ = response.Body.Close()
		return nil, errors.New("DAST cookie tracking failed")
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 && response.Header.Get("Location") != "" {
		redirect, err := response.Location()
		if err != nil {
			_ = response.Body.Close()
			return nil, errors.New("invalid DAST redirect")
		}
		redirectURL := redirect.String()
		if r.rejectSecretURL(redirect) {
			_ = response.Body.Close()
			return nil, errors.New("DAST redirect contains a tracked secret")
		}
		if err := r.authorize(ctx, ports.DASTRequest{Method: http.MethodGet, URL: proofURL(redirectURL)}); err != nil {
			_ = response.Body.Close()
			return nil, errAuthorizationDenied
		}
	}
	return response, nil
}

// rejectSecretURL runs before authorization. It checks the raw URL, its decoded
// components and the exact canonical form sent to the parent, because partial
// escaping can hide a value that canonicalization later reveals.
func (r *helperRunner) rejectSecretURL(u *url.URL) bool {
	redactor, err := r.newOutcomeRedactor()
	if err == nil && !redactor.containsURLSecret(u, u.String()) {
		canonical := proofURL(u.String())
		if parsed, perr := url.Parse(canonical); canonical != "" && perr == nil && !redactor.containsURLSecret(parsed, canonical) {
			return false
		}
	}
	r.secretFailed = true
	return true
}

func (r *helperRunner) applyAuth(req *http.Request) {
	credential := func(i int) string {
		if i >= len(r.session.Credentials) {
			return ""
		}
		return os.Getenv(secretEnvName(r.session.Credentials[i].Name))
	}
	switch r.session.Scheme {
	case dastsession.SchemeBasic:
		req.SetBasicAuth(credential(0), credential(1))
	case dastsession.SchemeBearer:
		req.Header.Set("Authorization", "Bearer "+credential(0))
	case dastsession.SchemeHeader:
		for _, binding := range r.session.Credentials {
			field := binding.Field
			if field == "" {
				field = binding.Name
			}
			req.Header.Set(field, os.Getenv(secretEnvName(binding.Name)))
		}
	case dastsession.SchemeCookie:
		for _, binding := range r.session.Credentials {
			field := binding.Field
			if field == "" {
				field = binding.Name
			}
			// Request cookie, not a Set-Cookie: Secure/HttpOnly/SameSite are response directives and
			// AddCookie serialises only Name=Value, so they would have no effect on the wire.
			req.AddCookie(&http.Cookie{Name: field, Value: os.Getenv(secretEnvName(binding.Name))}) //nolint:gosec // G124 does not apply to an outgoing request cookie
		}
	}
}

func (r *helperRunner) resolve(p string) (string, error) {
	u, err := r.base.Parse(p)
	if err != nil || !sameOrigin(r.base, u.String()) || r.session.DeniesPath(u.Path) {
		return "", errors.New("invalid DAST session path")
	}
	return u.String(), nil
}

func success(response *http.Response, signal dastsession.SuccessSignal) error {
	if signal.StatusCode != 0 && response.StatusCode != signal.StatusCode {
		return errors.New("session signal did not match")
	}
	if signal.HeaderPresent != "" && response.Header.Get(signal.HeaderPresent) == "" {
		return errors.New("session signal did not match")
	}
	if signal.CookiePresent != "" {
		present := false
		for _, cookie := range response.Cookies() {
			if cookie.Name == signal.CookiePresent {
				present = true
			}
		}
		if !present {
			return errors.New("session signal did not match")
		}
	}
	if signal.BodyContains != "" {
		body, err := io.ReadAll(io.LimitReader(response.Body, maxProofBodyBytes+1))
		if err != nil || !strings.Contains(string(body), signal.BodyContains) {
			return errors.New("session signal did not match")
		}
	}
	return nil
}

func helperAuthorizer() (func(context.Context, ports.DASTRequest) error, error) {
	requestFD, err := strconv.Atoi(os.Getenv("SYNAPSE_DAST_AUTH_REQUEST_FD"))
	if err != nil || requestFD < 3 {
		return nil, errors.New("DAST authorization channel unavailable")
	}
	decisionFD, err := strconv.Atoi(os.Getenv("SYNAPSE_DAST_AUTH_DECISION_FD"))
	if err != nil || decisionFD < 3 {
		return nil, errors.New("DAST authorization channel unavailable")
	}
	requests := json.NewEncoder(os.NewFile(uintptr(requestFD), "dast-auth-request"))
	decisions := json.NewDecoder(bufio.NewReader(os.NewFile(uintptr(decisionFD), "dast-auth-decision")))
	return func(_ context.Context, request ports.DASTRequest) error {
		if err := requests.Encode(request); err != nil {
			return errAuthorizationDenied
		}
		var decision ports.DASTAuthorization
		if err := decisions.Decode(&decision); err != nil || !decision.Allowed {
			return errAuthorizationDenied
		}
		return nil
	}, nil
}

func canonicalRequest(request *http.Request) ports.DASTRequest {
	return ports.DASTRequest{Method: request.Method, URL: proofURL(request.URL.String())}
}

func proofURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User = nil
	query := u.Query()
	for key := range query {
		query[key] = []string{"[REDACTED]"}
	}
	u.RawQuery = query.Encode()
	u.Fragment = ""
	return u.String()
}

func sameOrigin(base *url.URL, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return false
	}
	return canonicalOrigin(base) == canonicalOrigin(u)
}

func canonicalOrigin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else if strings.EqualFold(u.Scheme, "http") {
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

func requestPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	return path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
}

func secretEnvName(name string) string {
	return "SYNAPSE_DAST_SECRET_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name))
}

func secretTrackingFailure() ports.DASTOutcome {
	return ports.DASTOutcome{Incomplete: true, Reason: "secret_tracking_limit"}
}

// trackCookies keeps every issued value, including replaced values, until the outcome is sealed.
func (r *helperRunner) trackCookies(headers []string) bool {
	if r.secretFailed {
		return false
	}
	if r.cookieSecrets == nil {
		r.cookieSecrets = make(map[string]struct{})
	}
	for _, header := range headers {
		cookie, err := http.ParseSetCookie(header)
		if err != nil {
			r.secretFailed = true
			return false
		}
		if cookie.Value == "" {
			continue
		}
		if _, exists := r.cookieSecrets[cookie.Value]; exists {
			continue
		}
		if len(r.cookieSecrets) >= maxTrackedCookies || len(cookie.Value) > maxTrackedCookieBytes-r.cookieBytes {
			r.secretFailed = true
			return false
		}
		r.cookieSecrets[cookie.Value] = struct{}{}
		r.cookieBytes += len(cookie.Value)
		r.redactor = nil
	}
	return true
}

func secretForms(secret string) []string {
	encoded, _ := json.Marshal(secret)
	query, escapedPath := url.QueryEscape(secret), url.PathEscape(secret)
	return []string{secret, string(encoded[1 : len(encoded)-1]), query, escapedPath, lowerEscapes(query), lowerEscapes(escapedPath)}
}

func lowerEscapes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			b.WriteByte('%')
			b.WriteString(strings.ToLower(s[i+1 : i+3]))
			i += 2
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

type redactionSpan struct {
	start, end int
	quoted     bool
}

type outcomeRedactor struct {
	forms        []string // redacted wherever they appear
	boundedForms []string // short target-issued values, redacted only as whole tokens
	matcher      *regexp.Regexp
	longMatcher  *regexp.Regexp
	bounded      *regexp.Regexp
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// expandSecretForms returns every encoded form once, longest first, so the alternation
// prefers the widest match.
func expandSecretForms(secrets map[string]struct{}) []string {
	unique := make(map[string]struct{})
	for secret := range secrets {
		for _, form := range secretForms(secret) {
			if form != "" {
				unique[form] = struct{}{}
			}
		}
	}
	forms := make([]string, 0, len(unique))
	for form := range unique {
		forms = append(forms, form)
	}
	sort.Slice(forms, func(i, j int) bool {
		if len(forms[i]) != len(forms[j]) {
			return len(forms[i]) > len(forms[j])
		}
		return forms[i] < forms[j]
	})
	return forms
}

func compileAlternation(patterns []string) (*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	return regexp.Compile(strings.Join(patterns, "|"))
}

func (r *helperRunner) newOutcomeRedactor() (*outcomeRedactor, error) {
	// Credentials are fixed for this helper process; only newly issued cookies change the matcher.
	if r.redactor != nil {
		return r.redactor, nil
	}
	strict := make(map[string]struct{}, len(r.cookieSecrets))
	short := make(map[string]struct{})
	for secret := range r.cookieSecrets {
		if len(secret) < minSubstringCookieBytes {
			short[secret] = struct{}{}
		} else {
			strict[secret] = struct{}{}
		}
	}
	// Operator-supplied credentials are always redacted wherever they appear.
	for _, value := range os.Environ() {
		name, secret, ok := strings.Cut(value, "=")
		if ok && strings.HasPrefix(name, "SYNAPSE_DAST_SECRET_") && secret != "" {
			strict[secret] = struct{}{}
		}
	}
	redactor := &outcomeRedactor{forms: expandSecretForms(strict), boundedForms: expandSecretForms(short)}
	var patterns, longPatterns, boundedPatterns []string
	for _, form := range redactor.forms {
		patterns = append(patterns, regexp.QuoteMeta(form))
		if len(form) >= 4 {
			longPatterns = append(longPatterns, regexp.QuoteMeta(form))
		}
	}
	for _, form := range redactor.boundedForms {
		pattern := regexp.QuoteMeta(form)
		if isWordByte(form[0]) {
			pattern = `\b` + pattern
		}
		if isWordByte(form[len(form)-1]) {
			pattern += `\b`
		}
		boundedPatterns = append(boundedPatterns, pattern)
	}
	var err error
	if redactor.matcher, err = compileAlternation(patterns); err != nil {
		return nil, err
	}
	if redactor.longMatcher, err = compileAlternation(longPatterns); err != nil {
		return nil, err
	}
	if redactor.bounded, err = compileAlternation(boundedPatterns); err != nil {
		return nil, err
	}
	r.redactor = redactor
	return redactor, nil
}

func (r *outcomeRedactor) matches(text string) bool {
	return r.matcher != nil && r.matcher.MatchString(text) || r.bounded != nil && r.bounded.MatchString(text)
}

// matchesDecoded checks composed web encodings. Unresolved nesting fails closed.
func (r *outcomeRedactor) matchesDecoded(text string) bool {
	if r.matches(text) {
		return true
	}
	if r.matcher == nil && r.bounded == nil {
		return false
	}
	decodings, exhausted := secretDecodings(text)
	if exhausted {
		return true
	}
	for _, decoded := range decodings {
		if r.matches(decoded) {
			return true
		}
	}
	return false
}

func (r *outcomeRedactor) containsURLSecret(u *url.URL, raw string) bool {
	if r.longMatcher != nil {
		if r.longMatcher.MatchString(raw) {
			return true
		}
		decodings, _ := secretDecodings(raw)
		for _, decoded := range decodings {
			if r.longMatcher.MatchString(decoded) {
				return true
			}
		}
	}
	// Short values cannot invalidate the fixed authority merely by matching a hostname.
	components := []string{
		u.EscapedPath() + "?" + u.RawQuery + "#" + u.Fragment,
		u.EscapedPath(), u.Path, u.RawQuery, u.Fragment, u.EscapedFragment(),
	}
	// Malformed pairs are skipped here and dropped by proofURL, so they never cross the pipe.
	query, _ := url.ParseQuery(u.RawQuery)
	for key, values := range query {
		components = append(components, key)
		components = append(components, values...)
	}
	for _, component := range components {
		if r.matchesDecoded(component) {
			return true
		}
	}
	return false
}

func (r *outcomeRedactor) redactExcerpt(text string, truncated bool) (string, bool) {
	var spans []redactionSpan
	for _, match := range bodyQuotedSecret.FindAllStringSubmatchIndex(text, -1) {
		spans = append(spans, redactionSpan{match[6], match[7], true})
	}
	for _, match := range bodyUnquotedSecret.FindAllStringSubmatchIndex(text, -1) {
		spans = append(spans, redactionSpan{match[3], match[1], false})
	}
	if r.matcher != nil || r.bounded != nil {
		for _, match := range jsonString.FindAllStringIndex(text, -1) {
			var decoded string
			if json.Unmarshal([]byte(text[match[0]:match[1]]), &decoded) == nil && r.matchesDecoded(decoded) {
				spans = append(spans, redactionSpan{match[0], match[1], true})
			}
		}
		for _, match := range escapeToken.FindAllStringIndex(text, -1) {
			decodings, exhausted := secretDecodings(text[match[0]:match[1]])
			unsafe := exhausted
			for _, decoded := range decodings {
				if unsafe {
					break
				}
				unsafe = r.matches(decoded) || truncated && match[1] == len(text) && r.endsWithFormPrefix(decoded)
			}
			if unsafe {
				spans = append(spans, redactionSpan{match[0], match[1], false})
			}
		}
	}
	for _, matcher := range []*regexp.Regexp{r.matcher, r.bounded} {
		if matcher == nil {
			continue
		}
		for _, match := range matcher.FindAllStringIndex(text, -1) {
			spans = append(spans, redactionSpan{match[0], match[1], false})
		}
	}
	if truncated {
		trailingPrefix := func(form string, bounded bool) {
			for n := min(len(form)-1, len(text)); n > 0; n-- {
				start := len(text) - n
				if strings.HasSuffix(text, form[:n]) && (!bounded || start == 0 || !isWordByte(text[start-1]) || !isWordByte(form[0])) {
					spans = append(spans, redactionSpan{start, len(text), false})
					return
				}
			}
		}
		for _, form := range r.forms {
			trailingPrefix(form, false)
		}
		for _, form := range r.boundedForms {
			trailingPrefix(form, true)
		}
	}
	if len(spans) == 0 {
		return text, !r.matchesDecoded(text)
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	var out, residue strings.Builder
	pos := 0
	for i := 0; i < len(spans); {
		span := spans[i]
		i++
		for i < len(spans) && spans[i].start < span.end {
			if spans[i].end > span.end {
				span.end = spans[i].end
				span.quoted = false
			}
			i++
		}
		out.WriteString(text[pos:span.start])
		residue.WriteString(text[pos:span.start])
		residue.WriteByte(0)
		if span.quoted {
			out.WriteString(`"[REDACTED]"`)
		} else {
			out.WriteString("[REDACTED]")
		}
		pos = span.end
	}
	out.WriteString(text[pos:])
	residue.WriteString(text[pos:])
	// A composed reflection can span tokens. If its original span cannot be located,
	// refuse the outcome instead of sealing a recoverable value or hiding lost coverage.
	if r.matchesDecoded(residue.String()) {
		return "", false
	}
	return out.String(), true
}

// endsWithFormPrefix reports whether a token cut at the excerpt boundary may hold the
// start of a secret.
func (r *outcomeRedactor) endsWithFormPrefix(text string) bool {
	for _, forms := range [][]string{r.forms, r.boundedForms} {
		for _, form := range forms {
			for n := min(len(form)-1, len(text)); n > 0; n-- {
				if strings.HasSuffix(text, form[:n]) {
					return true
				}
			}
		}
	}
	return false
}

const (
	maxSecretDecodings = 4
	maxSecretViews     = 64
)

// secretDecodings explores alternate decoder orders: applying one decoder first can
// destroy literal escape syntax belonging to a credential. Depth and distinct-view
// bounds fail closed rather than silently skipping an unexplored representation.
func secretDecodings(s string) (out []string, exhausted bool) {
	if !strings.ContainsAny(s, `%&\+`) {
		return nil, false
	}
	decoders := [...]func(string) string{decodePercent, html.UnescapeString, decodeBackslash, decodeQuerySpaces}
	seen := map[string]struct{}{s: {}}
	frontier := []string{s}
	for range maxSecretDecodings {
		start := len(out)
		for _, view := range frontier {
			for _, decode := range decoders {
				decoded := decode(view)
				if _, exists := seen[decoded]; exists {
					continue
				}
				if len(seen) == maxSecretViews {
					return out, true
				}
				seen[decoded] = struct{}{}
				out = append(out, decoded)
			}
		}
		if len(out) == start {
			return out, false
		}
		frontier = out[start:]
	}
	for _, view := range frontier {
		for _, decode := range decoders {
			if _, exists := seen[decode(view)]; !exists {
				return out, true
			}
		}
	}
	return out, false
}

func decodeQuerySpaces(s string) string {
	return strings.ReplaceAll(s, "+", " ")
}

// decodeBackslash follows JSON/JavaScript character escapes, including UTF-16 pairs.
func decodeBackslash(s string) string {
	start := strings.IndexByte(s, '\\')
	if start < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(s[:start])
	for i := start; i < len(s); {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		tail := s[i+1:]
		if len(tail) >= 11 && tail[0] == 'u' && tail[5] == '\\' && tail[6] == 'u' {
			high, highErr := strconv.ParseUint(tail[1:5], 16, 16)
			low, lowErr := strconv.ParseUint(tail[7:11], 16, 16)
			if highErr == nil && lowErr == nil && high >= 0xd800 && high <= 0xdbff && low >= 0xdc00 && low <= 0xdfff {
				b.WriteRune(utf16.DecodeRune(rune(high), rune(low)))
				i += 12
				continue
			}
		}
		value, _, rest, err := strconv.UnquoteChar(s[i:], '"')
		if err == nil {
			b.WriteRune(value)
			i += len(s[i:]) - len(rest)
			continue
		}
		// JavaScript identity escapes retain the following character.
		b.WriteByte(tail[0])
		i += 2
	}
	return b.String()
}

func decodePercent(s string) string {
	start := strings.IndexByte(s, '%')
	if start < 0 {
		return s
	}
	hexDigit := func(c byte) bool {
		return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
	}
	for start+2 >= len(s) || !hexDigit(s[start+1]) || !hexDigit(s[start+2]) {
		next := strings.IndexByte(s[start+1:], '%')
		if next < 0 {
			return s
		}
		start += next + 1
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(s[:start])
	for i := start; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && hexDigit(s[i+1]) && hexDigit(s[i+2]) {
			v, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b.WriteByte(byte(v))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// A later response can issue a value already reflected in an earlier observation or URL.
// URLs cannot be rewritten without changing coverage and proof identity, so fail closed instead.
func (r *helperRunner) sanitizeOutcome(outcome ports.DASTOutcome) ports.DASTOutcome {
	if r.secretFailed {
		return secretTrackingFailure()
	}
	redactor, err := r.newOutcomeRedactor()
	if err != nil {
		return secretTrackingFailure()
	}
	containsSecret := func(raw string) bool {
		u, err := url.Parse(raw)
		if err != nil {
			return true
		}
		return redactor.containsURLSecret(u, raw)
	}
	for i := range outcome.Observations {
		o := &outcome.Observations[i]
		if containsSecret(o.URL) {
			return secretTrackingFailure()
		}
		excerpt, safe := redactor.redactExcerpt(o.BodyExcerpt, o.BodyTruncated)
		if !safe {
			return secretTrackingFailure()
		}
		o.BodyExcerpt = excerpt
	}
	for _, request := range outcome.Surface.Requests {
		if containsSecret(request.URL) || containsSecret(request.ExecutionURL) {
			return secretTrackingFailure()
		}
	}
	for _, entry := range outcome.Coverage.Entries {
		if containsSecret(entry.Request.URL) || containsSecret(entry.Request.ExecutionURL) {
			return secretTrackingFailure()
		}
	}
	return outcome
}

// redactHeaders preserves header names and non-secret values needed by passive checks.
func redactHeaders(headers http.Header) []string {
	out := make([]string, 0, len(headers))
	for name, values := range headers {
		switch {
		case strings.EqualFold(name, "Set-Cookie"):
			for _, value := range values {
				flags := map[string]bool{}
				for _, part := range strings.Split(value, ";")[1:] {
					name, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(part)), "=")
					switch name {
					case "secure", "httponly", "samesite":
						flags[name] = true
					}
				}
				var names []string
				for _, name := range []string{"secure", "httponly", "samesite"} {
					if flags[name] {
						names = append(names, name)
					}
				}
				out = append(out, "Set-Cookie: "+strings.Join(names, ";"))
			}
		case strings.EqualFold(name, "Strict-Transport-Security"):
			out = append(out, "Strict-Transport-Security")
		case strings.EqualFold(name, "X-Synapse-Auth-Weakness"):
			out = append(out, "X-Synapse-Auth-Weakness")
		}
	}
	sort.Strings(out)
	return out
}
