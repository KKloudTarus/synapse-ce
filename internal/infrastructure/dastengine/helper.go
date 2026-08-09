package dastengine

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastcrawl"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxProofBodyBytes = 4096

var bodySecret = regexp.MustCompile(`(?i)(authorization|cookie|set-cookie|token|secret|password|session)[[:space:]]*[:=][[:space:]]*[^[:space:]"'&<,;]+`)

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
		return json.NewEncoder(out).Encode(ports.DASTOutcome{Incomplete: true, Reason: "authentication_failed"})
	}
	if plan.Crawl != nil {
		outcome, err := runCrawl(ctx, &runner, *plan.Crawl)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(outcome)
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
	return json.NewEncoder(out).Encode(outcome)
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
	base      *url.URL
	client    *http.Client
	session   dastsession.Config
	authorize func(context.Context, ports.DASTRequest) error
	reauth    int
	interval  time.Duration
	last      time.Time
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
		BodyExcerpt: redactExcerpt(body), Headers: redactHeaders(response.Header),
	}, nil
}

func (r *helperRunner) do(ctx context.Context, method, rawURL string, login bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), rawURL, nil)
	if err != nil {
		return nil, errors.New("build DAST request")
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
	if err := r.authorize(ctx, canonicalRequest(req)); err != nil {
		return nil, errAuthorizationDenied
	}
	if !r.last.IsZero() {
		if delay := r.interval - time.Since(r.last); delay > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	r.last = time.Now()
	response, err := r.client.Do(req)
	if err != nil {
		if errors.Is(err, errAuthorizationDenied) {
			return nil, errAuthorizationDenied
		}
		return nil, errors.New("send DAST request")
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 && response.Header.Get("Location") != "" {
		redirect, err := response.Location()
		if err != nil {
			_ = response.Body.Close()
			return nil, errors.New("invalid DAST redirect")
		}
		if err := r.authorize(ctx, ports.DASTRequest{Method: http.MethodGet, URL: proofURL(redirect.String())}); err != nil {
			_ = response.Body.Close()
			return nil, errAuthorizationDenied
		}
	}
	return response, nil
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

func redactExcerpt(body []byte) string {
	text := bodySecret.ReplaceAllString(string(body), "$1=[REDACTED]")
	for _, value := range os.Environ() {
		name, secret, ok := strings.Cut(value, "=")
		if ok && strings.HasPrefix(name, "SYNAPSE_DAST_SECRET_") && secret != "" {
			text = strings.ReplaceAll(text, secret, "[REDACTED]")
		}
	}
	return text
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
