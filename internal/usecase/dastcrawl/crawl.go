// Package dastcrawl derives a bounded, deterministic HTTP surface from authenticated observations.
package dastcrawl

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	DefaultDepth     = 8
	DefaultPages     = 2000
	DefaultRequests  = 20000
	DefaultWallClock = 30 * time.Minute
)

type Limits struct {
	Depth, Pages, Requests int
	WallClock              time.Duration
}

func (l Limits) normalized() (Limits, error) {
	if l.Depth == 0 {
		l.Depth = DefaultDepth
	}
	if l.Pages == 0 {
		l.Pages = DefaultPages
	}
	if l.Requests == 0 {
		l.Requests = DefaultRequests
	}
	if l.WallClock == 0 {
		l.WallClock = DefaultWallClock
	}
	if l.Depth < 1 || l.Depth > DefaultDepth || l.Pages < 1 || l.Pages > DefaultPages || l.Requests < 1 || l.Requests > DefaultRequests || l.WallClock < time.Second || l.WallClock > DefaultWallClock {
		return Limits{}, fmt.Errorf("%w: invalid DAST crawl limits", shared.ErrValidation)
	}
	return l, nil
}

type Input struct {
	Target   string
	Seeds    []dastsurface.Request
	Robots   string
	Sitemaps []string
	OpenAPI  []string
	GraphQL  []string // Explicitly operator-permitted introspection response JSON.
}

type Batch func(context.Context, []dastsurface.Request) (ports.DASTOutcome, error)

type Result struct {
	Surface      dastsurface.Surface
	Coverage     dastsurface.Coverage
	Observations []ports.DASTObservation
	Incomplete   bool
	Reason       string
}

type queued struct {
	request dastsurface.Request
	depth   int
}

func Crawl(ctx context.Context, input Input, limits Limits, run Batch) (Result, error) {
	if run == nil {
		return Result{}, fmt.Errorf("%w: DAST crawl batch runner is required", shared.ErrValidation)
	}
	limits, err := limits.normalized()
	if err != nil {
		return Result{}, err
	}
	base, err := url.Parse(input.Target)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil {
		return Result{}, fmt.Errorf("%w: DAST crawl target is invalid", shared.ErrValidation)
	}
	crawlCtx, cancel := context.WithTimeout(ctx, limits.WallClock)
	defer cancel()
	var coverage []dastsurface.CoverageEntry
	queue := append([]queued{}, sourceRequests(base, input.Seeds, dastsurface.SourceSeed, &coverage)...)
	queue = append(queue, sourceRequests(base, parseRobots(input.Robots), dastsurface.SourceRobots, &coverage)...)
	for _, doc := range input.Sitemaps {
		queue = append(queue, sourceRequests(base, parseSitemap(doc), dastsurface.SourceSitemap, &coverage)...)
	}
	for _, doc := range input.OpenAPI {
		queue = append(queue, sourceRequests(base, parseOpenAPI(doc), dastsurface.SourceOpenAPI, &coverage)...)
	}
	for _, doc := range input.GraphQL {
		queue = append(queue, sourceRequests(base, parseGraphQL(doc), dastsurface.SourceGraphQL, &coverage)...)
	}
	sortQueue(queue)
	seen := map[string]bool{}
	var executed []dastsurface.Request
	var observations []ports.DASTObservation
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return finish(executed, observations, coverage, true, "context_cancelled")
		}
		if err := crawlCtx.Err(); err != nil {
			return finish(executed, observations, appendLimited(queue, coverage, "wall_clock"), true, "wall_clock")
		}
		q := queue[0]
		queue = queue[1:]
		if seen[q.request.Key()] {
			continue
		}
		seen[q.request.Key()] = true
		if q.depth > limits.Depth {
			coverage = append(coverage, entry(q.request, dastsurface.CoverageLimited, "depth"))
			continue
		}
		if len(executed) >= limits.Pages || len(executed) >= limits.Requests {
			return finish(executed, observations, appendLimited(append([]queued{q}, queue...), coverage, "page_or_request_limit"), true, "page_or_request_limit")
		}
		outcome, runErr := run(crawlCtx, []dastsurface.Request{q.request})
		if ctx.Err() != nil {
			return finish(executed, observations, coverage, true, "context_cancelled")
		}
		if crawlCtx.Err() != nil {
			return finish(executed, observations, appendLimited(append([]queued{q}, queue...), coverage, "wall_clock"), true, "wall_clock")
		}
		if runErr != nil {
			return Result{}, fmt.Errorf("run DAST crawl request: %w", runErr)
		}
		if len(outcome.Coverage.Entries) == 0 {
			coverage = append(coverage, entry(q.request, dastsurface.CoverageRequested, ""))
		} else {
			coverage = append(coverage, outcome.Coverage.Entries...)
		}
		executed = append(executed, q.request)
		observations = append(observations, outcome.Observations...)
		if outcome.Incomplete {
			return finish(executed, observations, coverage, true, outcome.Reason)
		}
		for _, observation := range outcome.Observations {
			for _, discovered := range parseObservation(base, observation) {
				if discovered.Method != "GET" && discovered.Method != "HEAD" {
					coverage = append(coverage, entry(discovered, dastsurface.CoverageSkipped, "form"))
					continue
				}
				discovered.Source = dastsurface.SourceHTML
				next := sourceRequests(base, []dastsurface.Request{discovered}, discovered.Source, &coverage)
				for i := range next {
					next[i].depth = q.depth + 1
				}
				queue = append(queue, next...)
			}
		}
		sortQueue(queue)
	}
	return finish(executed, observations, coverage, false, "")
}

func finish(requests []dastsurface.Request, observations []ports.DASTObservation, entries []dastsurface.CoverageEntry, incomplete bool, reason string) (Result, error) {
	surface, err := dastsurface.NewSurface(requests)
	if err != nil {
		return Result{}, err
	}
	coverage, err := dastsurface.NewCoverage(entries)
	if err != nil {
		return Result{}, err
	}
	return Result{Surface: surface, Coverage: coverage, Observations: observations, Incomplete: incomplete, Reason: reason}, nil
}
func entry(r dastsurface.Request, status dastsurface.CoverageStatus, reason string) dastsurface.CoverageEntry {
	return dastsurface.CoverageEntry{Request: r, Status: status, Reason: reason, Source: r.Source}
}
func appendLimited(q []queued, entries []dastsurface.CoverageEntry, reason string) []dastsurface.CoverageEntry {
	for _, v := range q {
		entries = append(entries, entry(v.request, dastsurface.CoverageLimited, reason))
	}
	return entries
}
func sortQueue(q []queued) {
	sort.Slice(q, func(i, j int) bool {
		if q[i].depth != q[j].depth {
			return q[i].depth < q[j].depth
		}
		return q[i].request.Key() < q[j].request.Key()
	})
}
func sourceRequests(base *url.URL, requests []dastsurface.Request, source dastsurface.Source, coverage *[]dastsurface.CoverageEntry) []queued {
	out := make([]queued, 0, len(requests))
	for _, r := range requests {
		raw := r.URL
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil {
			continue
		}
		if !parsed.IsAbs() {
			raw = base.ResolveReference(parsed).String()
		}
		n, err := dastsurface.NormalizeRequest(r.Method, raw)
		if err != nil {
			continue
		}
		executionURL := raw
		if r.ExecutionURL != "" {
			executionURL = r.ExecutionURL
		}
		if executionURL == "" {
			executionURL = r.URL
		}
		executionURLParsed, executionErr := url.Parse(executionURL)
		if executionErr != nil || executionURLParsed.User != nil {
			continue
		}
		executionURLParsed.Scheme = strings.ToLower(executionURLParsed.Scheme)
		executionURLParsed.Host = strings.ToLower(executionURLParsed.Host)
		executionURLParsed.Fragment = ""
		n.ExecutionURL = executionURLParsed.String()
		n.Source = source
		if !sameOrigin(base, n.URL) {
			*coverage = append(*coverage, entry(n, dastsurface.CoverageOutOfScope, "origin"))
			continue
		}
		if n.Method != "GET" && n.Method != "HEAD" {
			*coverage = append(*coverage, entry(n, dastsurface.CoverageSkipped, "discovery_method"))
			continue
		}
		out = append(out, queued{request: n})
	}
	return out
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

func parseObservation(base *url.URL, o ports.DASTObservation) []dastsurface.Request {
	return append(parseHTML(base, o.URL, o.BodyExcerpt), parseJS(base, o.URL, scriptText(o.BodyExcerpt))...)
}
func resolve(base *url.URL, page, raw string) (dastsurface.Request, bool) {
	u, err := url.Parse(raw)
	if err != nil || raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(strings.ToLower(raw), "javascript:") {
		return dastsurface.Request{}, false
	}
	pageURL, _ := url.Parse(page)
	u = pageURL.ResolveReference(u)
	if !sameOrigin(base, u.String()) {
		return dastsurface.Request{}, false
	}
	r, err := dastsurface.NormalizeRequest("GET", u.String())
	return r, err == nil
}

func parseHTML(base *url.URL, page, body string) []dastsurface.Request {
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var out []dastsurface.Request
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			var attr string
			switch strings.ToLower(n.Data) {
			case "a", "area", "link", "script":
				attr = "href"
				if n.Data == "script" {
					attr = "src"
				}
			case "form":
				for _, a := range n.Attr {
					if strings.EqualFold(a.Key, "action") {
						attr = a.Val
					}
				}
				if attr != "" {
					if r, ok := resolve(base, page, attr); ok {
						r.Method = "POST"
						r.Source = dastsurface.SourceForm
						out = append(out, r)
					}
				}
				attr = ""
			}
			if attr != "" {
				for _, a := range n.Attr {
					if strings.EqualFold(a.Key, attr) {
						if r, ok := resolve(base, page, a.Val); ok {
							out = append(out, r)
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return out
}

var jsEndpoint = regexp.MustCompile(`(?i)["']((?:/|https?://)[^"'\\\s]{1,512})["']`)

func parseJS(base *url.URL, page, body string) []dastsurface.Request {
	var out []dastsurface.Request
	for _, m := range jsEndpoint.FindAllStringSubmatch(body, -1) {
		if r, ok := resolve(base, page, m[1]); ok {
			r.Source = dastsurface.SourceScript
			out = append(out, r)
		}
	}
	return out
}
func parseRobots(doc string) []dastsurface.Request {
	var out []dastsurface.Request
	for _, line := range strings.Split(doc, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), "sitemap") {
			out = append(out, dastsurface.Request{Method: "GET", URL: strings.TrimSpace(value)})
		}
	}
	return out
}

type sitemap struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
	Maps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

func parseSitemap(doc string) []dastsurface.Request {
	var s sitemap
	if xml.Unmarshal([]byte(doc), &s) != nil {
		return nil
	}
	var out []dastsurface.Request
	for _, u := range s.URLs {
		out = append(out, dastsurface.Request{Method: "GET", URL: strings.TrimSpace(u.Loc)})
	}
	for _, u := range s.Maps {
		out = append(out, dastsurface.Request{Method: "GET", URL: strings.TrimSpace(u.Loc)})
	}
	return out
}
func parseOpenAPI(doc string) []dastsurface.Request {
	var raw struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal([]byte(doc), &raw) == nil {
		var out []dastsurface.Request
		for p, methods := range raw.Paths {
			var ms map[string]json.RawMessage
			_ = json.Unmarshal(methods, &ms)
			for method := range ms {
				if method == "get" || method == "head" {
					out = append(out, dastsurface.Request{Method: strings.ToUpper(method), URL: p})
				}
			}
		}
		return out
	}
	var out []dastsurface.Request
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "/") && strings.HasSuffix(line, ":") {
			out = append(out, dastsurface.Request{Method: "GET", URL: strings.TrimSuffix(line, ":")})
		}
	}
	return out
}
func parseGraphQL(doc string) []dastsurface.Request {
	var raw any
	if json.Unmarshal([]byte(doc), &raw) != nil {
		return nil
	}
	encoded, _ := json.Marshal(raw)
	var out []dastsurface.Request
	for _, m := range jsEndpoint.FindAllStringSubmatch(string(encoded), -1) {
		out = append(out, dastsurface.Request{Method: "GET", URL: m[1]})
	}
	return out
}

func scriptText(body string) string {
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return ""
	}
	var parts []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "script") {
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				if child.Type == html.TextNode {
					parts = append(parts, child.Data)
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return strings.Join(parts, "\n")
}
