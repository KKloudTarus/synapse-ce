// Package dastsurface models the deterministic, bounded DAST application surface.
package dastsurface

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var ignoredQueryKeys = map[string]struct{}{
	"cursor": {}, "limit": {}, "offset": {}, "page": {}, "pagesize": {},
	"jsessionid": {}, "phpsessid": {}, "session": {}, "sessionid": {}, "sid": {}, "token": {},
}

// Request is one discovered request. URL is normalized before it enters a surface.
type Source string

const (
	SourceSeed    Source = "seed"
	SourceHTML    Source = "html"
	SourceForm    Source = "form"
	SourceScript  Source = "script"
	SourceRobots  Source = "robots"
	SourceSitemap Source = "sitemap"
	SourceOpenAPI Source = "openapi"
	SourceGraphQL Source = "graphql"
)

// Request is one discovered request. URL deduplicates; ExecutionURL retains first concrete target.
type Request struct {
	Method       string
	URL          string
	ExecutionURL string
	Source       Source
}

func (r Request) Key() string { return strings.ToUpper(r.Method) + " " + r.URL }

// NormalizeRequest normalizes a URL and removes common pagination/session query
// keys before deduplication. It never performs network I/O.
func NormalizeRequest(method, rawURL string) (Request, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return Request{}, fmt.Errorf("%w: request method is required", shared.ErrValidation)
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !u.IsAbs() || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return Request{}, fmt.Errorf("%w: request URL must be absolute HTTP(S) without userinfo", shared.ErrValidation)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	if u.Path == "." {
		u.Path = "/"
	}
	q := u.Query()
	for key := range q {
		if _, ignored := ignoredQueryKeys[strings.ToLower(key)]; ignored {
			q.Del(key)
		}
	}
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return Request{Method: method, URL: u.String()}, nil
}

// Surface contains unique normalized requests in deterministic order.
type Surface struct{ Requests []Request }

func NewSurface(discovered []Request) (Surface, error) {
	unique := make(map[string]Request, len(discovered))
	for _, request := range discovered {
		normalized, err := NormalizeRequest(request.Method, request.URL)
		if err != nil {
			return Surface{}, err
		}
		if request.ExecutionURL != "" {
			normalized.ExecutionURL = request.ExecutionURL
		}
		normalized.Source = request.Source
		if _, exists := unique[normalized.Key()]; !exists {
			unique[normalized.Key()] = normalized
		}
	}
	requests := make([]Request, 0, len(unique))
	for _, request := range unique {
		requests = append(requests, request)
	}
	sort.Slice(requests, func(i, j int) bool { return requests[i].Key() < requests[j].Key() })
	return Surface{Requests: requests}, nil
}

// CoverageStatus explains whether a discovered request was issued or skipped.
type CoverageStatus string

const (
	CoverageRequested  CoverageStatus = "requested"
	CoverageSkipped    CoverageStatus = "skipped"
	CoverageOutOfScope CoverageStatus = "out_of_scope"
	CoverageLimited    CoverageStatus = "limited"
)

func (s CoverageStatus) Valid() bool {
	switch s {
	case CoverageRequested, CoverageSkipped, CoverageOutOfScope, CoverageLimited:
		return true
	}
	return false
}

// CoverageEntry preserves the decision for one normalized request.
type CoverageEntry struct {
	Request Request
	Status  CoverageStatus
	Reason  string
	Source  Source
}

// Coverage is a deterministic deduplicated surface map. A request may appear once;
// conflicting records fail closed rather than silently choosing a completion state.
type Coverage struct{ Entries []CoverageEntry }

func NewCoverage(entries []CoverageEntry) (Coverage, error) {
	unique := make(map[string]CoverageEntry, len(entries))
	for _, entry := range entries {
		normalized, err := NormalizeRequest(entry.Request.Method, entry.Request.URL)
		if err != nil {
			return Coverage{}, err
		}
		if !entry.Status.Valid() || (entry.Status != CoverageRequested && strings.TrimSpace(entry.Reason) == "") {
			return Coverage{}, fmt.Errorf("%w: coverage status and reason are invalid", shared.ErrValidation)
		}
		entry.Request = normalized
		key := normalized.Key()
		if prior, exists := unique[key]; exists && prior != entry {
			return Coverage{}, fmt.Errorf("%w: conflicting coverage for %s", shared.ErrValidation, key)
		}
		unique[key] = entry
	}
	out := make([]CoverageEntry, 0, len(unique))
	for _, entry := range unique {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Request.Key() < out[j].Request.Key() })
	return Coverage{Entries: out}, nil
}
