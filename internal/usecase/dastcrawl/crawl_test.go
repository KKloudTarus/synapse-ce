package dastcrawl

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCrawlSourcesAndSafety(t *testing.T) {
	var contacted []string
	run := func(_ context.Context, requests []dastsurface.Request) (ports.DASTOutcome, error) {
		contacted = append(contacted, requests[0].ExecutionURL)
		body := ""
		if requests[0].URL == "https://app.test/" {
			body = `<a href="/b">b</a><a href="https://outside.test/no">no</a><form action="/submit" method="post"></form><script>fetch('/literal')</script><script>fetch('/' + dynamic)</script>`
		}
		return ports.DASTOutcome{Observations: []ports.DASTObservation{{URL: requests[0].ExecutionURL, BodyExcerpt: body}}}, nil
	}
	result, err := Crawl(context.Background(), Input{Target: "https://app.test", Seeds: []dastsurface.Request{{Method: "GET", URL: "https://app.test/?page=1"}, {Method: "POST", URL: "https://app.test/post"}, {Method: "GET", URL: "https://outside.test/no"}}, Robots: "Sitemap: https://app.test/robots-map", Sitemaps: []string{`<urlset><url><loc>https://app.test/site</loc></url></urlset>`}, OpenAPI: []string{`{"paths":{"/api":{"get":{}},"/write":{"post":{}}}}`}, GraphQL: []string{`{"data":{"url":"/graphql-doc"}}`}}, Limits{}, run)
	if err != nil || result.Incomplete {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	want := []string{"https://app.test/?page=1", "https://app.test/api", "https://app.test/graphql-doc", "https://app.test/robots-map", "https://app.test/site", "https://app.test/b", "https://app.test/literal"}
	if !reflect.DeepEqual(contacted, want) {
		t.Fatalf("contacted=%v want=%v", contacted, want)
	}
	for _, c := range result.Coverage.Entries {
		if c.Status == dastsurface.CoverageOutOfScope && c.Request.URL == "https://outside.test/no" {
			return
		}
	}
	t.Fatal("out-of-scope link was not recorded")
}

func TestCrawlRecordsEngineSkippedRequests(t *testing.T) {
	requested := false
	result, err := Crawl(context.Background(), Input{
		Target: "https://app.test",
		Seeds:  []dastsurface.Request{{Method: "GET", URL: "https://app.test/logout"}},
	}, Limits{}, func(_ context.Context, requests []dastsurface.Request) (ports.DASTOutcome, error) {
		requested = true
		return ports.DASTOutcome{Coverage: dastsurface.Coverage{Entries: []dastsurface.CoverageEntry{{
			Request: requests[0], Status: dastsurface.CoverageSkipped, Reason: "deny_path", Source: requests[0].Source,
		}}}}, nil
	})
	if err != nil || !requested || len(result.Coverage.Entries) != 1 || result.Coverage.Entries[0].Status != dastsurface.CoverageSkipped || result.Coverage.Entries[0].Reason != "deny_path" {
		t.Fatalf("requested=%t result=%+v err=%v", requested, result, err)
	}
	for _, entry := range result.Coverage.Entries {
		if entry.Status == dastsurface.CoverageRequested {
			t.Fatalf("engine-skipped request was reported as requested: %+v", entry)
		}
	}
}

func TestCrawlBoundsAndCancellation(t *testing.T) {
	seed := []dastsurface.Request{{Method: "GET", URL: "https://app.test/a"}, {Method: "GET", URL: "https://app.test/b"}}
	for name, tc := range map[string]struct {
		ctx    context.Context
		limits Limits
		want   string
	}{
		"page":    {context.Background(), Limits{Pages: 1}, "page_or_request_limit"},
		"request": {context.Background(), Limits{Requests: 1}, "page_or_request_limit"},
		"depth":   {context.Background(), Limits{Depth: 1}, ""},
		"cancel":  {func() context.Context { c, cancel := context.WithCancel(context.Background()); cancel(); return c }(), Limits{}, "context_cancelled"},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := Crawl(tc.ctx, Input{Target: "https://app.test", Seeds: seed}, tc.limits, func(_ context.Context, r []dastsurface.Request) (ports.DASTOutcome, error) {
				return ports.DASTOutcome{}, nil
			})
			if err != nil || !result.Incomplete && tc.want != "" || result.Reason != tc.want {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
	started := time.Now()
	result, err := Crawl(context.Background(), Input{Target: "https://app.test", Seeds: seed}, Limits{WallClock: time.Second}, func(ctx context.Context, _ []dastsurface.Request) (ports.DASTOutcome, error) {
		<-ctx.Done()
		return ports.DASTOutcome{}, nil
	})
	if err != nil || !result.Incomplete || result.Reason != "wall_clock" || time.Since(started) > 2*time.Second {
		t.Fatalf("elapsed=%s result=%#v err=%v", time.Since(started), result, err)
	}
}

func TestCrawlPathologicalPaginatorRetainsFirstExecutionURL(t *testing.T) {
	var got []string
	_, err := Crawl(context.Background(), Input{Target: "https://app.test", Seeds: []dastsurface.Request{{Method: "GET", URL: "https://app.test/list?page=1"}, {Method: "GET", URL: "https://app.test/list?page=2"}}}, Limits{}, func(_ context.Context, r []dastsurface.Request) (ports.DASTOutcome, error) {
		got = append(got, r[0].ExecutionURL)
		return ports.DASTOutcome{}, nil
	})
	if err != nil || !reflect.DeepEqual(got, []string{"https://app.test/list?page=1"}) {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestCrawlPropagatesEngineError(t *testing.T) {
	want := errors.New("sandbox unavailable")
	_, err := Crawl(context.Background(), Input{Target: "https://app.test", Seeds: []dastsurface.Request{{Method: "GET", URL: "https://app.test/"}}}, Limits{}, func(context.Context, []dastsurface.Request) (ports.DASTOutcome, error) {
		return ports.DASTOutcome{}, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("err=%v", err)
	}
}
