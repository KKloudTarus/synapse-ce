package ownsbom

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// stubFetcher serves POMs from a map, so the resolver can be tested without a network.
type stubFetcher struct {
	poms  map[string][]byte
	calls int32
	warn  []string
}

func (s *stubFetcher) FetchPOM(_ context.Context, group, artifact, version string, _ []string) ([]byte, bool) {
	atomic.AddInt32(&s.calls, 1)
	data, ok := s.poms[pomRelativePath(group, artifact, version)]
	return data, ok
}

func (s *stubFetcher) Warnings() []string { return s.warn }

// A CI runner has no local Maven repository at all. Without a fetcher a Spring-style pom.xml resolves to the
// handful of literal versions it states outright; with one the whole tree resolves, which is the difference
// between reporting almost nothing and reporting the artifacts the build actually uses.
func TestMavenResolvesWithNoLocalRepositoryAtAll(t *testing.T) {
	pom := func(body string) []byte { return []byte(body) }
	fetch := &stubFetcher{poms: map[string][]byte{
		pomRelativePath("com.example", "platform", "1.0.0"): pom(`<project>
  <groupId>com.example</groupId><artifactId>platform</artifactId><version>1.0.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.example</groupId><artifactId>starter</artifactId><version>3.1.0</version></dependency>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.7</version></dependency>
  </dependencies></dependencyManagement></project>`),
		pomRelativePath("com.example", "starter", "3.1.0"): pom(`<project>
  <groupId>com.example</groupId><artifactId>starter</artifactId><version>3.1.0</version>
  <dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency></dependencies></project>`),
		pomRelativePath("org.slf4j", "slf4j-api", "2.0.7"): pom(`<project>
  <groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.7</version></project>`),
	}}

	project := `<project>
  <parent><groupId>com.example</groupId><artifactId>platform</artifactId><version>1.0.0</version><relativePath/></parent>
  <groupId>com.example</groupId><artifactId>service</artifactId><version>0.1.0</version>
  <dependencies><dependency><groupId>com.example</groupId><artifactId>starter</artifactId></dependency></dependencies>
</project>`

	// Point the local repository at a directory that does not exist: nothing is on disk, as on a clean runner.
	t.Setenv("MAVEN_REPO_LOCAL", filepath.Join(t.TempDir(), "absent"))
	dir := t.TempDir()
	path := filepath.Join(dir, "pom.xml")
	if err := os.WriteFile(path, []byte(project), 0o644); err != nil {
		t.Fatal(err)
	}
	in := ParseInput{Dir: dir, Path: path, Content: []byte(project)}

	localOnly, _, err := (Maven{}).Parse(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(localOnly) != 0 {
		t.Fatalf("with no local repository and no fetcher the managed tree must not resolve, got %d", len(localOnly))
	}

	comps, edges, err := (Maven{Fetcher: fetch}).Parse(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range comps {
		names = append(names, c.Name+"@"+c.Version)
	}
	for _, want := range []string{"com.example:starter@3.1.0", "org.slf4j:slf4j-api@2.0.7"} {
		if !contains(names, want) {
			t.Errorf("expected %s from the fetched tree, got %v", want, names)
		}
	}
	if len(edges) == 0 {
		t.Error("the fetched tree must carry dependency edges; completeness reads them as the resolution signal")
	}
}

// The project's own <repositories> are tried before Maven Central. This is what lets an internal artifact be
// fetched from the repository that holds it: asking a public mirror for it instead is what earned a 429 block
// on a live estate, once per module, until the whole run was lost.
func TestProjectRepositoriesArePreferredOverCentral(t *testing.T) {
	var raw mavenPOMXML
	project := `<project>
  <groupId>io.example</groupId><artifactId>service</artifactId><version>0.1</version>
  <repositories>
    <repository><id>internal</id><url>https://nexus.example.com/repository/maven-releases</url></repository>
    <repository><id>unresolved</id><url>https://${env.HOST}/maven</url></repository>
    <repository><id>blank</id><url>   </url></repository>
  </repositories></project>`
	if err := xml.Unmarshal([]byte(project), &raw); err != nil {
		t.Fatal(err)
	}
	repos := projectRepositories(&raw)
	if len(repos) != 1 || repos[0] != "https://nexus.example.com/repository/maven-releases" {
		t.Fatalf("only the resolved repository URL must be collected, got %v", repos)
	}
	ordered := appendCentral(repos, mavenCentralURL)
	if ordered[0] != repos[0] || ordered[len(ordered)-1] != mavenCentralURL {
		t.Errorf("the project's repository must come first and Central last, got %v", ordered)
	}
}

// A coordinate a repository answered "not here" is never asked for again. Re-requesting one is precisely what
// earns a rate-limit block, and it is the behaviour that cost another scanner an entire estate's Java results.
func TestFetcherNeverRepeatsAMissingCoordinate(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	f := newTestFetcher(t, "")
	for i := 0; i < 5; i++ {
		if _, ok := f.FetchPOM(context.Background(), "io.internal", "artifact", "1.0", []string{srv.URL}); ok {
			t.Fatal("a 404 must not report success")
		}
	}
	// One request, not five: the 404 is remembered.
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("a missing coordinate must be requested once, got %d requests", got)
	}
}

// A 429 stops that host for the rest of the scan, is never fatal, and never sleeps for the Retry-After it
// asks for. The scan says the tree is a lower bound instead.
func TestFetcherStopsUsingARateLimitedHost(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Retry-After", "1800")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	f := newTestFetcher(t, "")
	for i := 0; i < 4; i++ {
		f.FetchPOM(context.Background(), "g", fmt.Sprintf("a%d", i), "1.0", []string{srv.URL})
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("a rate-limited host must be asked once, got %d requests", got)
	}
	warnings := strings.Join(f.Warnings(), " | ")
	if !strings.Contains(warnings, "rate-limited") || !strings.Contains(warnings, "lower bound") {
		t.Errorf("the scan must say the host was rate-limited and the tree is a lower bound, got %q", warnings)
	}
	if !strings.Contains(warnings, "1800") {
		t.Errorf("the Retry-After the host asked for belongs in the warning, got %q", warnings)
	}
}

// A fetched POM is cached on disk so a second scan of the same project needs no network.
func TestFetcherCachesToDisk(t *testing.T) {
	var hits int32
	body := `<project><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></project>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	cache := t.TempDir()
	first := newTestFetcher(t, cache)
	if _, ok := first.FetchPOM(context.Background(), "g", "a", "1.0", []string{srv.URL}); !ok {
		t.Fatal("the first fetch must succeed")
	}
	second := newTestFetcher(t, cache)
	data, ok := second.FetchPOM(context.Background(), "g", "a", "1.0", []string{srv.URL})
	if !ok || string(data) != body {
		t.Fatal("the second fetch must be served from the cache")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("the cached POM must not be re-requested, got %d requests", got)
	}
}

// A pom.xml is untrusted input, so a repository URL it names must not be able to point the scan at the
// network it runs inside: loopback, link-local (where a cloud metadata service lives) and private ranges are
// all refused, and so is plain http and a URL carrying credentials.
func TestRepositoryURLPolicyRefusesUnsafeTargets(t *testing.T) {
	for _, raw := range []string{
		"http://repo.maven.apache.org/maven2",      // not https
		"https://127.0.0.1/maven",                  // loopback
		"https://[::1]/maven",                      // loopback v6
		"https://169.254.169.254/latest/meta-data", // instance metadata
		"https://10.1.2.3/maven",                   // RFC 1918
		"https://192.168.0.9/maven",                // RFC 1918
		"https://user:pass@repo.example.com/maven", // embedded credentials
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRepositoryURL(u, false); err == nil {
			t.Errorf("%s must be refused", raw)
		}
	}
	// An operator scanning their own code against their own internal repository opts in explicitly.
	u, _ := url.Parse("https://10.1.2.3/maven")
	if err := validateRepositoryURL(u, true); err != nil {
		t.Errorf("an opted-in private repository must be allowed, got %v", err)
	}
	// The opt-in does NOT re-admit loopback or metadata: those are never a Maven repository.
	for _, raw := range []string{"https://127.0.0.1/maven", "https://169.254.169.254/maven"} {
		u, _ := url.Parse(raw)
		if err := validateRepositoryURL(u, true); err == nil {
			t.Errorf("%s must be refused even with the private opt-in", raw)
		}
	}
}

// A header from a remote host is untrusted text and must not be able to write a paragraph into a warning.
func TestClipHeaderBoundsUntrustedText(t *testing.T) {
	got := clipHeader(strings.Repeat("A", 200) + "\n\nINJECTED")
	if len(got) > 32 {
		t.Errorf("header must be bounded, got %d chars", len(got))
	}
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("control characters must be stripped, got %q", got)
	}
}

// newTestFetcher builds a fetcher whose address policy admits the loopback test server, which is the one
// place the production policy and a test must differ.
func newTestFetcher(t *testing.T, cacheDir string) *HTTPPOMFetcher {
	t.Helper()
	f := NewHTTPPOMFetcher(cacheDir)
	// The production policy refuses loopback even with the private opt-in, deliberately, so a test server that
	// only ever listens there needs the policy relaxed for it. Everything else the fetcher does is unchanged.
	f.validate = func(*url.URL) error { return nil }
	// No test may reach the real Maven Central: a suite that did would be doing the exact thing this file
	// exists to stop. Clearing it leaves only the repositories a test passes in.
	f.central = ""
	return f
}
