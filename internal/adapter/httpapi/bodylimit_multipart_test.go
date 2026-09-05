package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
)

// multipartUploadRoutes ties each route that accepts a file upload to the handler function that
// reads it. The middleware ceiling is chosen per route pattern, and nesting an http.MaxBytesReader
// inside the middleware's reader can only tighten the bound, never raise it. A handler that asks
// for 512 MiB while its route sits on the 1 MiB default is therefore capped at 1 MiB, which is the
// regression this table exists to prevent.
var multipartUploadRoutes = map[string]string{
	"createEngagement":     "POST /api/v1/engagements",
	"createProject":        "POST /api/v1/projects",
	"startProjectAnalysis": "POST /api/v1/projects/{key}/analyses",
	"publishProjectSource": "POST /api/v1/projects/{key}/analyses/{id}/source",
}

// TestMultipartRoutesCarryAnUploadCeiling proves every upload route is allowed a body larger than
// the JSON default. Without it the two creation routes silently reject any archive over 1 MiB,
// which is every real archive.
func TestMultipartRoutesCarryAnUploadCeiling(t *testing.T) {
	for handler, pattern := range multipartUploadRoutes {
		t.Run(handler, func(t *testing.T) {
			if got := bodyLimitFor(pattern); got <= defaultBodyLimit {
				t.Errorf("%s is registered at %q with a %d byte ceiling; an upload route needs an entry in routeBodyLimits", handler, pattern, got)
			}
		})
	}
}

// TestEveryMultipartHandlerIsAccountedFor makes the table above fail loudly when a new upload
// handler is added, rather than letting it inherit a ceiling that silently truncates its uploads.
func TestEveryMultipartHandlerIsAccountedFor(t *testing.T) {
	found := map[string]bool{}
	for _, file := range []string{"engagement_handler.go", "project_handler.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var current string
		for _, line := range strings.Split(string(src), "\n") {
			if m := regexp.MustCompile(`^func (?:\(rt \*Router\) )?(\w+)\(`).FindStringSubmatch(line); m != nil {
				current = m[1]
			}
			if strings.Contains(line, "ParseMultipartForm(") {
				found[current] = true
			}
		}
	}
	// parseCoverageUpload is a helper called by startProjectAnalysis, which is the registered route.
	delete(found, "parseCoverageUpload")
	found["startProjectAnalysis"] = true

	var unaccounted []string
	for name := range found {
		if _, ok := multipartUploadRoutes[name]; !ok {
			unaccounted = append(unaccounted, name)
		}
	}
	sort.Strings(unaccounted)
	if len(unaccounted) > 0 {
		t.Errorf("handlers read a multipart body but have no route ceiling recorded: %v", unaccounted)
	}
}

// TestUploadRouteAcceptsABodyOverTheJSONDefault drives the real middleware with a multipart body
// larger than defaultBodyLimit and proves the handler receives all of it.
func TestUploadRouteAcceptsABodyOverTheJSONDefault(t *testing.T) {
	for _, pattern := range []string{"POST /api/v1/engagements", "POST /api/v1/projects"} {
		t.Run(pattern, func(t *testing.T) {
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			part, err := mw.CreateFormFile("source", "src.tar.gz")
			if err != nil {
				t.Fatalf("create part: %v", err)
			}
			if _, err := part.Write(bytes.Repeat([]byte("a"), int(defaultBodyLimit)+(1<<20))); err != nil {
				t.Fatalf("write part: %v", err)
			}
			if err := mw.Close(); err != nil {
				t.Fatalf("close writer: %v", err)
			}
			want := int64(body.Len())

			var read int64
			var readErr error
			handler := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The production handlers nest their own, larger reader here.
				r.Body = http.MaxBytesReader(w, r.Body, 600<<20)
				read, readErr = io.Copy(io.Discard, r.Body)
			}))
			req := httptest.NewRequest(http.MethodPost, "/"+fmt.Sprint(strings.Fields(pattern)[1]), bytes.NewReader(body.Bytes()))
			req.Pattern = pattern
			req.Header.Set("Content-Type", mw.FormDataContentType())
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if readErr != nil {
				t.Fatalf("a %d byte upload was rejected: %v", want, readErr)
			}
			if read != want {
				t.Errorf("handler read %d bytes, want %d", read, want)
			}
		})
	}
}

// TestUploadCeilingSurvivesTheRealChain drives the production handler rather than a hand-built
// middleware, because the route ceiling depends on the ORDER of two middlewares and the unit tests
// above set r.Pattern themselves.
//
// annotateRoutePattern must run outside limitRequestBody. Reversed, r.Pattern is still empty when
// the ceiling is chosen, every route silently falls back to the 1 MiB default, and every upload
// route is capped again with no test failing. This drives rt.Handler() end to end so the wiring is
// what is under test.
func TestUploadCeilingSurvivesTheRealChain(t *testing.T) {
	aupStore := newFakeAUPStore()
	aupStore.accepted["1.0"] = aup.Acceptance{Version: "1.0"}
	rt := &Router{
		log: discardLog(),
		auth: NewAuthenticator(func(_ context.Context, token string) (Principal, bool) {
			if token == "operator" {
				return Principal{ID: "operator", Role: "admin", TenantID: "tenant-a"}, true
			}
			return Principal{}, false
		}),
		aup: newTestAUP(aupStore, &fakeAudit{}),
	}
	handler := rt.Handler()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("metadata", `{"name":"Upload","client":"acme"}`); err != nil {
		t.Fatalf("write field: %v", err)
	}
	part, err := mw.CreateFormFile("source", "src.tar.gz")
	if err != nil {
		t.Fatalf("create part: %v", err)
	}
	if _, err := part.Write(bytes.Repeat([]byte("a"), 2<<20)); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer operator")
	rec := httptest.NewRecorder()
	// The engagement service is not wired in this fixture, so reaching the handler with the whole
	// body read is itself the success condition: the handler parses the multipart form first and
	// only then touches the service. A size rejection happens strictly earlier, in the middleware.
	reachedHandler := func() (reached bool) {
		defer func() { reached = recover() != nil }()
		handler.ServeHTTP(rec, req)
		return false
	}()

	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("a 2 MiB source upload was rejected as too large: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "oversized") {
		t.Fatalf("a 2 MiB source upload was rejected as oversized: %s", rec.Body.String())
	}
	if !reachedHandler && rec.Code >= 400 {
		t.Fatalf("the upload never reached the handler: %d %s", rec.Code, rec.Body.String())
	}
}
