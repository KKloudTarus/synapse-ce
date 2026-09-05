package httpapi

import (
	"bytes"
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
