package httpapi

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestSSEHandlersReleaseTheWriteDeadline proves a server-sent-event stream outlives the listener's
// write timeout. Go applies WriteTimeout as a deadline from the start of the response, so without
// the release a stream whose own ceiling is longer than the listener timeout is cut off mid-stream,
// silently: the handlers ignore write errors, so nothing is logged and the client just stops
// receiving events.
func TestSSEHandlersReleaseTheWriteDeadline(t *testing.T) {
	const writeTimeout = 150 * time.Millisecond

	stream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		releaseWriteDeadline(w)
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 4; i++ {
			if _, err := w.Write([]byte("data: tick\n\n")); err != nil {
				return
			}
			flusher.Flush()
			time.Sleep(writeTimeout / 2)
		}
	})

	srv := httptest.NewUnstartedServer(stream)
	srv.Config.WriteTimeout = writeTimeout
	srv.Start()
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Four ticks span twice the write timeout, so an unreleased deadline truncates the read.
	scanner := bufio.NewScanner(resp.Body)
	var ticks int
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data:") {
			ticks++
		}
	}
	if ticks != 4 {
		t.Fatalf("read %d events before the stream died, want 4: %v", ticks, scanner.Err())
	}
}

// TestWriteDeadlineTruncatesAStreamWithoutTheRelease is the control: the same stream without the
// release really does get cut off, so the test above is measuring the fix rather than a no-op.
func TestWriteDeadlineTruncatesAStreamWithoutTheRelease(t *testing.T) {
	const writeTimeout = 150 * time.Millisecond

	stream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 4; i++ {
			if _, err := w.Write([]byte("data: tick\n\n")); err != nil {
				return
			}
			flusher.Flush()
			time.Sleep(writeTimeout / 2)
		}
	})

	srv := httptest.NewUnstartedServer(stream)
	srv.Config.WriteTimeout = writeTimeout
	srv.Start()
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	scanner := bufio.NewScanner(resp.Body)
	var ticks int
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data:") {
			ticks++
		}
	}
	if ticks == 4 {
		t.Fatal("the write deadline did not truncate the stream; this control no longer proves anything")
	}
}

// TestEveryStreamingHandlerReleasesTheDeadline keeps a new SSE handler from inheriting the bug.
func TestEveryStreamingHandlerReleasesTheDeadline(t *testing.T) {
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`^func (?:\(rt \*Router\) )?(\w+)\(`)
	for _, entry := range files {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var current string
		bodies := map[string][]string{}
		for _, line := range strings.Split(string(src), "\n") {
			if m := fn.FindStringSubmatch(line); m != nil {
				current = m[1]
			}
			bodies[current] = append(bodies[current], line)
		}
		for handler, lines := range bodies {
			body := strings.Join(lines, "\n")
			if !strings.Contains(body, `"text/event-stream"`) {
				continue
			}
			if !strings.Contains(body, "releaseWriteDeadline(w)") {
				t.Errorf("%s in %s writes an event stream but does not call releaseWriteDeadline; the listener write timeout will cut it off", handler, name)
			}
		}
	}
}
