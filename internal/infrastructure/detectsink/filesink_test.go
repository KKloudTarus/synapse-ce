package detectsink

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
)

func validDetection(t *testing.T) detection.Detection {
	t.Helper()
	r, ok := detection.Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("expected det.process_enumeration in the catalogue")
	}
	ev := detection.Event{Class: detection.ClassProcess, At: time.Unix(1, 0), Host: "h",
		Process: &detection.ProcessEvent{PID: 1, Comm: "ps", Path: "/usr/bin/ps"}}
	d, err := detection.NewDetection(r, "host-1", "agent:1", []detection.Event{ev}, time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestFileSinkAppendsJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "detections.jsonl")
	s, err := New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	d := validDetection(t)
	if err := s.Emit(context.Background(), d); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := s.Emit(context.Background(), d); err != nil {
		t.Fatalf("emit 2: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var got detection.Detection
		if err := json.Unmarshal(sc.Bytes(), &got); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", n, err)
		}
		if got.RuleID != "det.process_enumeration" {
			t.Errorf("line %d wrong rule: %q", n, got.RuleID)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("want 2 JSON lines, got %d", n)
	}
}

func TestFileSinkRefusesInvalidDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "detections.jsonl")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// A zero detection has no attribution and must be refused, not written.
	if err := s.Emit(context.Background(), detection.Detection{}); err == nil {
		t.Fatal("an invalid detection must be refused")
	}
	fi, _ := os.Stat(path)
	if fi.Size() != 0 {
		t.Fatalf("nothing should have been written, file is %d bytes", fi.Size())
	}
}

func TestNewRejectsEmptyPath(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("empty path must be rejected")
	}
}
