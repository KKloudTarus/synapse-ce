package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	dci "github.com/KKloudTarus/synapse-ce/internal/domain/clusterinventory"
)

type fakeSource struct {
	snap dci.Snapshot
	err  error
}

func (f fakeSource) Snapshot(context.Context, string) (dci.Snapshot, error) { return f.snap, f.err }

func TestRunEmitsSnapshotJSON(t *testing.T) {
	src := fakeSource{snap: dci.Snapshot{
		Cluster: "prod-eu",
		Namespaces: []dci.Namespace{{
			Name:      "payments",
			Workloads: []dci.Workload{{Kind: "Deployment", Name: "api", Containers: []dci.Container{{Name: "api", Image: "reg/api:v1", Digest: "sha256:aaa"}}}},
		}},
	}}
	var out bytes.Buffer
	if err := run(context.Background(), src, "prod-eu", &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	var decoded dci.Snapshot
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("output must be valid snapshot JSON: %v", err)
	}
	if decoded.Cluster != "prod-eu" || len(decoded.Namespaces) != 1 {
		t.Fatalf("snapshot not emitted faithfully: %+v", decoded)
	}
	if !strings.Contains(out.String(), "sha256:aaa") {
		t.Fatalf("resolved digest must appear in the emitted inventory")
	}
}

func TestRunPropagatesCollectError(t *testing.T) {
	src := fakeSource{err: errors.New("forbidden: pods")}
	if err := run(context.Background(), src, "prod-eu", &bytes.Buffer{}); err == nil {
		t.Fatal("a collection failure must propagate (fail loud), not be swallowed")
	}
}

func TestSplitCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"a", []string{"a"}},
		{" a , ,b,, c ", []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		got := splitCSV(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("splitCSV(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Fatalf("splitCSV(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestEnvDuration(t *testing.T) {
	t.Setenv("SYNAPSE_TEST_DUR", "30s")
	if got := envDuration("SYNAPSE_TEST_DUR", time.Minute); got != 30*time.Second {
		t.Fatalf("envDuration = %v, want 30s", got)
	}
	t.Setenv("SYNAPSE_TEST_DUR", "not-a-duration")
	if got := envDuration("SYNAPSE_TEST_DUR", time.Minute); got != time.Minute {
		t.Fatalf("a bad duration must fall back to the default, got %v", got)
	}
	if got := envDuration("SYNAPSE_TEST_UNSET_DUR", time.Minute); got != time.Minute {
		t.Fatalf("unset must use the default, got %v", got)
	}
}
