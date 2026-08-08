package main

import (
	"context"
	"errors"
	"testing"
	"time"

	dci "github.com/KKloudTarus/synapse-ce/internal/domain/clusterinventory"
)

type fakeSource struct {
	snap dci.Snapshot
	err  error
}

func (f fakeSource) Snapshot(context.Context, string) (dci.Snapshot, error) { return f.snap, f.err }

type fakeSender struct {
	calls int
	token string
	snap  any
	err   error
}

func (f *fakeSender) SendClusterInventory(_ context.Context, token string, snap any) error {
	f.calls++
	f.token = token
	f.snap = snap
	return f.err
}

func sampleSnapshot() dci.Snapshot {
	return dci.Snapshot{
		Cluster: "prod-eu",
		Namespaces: []dci.Namespace{{
			Name:      "payments",
			Workloads: []dci.Workload{{Kind: "Deployment", Name: "api", Containers: []dci.Container{{Name: "api", Image: "reg/api:v1", Digest: "sha256:aaa"}}}},
		}},
	}
}

func TestRunCollectsAndReports(t *testing.T) {
	src := fakeSource{snap: sampleSnapshot()}
	snd := &fakeSender{}
	if err := run(context.Background(), src, snd, "tok", "prod-eu"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if snd.calls != 1 {
		t.Fatalf("the snapshot must be reported exactly once, got %d", snd.calls)
	}
	if snd.token != "tok" {
		t.Fatalf("report must carry the agent token, got %q", snd.token)
	}
	got, ok := snd.snap.(dci.Snapshot)
	if !ok || got.Cluster != "prod-eu" {
		t.Fatalf("the collected snapshot must be sent, got %#v", snd.snap)
	}
}

func TestRunPropagatesCollectError(t *testing.T) {
	snd := &fakeSender{}
	if err := run(context.Background(), fakeSource{err: errors.New("forbidden: pods")}, snd, "tok", "prod-eu"); err == nil {
		t.Fatal("a collection failure must fail loud, not be swallowed")
	}
	if snd.calls != 0 {
		t.Fatal("nothing must be reported when collection fails")
	}
}

func TestRunPropagatesSendError(t *testing.T) {
	snd := &fakeSender{err: errors.New("503")}
	if err := run(context.Background(), fakeSource{snap: sampleSnapshot()}, snd, "tok", "prod-eu"); err == nil {
		t.Fatal("a report failure must surface (so the resync loop logs + retries)")
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
	t.Setenv("SYNAPSE_TEST_DUR", "bad")
	if got := envDuration("SYNAPSE_TEST_DUR", time.Minute); got != time.Minute {
		t.Fatalf("a bad duration must fall back to the default, got %v", got)
	}
}
