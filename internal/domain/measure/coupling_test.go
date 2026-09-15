package measure

import "testing"

func TestCouplingMetricsAndDirectoryBoundary(t *testing.T) {
	report, err := NewCouplingReport([]CouplingModule{
		{ID: "go:a", Path: "x/a", Language: "go"},
		{ID: "go:b", Path: "x/b", Language: "go"},
		{ID: "go:c", Path: "y/c", Language: "go"},
		{ID: "go:d", Path: "z/d", Language: "go"},
	}, []CouplingEdge{{From: "go:a", To: "go:b"}, {From: "go:a", To: "go:c"}, {From: "go:b", To: "go:c"}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	assert := func(path string, kind NodeKind, ca, ce int, instability *float64) {
		t.Helper()
		m := report.MetricsForPath(path, kind)
		if m.Afferent.Value == nil || *m.Afferent.Value != ca || m.Efferent.Value == nil || *m.Efferent.Value != ce {
			t.Fatalf("%s: got Ca=%v Ce=%v", path, m.Afferent.Value, m.Efferent.Value)
		}
		if instability == nil {
			if m.Instability.Availability != AvailabilityUnavailable {
				t.Fatalf("%s: instability should be unavailable", path)
			}
		} else if m.Instability.Value == nil || *m.Instability.Value != *instability {
			t.Fatalf("%s: instability=%v, want %v", path, m.Instability.Value, *instability)
		}
	}
	one, half, zero := 1.0, 0.5, 0.0
	assert("x/a", NodeDirectory, 0, 2, &one)
	assert("x/b", NodeDirectory, 1, 1, &half)
	assert("y/c", NodeDirectory, 2, 0, &zero)
	assert("z/d", NodeDirectory, 0, 0, nil)
	// x contains a->b internally, so its boundary has one outgoing neighbour (c), not 3.
	assert("x", NodeDirectory, 0, 1, &one)
	if got, ok := report.MaxEfferent(); !ok || got != 2 {
		t.Fatalf("max Ce=(%d,%v), want (2,true)", got, ok)
	}
	if got, ok := report.MaxInstability(); !ok || got != 1 {
		t.Fatalf("max I=(%g,%v), want (1,true)", got, ok)
	}
}

func TestCouplingReportCanonicalizesAndFailsClosed(t *testing.T) {
	report, err := NewCouplingReport(
		[]CouplingModule{{ID: "js:b", Path: "b.ts", Language: "JS-TS"}, {ID: "js:a", Path: "a.ts", Language: "js-ts"}},
		[]CouplingEdge{{From: "js:a", To: "js:b"}, {From: "js:a", To: "js:b"}, {From: "js:a", To: "js:a"}},
		[]CouplingGap{{Language: "JS-TS", Path: "a.ts", Reason: "dynamic_import"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if report.Complete || len(report.Edges) != 1 || report.Modules[0].ID != "js:a" {
		t.Fatalf("unexpected canonical report: %+v", report)
	}
	if m := report.MetricsForPath("a.ts", NodeFile); m.Afferent.Value != nil || m.Afferent.Reason != "coupling_incomplete" {
		t.Fatalf("partial graph exposed a value: %+v", m)
	}
	bad := report
	bad.Complete = true
	if err := bad.Validate(); err == nil {
		t.Fatal("corrupt completeness accepted")
	}
	bad = report
	bad.Gaps[0].Path = "../outside.ts"
	if err := bad.Validate(); err == nil {
		t.Fatal("forged gap path accepted")
	}
	if _, err := NewCouplingReport([]CouplingModule{{ID: "go:a", Path: "../a", Language: "go"}}, nil, nil); err == nil {
		t.Fatal("traversal path accepted")
	}
}
