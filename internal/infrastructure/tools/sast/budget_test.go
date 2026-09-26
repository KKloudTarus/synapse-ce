package sast

import "testing"

// The budget is derived from the memory the process may use, so it closes the monorepo gap on a real runner
// without risking a small one. The floor is the historical default, so an unreadable environment behaves
// exactly as it did before rather than worse.
func TestBudgetForMemoryLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int64
		want  int64
	}{
		{"unknown limit keeps the historical default", 0, minSourceBudget},
		{"negative limit keeps the historical default", -1, minSourceBudget},
		{"a 256 MiB container stays at the floor", 256 << 20, minSourceBudget},
		{"a 512 MiB container stays at the floor", 512 << 20, minSourceBudget},
		{"a 2 GiB runner gets a quarter of a GiB", 2 << 30, 256 << 20},
		{"a 4 GiB runner reaches the ceiling", 4 << 30, maxSourceBudget},
		{"a 256 GiB host is still capped", 256 << 30, maxSourceBudget},
	} {
		if got := budgetFor(tc.limit); got != tc.want {
			t.Errorf("%s: budgetFor(%d) = %d, want %d", tc.name, tc.limit, got, tc.want)
		}
	}
}

// The derived default must always be usable: at or above the historical floor, at or below the ceiling.
func TestDefaultSourceBudgetIsInRange(t *testing.T) {
	got := defaultSourceBudget()
	if got < minSourceBudget || got > maxSourceBudget {
		t.Errorf("derived budget %d is outside [%d, %d]", got, minSourceBudget, maxSourceBudget)
	}
	// Computed once and stable, so two scans in one process cannot disagree about what they covered.
	if again := defaultSourceBudget(); again != got {
		t.Errorf("derived budget is not stable: %d then %d", got, again)
	}
}

// A container limit is what binds in CI, so it must win over the host total whenever it is smaller.
func TestProcessMemoryLimitPrefersTheSmaller(t *testing.T) {
	limit := processMemoryLimit()
	host := hostMemoryTotal()
	if host > 0 && limit > host {
		t.Errorf("the limit %d must not exceed the host total %d", limit, host)
	}
	if cg := cgroupMemoryLimit(); cg > 0 && limit > cg {
		t.Errorf("the limit %d must not exceed the cgroup limit %d", limit, cg)
	}
}
