package postgres

import "testing"

// TestSingletonLockKeyDistinctPerRole covers that the API and the worker get DIFFERENT
// advisory-lock keys, so they coexist (each a singleton in its own role) – while the same
// role yields the same key (a second same-role instance is refused).
func TestSingletonLockKeyDistinctPerRole(t *testing.T) {
	api, worker := singletonLockKey("api"), singletonLockKey("worker")
	if api == worker {
		t.Fatalf("api and worker must get distinct lock keys, both = %d", api)
	}
	if singletonLockKey("api") != api {
		t.Error("the same role must yield the same key (stable)")
	}
}
