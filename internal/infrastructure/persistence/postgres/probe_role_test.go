package postgres

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// uniqueProbeRole returns a role name unique to this test run.
//
// Several tests need a real NOSUPERUSER NOBYPASSRLS role, because RLS is a no-op for the
// superuser the test suite usually connects as. Roles are cluster-global, not per-database, so a
// fixed name leaks across databases: an aborted run leaves the role owning objects in one
// database, and every later run in every other database fails with "role already exists" or
// "cannot be dropped because some objects depend on it". A per-run name removes the collision
// entirely, and the caller still drops what it created.
func uniqueProbeRole(t *testing.T, prefix string) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("probe role suffix: %v", err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
