package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

// uniqueProbeRole creates a role unique to this test run and drops it when the test ends.
//
// Several tests need a real NOSUPERUSER NOBYPASSRLS role, because row level security is a no-op
// for the superuser the suite usually connects as. Roles are cluster-global rather than
// per-database, so a fixed name collides across databases: an aborted run leaves the role owning
// objects in one database, and every later run in every other database on the server then fails
// with "role already exists" or "cannot be dropped because some objects depend on it".
//
// The cleanup opens its OWN connection from the dsn instead of borrowing the test's pool. A test
// body closes its pool with a plain defer, and Go runs deferred functions before t.Cleanup
// callbacks, so a cleanup that used the test's pool ran every statement against a closed pool and
// discarded the error. That leaked six cluster-global roles per run, permanently, because the
// per-run name also removed the self-healing DROP ROLE IF EXISTS that a fixed name gave the next
// run. Owning the connection here makes the drop correct at every call site by construction.
func uniqueProbeRole(t *testing.T, dsn, prefix string) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("probe role suffix: %v", err)
	}
	role := prefix + "_" + hex.EncodeToString(b[:])
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		pool, err := Connect(ctx, dsn)
		if err != nil {
			t.Errorf("probe role %s was not dropped: connect: %v", role, err)
			return
		}
		defer pool.Close()
		// DROP OWNED BY must precede DROP ROLE: the role owns the grants the test gave it, and
		// Postgres refuses to drop a role while anything depends on it.
		if _, err := pool.Exec(ctx, `DROP OWNED BY `+role); err != nil {
			t.Errorf("probe role %s was not dropped: drop owned: %v", role, err)
			return
		}
		if _, err := pool.Exec(ctx, `DROP ROLE IF EXISTS `+role); err != nil {
			t.Errorf("probe role %s was not dropped: %v", role, err)
		}
	})
	return role
}
