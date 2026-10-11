package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMigration0203InboundWebhookPayloadDedupe(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 203, 202)
	if err := goose.UpTo(isolated.db, ".", 203); err != nil {
		t.Fatal(err)
	}
	requireMigrationIndexes(t, isolated.db, "inbound_webhook_events_payload_unique")
	if err := goose.DownTo(isolated.db, ".", 202); err != nil {
		t.Fatal(err)
	}
	var columns int
	if err := isolated.db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name='inbound_webhook_events' AND column_name='payload_sha256'`).Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("payload column after rollback=%d err=%v", columns, err)
	}
}

type atomicWebhookFixture struct {
	*rls817Fixture
	store *InboundWebhookRepository
	id    ports.InboundWebhookIdentity
	queue *JobQueue
	kind  string
}

func newAtomicWebhookFixture(t *testing.T) atomicWebhookFixture {
	t.Helper()
	f := newRLS817Fixture(t)
	owner := "atomic-gitlab-" + randHex(t)
	public := strings.Repeat("w", 32) + randHex(t)
	ctx := context.Background()
	if _, err := f.owner.Exec(ctx, `INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,enabled,created_at,updated_at) VALUES($1,$2,'gitlab','Atomic hook','https://gitlab.com/atomic',true,now(),now())`, owner, rls817TenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(ctx, `INSERT INTO inbound_webhook_endpoints(public_id,tenant_id,owner_kind,owner_id,enabled,current_version,current_sealed,rate_per_minute) VALUES($1,$2,'integration',$3,true,1,'sealed-placeholder',60)`, public, rls817TenantA, owner); err != nil {
		t.Fatal(err)
	}
	kind := "test.webhook." + owner
	t.Cleanup(func() {
		_, _ = f.owner.Exec(context.Background(), "DELETE FROM jobs WHERE kind=$1", kind)
		_, _ = f.owner.Exec(context.Background(), "DELETE FROM inbound_webhook_endpoints WHERE public_id=$1", public)
		_, _ = f.owner.Exec(context.Background(), "DELETE FROM integrations WHERE id=$1", owner)
	})
	return atomicWebhookFixture{rls817Fixture: f, store: NewInboundWebhookRepository(f.runtime), id: ports.InboundWebhookIdentity{PublicID: public, TenantID: rls817TenantA, OwnerKind: "integration", OwnerID: owner}, queue: NewJobQueue(f.runtime, idgen.RandomID{}), kind: kind}
}

func atomicWebhookEvent(id string) ports.InboundWebhookEvent {
	digest := sha256.Sum256([]byte("authenticated-body"))
	return ports.InboundWebhookEvent{Provider: "gitlab", EventID: id, PayloadSHA256: hex.EncodeToString(digest[:])}
}

func (f atomicWebhookFixture) enqueue(ctx context.Context) error {
	_, err := f.queue.Enqueue(ctx, f.kind, []byte("queued-webhook-scan"))
	return err
}

func (f atomicWebhookFixture) assertCounts(t *testing.T, events, jobs int) {
	t.Helper()
	err := WithTenant(context.Background(), f.runtime, f.id.TenantID.String(), func(tx pgx.Tx) error {
		var gotEvents, gotJobs int
		if err := tx.QueryRow(context.Background(), `SELECT count(*) FROM inbound_webhook_events WHERE public_id=$1`, f.id.PublicID).Scan(&gotEvents); err != nil {
			return err
		}
		if err := tx.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE kind=$1`, f.kind).Scan(&gotJobs); err != nil {
			return err
		}
		if gotEvents != events || gotJobs != jobs {
			t.Errorf("committed events/jobs=%d/%d, want %d/%d", gotEvents, gotJobs, events, jobs)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInboundWebhookEnqueueAndDedupeCommitTogether(t *testing.T) {
	f := newAtomicWebhookFixture(t)
	ctx := shared.WithTenant(context.Background(), f.id.TenantID)
	event := atomicWebhookEvent("delivery-1")
	failure := errors.New("receiver failed after inserting queue job")
	processed, err := f.store.ProcessInboundWebhookEvent(ctx, f.id, event, func(txCtx context.Context) error {
		if err := f.enqueue(txCtx); err != nil {
			return err
		}
		return failure
	})
	if processed || !errors.Is(err, failure) {
		t.Fatalf("failed processing=%v err=%v", processed, err)
	}
	f.assertCounts(t, 0, 0)
	processed, err = f.store.ProcessInboundWebhookEvent(ctx, f.id, event, f.enqueue)
	if !processed || err != nil {
		t.Fatalf("redelivery=%v err=%v", processed, err)
	}
	f.assertCounts(t, 1, 1)
	// Neither an exact delivery retry nor a changed unsigned ID creates new work.
	for _, id := range []string{"delivery-1", "forged-delivery-2"} {
		event.EventID = id
		processed, err = f.store.ProcessInboundWebhookEvent(ctx, f.id, event, func(context.Context) error { t.Error("replay invoked receiver"); return nil })
		if processed || err != nil {
			t.Fatalf("replay=%v err=%v", processed, err)
		}
	}
	f.assertCounts(t, 1, 1)
}

func TestInboundWebhookCanceledCommitRemainsRetryable(t *testing.T) {
	f := newAtomicWebhookFixture(t)
	ctx, cancel := context.WithCancel(shared.WithTenant(context.Background(), f.id.TenantID))
	defer cancel()
	event := atomicWebhookEvent("canceled-delivery")
	processed, err := f.store.ProcessInboundWebhookEvent(ctx, f.id, event, func(txCtx context.Context) error {
		if err := f.enqueue(txCtx); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if processed || err == nil {
		t.Fatalf("canceled commit=%v err=%v", processed, err)
	}
	f.assertCounts(t, 0, 0)
	processed, err = f.store.ProcessInboundWebhookEvent(context.Background(), f.id, event, f.enqueue)
	if !processed || err != nil {
		t.Fatalf("retry=%v err=%v", processed, err)
	}
	f.assertCounts(t, 1, 1)
}

func TestInboundWebhookLostConnectionRollsBackClaimAndQueue(t *testing.T) {
	f := newAtomicWebhookFixture(t)
	event := atomicWebhookEvent("crashed-delivery")
	processed, err := f.store.ProcessInboundWebhookEvent(context.Background(), f.id, event, func(txCtx context.Context) error {
		if err := f.enqueue(txCtx); err != nil {
			return err
		}
		tx, ok, err := contextTenantTx(txCtx, f.id.TenantID)
		if err != nil || !ok {
			return errors.New("missing callback transaction")
		}
		var pid int
		if err := tx.QueryRow(txCtx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			return err
		}
		_, err = f.owner.Exec(context.Background(), "SELECT pg_terminate_backend($1)", pid)
		return err
	})
	if processed || err == nil {
		t.Fatalf("lost connection=%v err=%v", processed, err)
	}
	f.assertCounts(t, 0, 0)
	processed, err = f.store.ProcessInboundWebhookEvent(context.Background(), f.id, event, f.enqueue)
	if !processed || err != nil {
		t.Fatalf("crash retry=%v err=%v", processed, err)
	}
	f.assertCounts(t, 1, 1)
}

func TestInboundWebhookConcurrentPayloadReplaysEnqueueOnce(t *testing.T) {
	f := newAtomicWebhookFixture(t)
	var calls atomic.Int32
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			event := atomicWebhookEvent(strings.Repeat("x", i+1))
			_, err := f.store.ProcessInboundWebhookEvent(context.Background(), f.id, event, func(ctx context.Context) error { calls.Add(1); return f.enqueue(ctx) })
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("receiver calls=%d, want 1", calls.Load())
	}
	f.assertCounts(t, 1, 1)
}

func TestGitLabConcurrentBindingsAdmitOnlyOneProject(t *testing.T) {
	f := newAtomicWebhookFixture(t)
	projectID := "atomic-project-" + randHex(t)
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO projects(id,tenant_id,name,key,source_binding) VALUES($1,$2,'Atomic project',$1,'{}')`, projectID, f.id.TenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.owner.Exec(context.Background(), "DELETE FROM integration_bindings WHERE integration_id=$1", f.id.OwnerID)
		_, _ = f.owner.Exec(context.Background(), "DELETE FROM projects WHERE id=$1", projectID)
	})
	store := NewIntegrationStore(f.runtime, nil)
	ctx := shared.WithTenant(context.Background(), f.id.TenantID)
	start := make(chan struct{})
	results := make(chan error, 8)
	for i := range 8 {
		go func() {
			<-start
			now := time.Now().UTC()
			binding := integration.Binding{ID: shared.ID("gitlab-binding-" + randHex(t)), TenantID: f.id.TenantID, IntegrationID: shared.ID(f.id.OwnerID), ProjectID: shared.ID(projectID), ExternalKey: fmt.Sprintf("org/repo%d", i), ExternalName: "Repo", Version: 1, CreatedAt: now, UpdatedAt: now}
			results <- store.CreateIntegrationBinding(ctx, binding, integrationMutationAudit("integration.binding_created", binding.ID, now))
		}()
	}
	close(start)
	accepted := 0
	for range 8 {
		err := <-results
		if err == nil {
			accepted++
		} else if !errors.Is(err, shared.ErrConflict) {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted=%d want=1", accepted)
	}
}
