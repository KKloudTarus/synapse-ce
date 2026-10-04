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
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func TestMigration0221BitbucketWebhookLifecycle(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 221, 220)
	// Upgrade a database already at shipped 0220 through the production entry point.
	// requireIdentityMigrationReadiness is not called here: it asserts the database sits at exactly
	// the identity chain's ceiling (218), which stopped being true once 0219 and 0220 shipped. The
	// identity chain's own conformance test owns that invariant; this test owns the Bitbucket lane.
	if err := Migrate(context.Background(), isolated.dsn); err != nil {
		t.Fatal(err)
	}
	requireIdentityMigrationVersion(t, isolated.db, 221)
	requireMigrationIndexes(t, isolated.db, "inbound_webhook_events_payload_unique", "notification_events_type_recent_idx")
	for _, fn := range []string{"synapse_lock_bitbucket_inbound_webhook(text,text,text)", "synapse_provision_bitbucket_inbound_webhook(text,text,text,text,integer)", "synapse_rotate_bitbucket_inbound_webhook(text,text,text,integer,text,timestamp with time zone)"} {
		var publicExecute bool
		if err := isolated.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE p.oid=$1::regprocedure AND acl.grantee=0 AND acl.privilege_type='EXECUTE')`, fn).Scan(&publicExecute); err != nil {
			t.Fatal(err)
		}
		if publicExecute {
			t.Fatalf("PUBLIC execute on %s", fn)
		}
	}
	if err := goose.DownTo(isolated.db, ".", 220); err != nil {
		t.Fatal(err)
	}
	// The rollback stops at the version below this lane, leaving everything shipped before it intact.
	requireIdentityMigrationVersion(t, isolated.db, 220)
	requireMigrationIndexes(t, isolated.db, "inbound_webhook_events_payload_unique", "notification_events_type_recent_idx")
	var installed bool
	if err := isolated.db.QueryRow(`SELECT to_regprocedure('synapse_lock_bitbucket_inbound_webhook(text,text,text)') IS NOT NULL`).Scan(&installed); err != nil || installed {
		t.Fatalf("function after down=%v err=%v", installed, err)
	}
}

type bitbucketAtomicFixture struct {
	*rls817Fixture
	store *InboundWebhookRepository
	id    ports.InboundWebhookIdentity
	queue *JobQueue
	kind  string
}

func newBitbucketAtomicFixture(t *testing.T) bitbucketAtomicFixture {
	t.Helper()
	f := newRLS817Fixture(t)
	owner := "atomic-bitbucket-" + randHex(t)
	public := strings.Repeat("w", 32) + randHex(t)
	ctx := context.Background()
	if _, err := f.owner.Exec(ctx, `INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,enabled,created_at,updated_at) VALUES($1,$2,'bitbucket','Atomic hook','https://bitbucket.org/atomic',true,now(),now())`, owner, rls817TenantA); err != nil {
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
	return bitbucketAtomicFixture{rls817Fixture: f, store: NewInboundWebhookRepository(f.runtime), id: ports.InboundWebhookIdentity{PublicID: public, TenantID: rls817TenantA, OwnerKind: "integration", OwnerID: owner}, queue: NewJobQueue(f.runtime, idgen.RandomID{}), kind: kind}
}

type bitbucketTestEvent struct{ EventID, PayloadSHA256 string }

func bitbucketAtomicEvent(id string) bitbucketTestEvent {
	digest := sha256.Sum256([]byte("authenticated-body"))
	return bitbucketTestEvent{EventID: id, PayloadSHA256: hex.EncodeToString(digest[:])}
}

func (f bitbucketAtomicFixture) enqueue(ctx context.Context) error {
	_, err := f.queue.Enqueue(ctx, f.kind, []byte("queued-webhook-scan"))
	return err
}

func (f bitbucketAtomicFixture) assertCounts(t *testing.T, events, jobs int) {
	t.Helper()
	err := WithTenant(context.Background(), f.runtime, f.id.TenantID.String(), func(tx pgx.Tx) error {
		var gotEvents, gotJobs int
		if err := tx.QueryRow(context.Background(), `SELECT count(*) FROM inbound_webhook_events WHERE public_id=$1`, f.id.PublicID).Scan(&gotEvents); err != nil {
			return err
		}
		if err := tx.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE kind=$1`, f.kind).Scan(&gotJobs); err != nil {
			return err
		}
		if gotEvents != 2*events || gotJobs != jobs {
			t.Errorf("committed events/jobs=%d/%d, want %d/%d", gotEvents, gotJobs, events, jobs)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBitbucketWebhookEnqueueAndDedupeCommitTogether(t *testing.T) {
	f := newBitbucketAtomicFixture(t)
	ctx := shared.WithTenant(context.Background(), f.id.TenantID)
	event := bitbucketAtomicEvent("delivery-1")
	failure := errors.New("receiver failed after inserting queue job")
	processed, err := f.store.AcceptBitbucketWebhook(ctx, f.id, event.EventID, event.PayloadSHA256, func(txCtx context.Context) error {
		if err := f.enqueue(txCtx); err != nil {
			return err
		}
		return failure
	})
	if processed || !errors.Is(err, failure) {
		t.Fatalf("failed processing=%v err=%v", processed, err)
	}
	f.assertCounts(t, 0, 0)
	processed, err = f.store.AcceptBitbucketWebhook(ctx, f.id, event.EventID, event.PayloadSHA256, f.enqueue)
	if !processed || err != nil {
		t.Fatalf("redelivery=%v err=%v", processed, err)
	}
	f.assertCounts(t, 1, 1)
	// Neither an exact delivery retry nor a changed unsigned ID creates new work.
	for _, id := range []string{"delivery-1", "forged-delivery-2"} {
		event.EventID = id
		processed, err = f.store.AcceptBitbucketWebhook(ctx, f.id, event.EventID, event.PayloadSHA256, func(context.Context) error { t.Error("replay invoked receiver"); return nil })
		if processed || err != nil {
			t.Fatalf("replay=%v err=%v", processed, err)
		}
	}
	f.assertCounts(t, 1, 1)
}

func TestBitbucketWebhookCanceledCommitRemainsRetryable(t *testing.T) {
	f := newBitbucketAtomicFixture(t)
	ctx, cancel := context.WithCancel(shared.WithTenant(context.Background(), f.id.TenantID))
	defer cancel()
	event := bitbucketAtomicEvent("canceled-delivery")
	processed, err := f.store.AcceptBitbucketWebhook(ctx, f.id, event.EventID, event.PayloadSHA256, func(txCtx context.Context) error {
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
	processed, err = f.store.AcceptBitbucketWebhook(context.Background(), f.id, event.EventID, event.PayloadSHA256, f.enqueue)
	if !processed || err != nil {
		t.Fatalf("retry=%v err=%v", processed, err)
	}
	f.assertCounts(t, 1, 1)
}

func TestBitbucketWebhookLostConnectionRollsBackClaimAndQueue(t *testing.T) {
	f := newBitbucketAtomicFixture(t)
	event := bitbucketAtomicEvent("crashed-delivery")
	processed, err := f.store.AcceptBitbucketWebhook(context.Background(), f.id, event.EventID, event.PayloadSHA256, func(txCtx context.Context) error {
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
	processed, err = f.store.AcceptBitbucketWebhook(context.Background(), f.id, event.EventID, event.PayloadSHA256, f.enqueue)
	if !processed || err != nil {
		t.Fatalf("crash retry=%v err=%v", processed, err)
	}
	f.assertCounts(t, 1, 1)
}

func TestBitbucketWebhookConcurrentPayloadReplaysEnqueueOnce(t *testing.T) {
	f := newBitbucketAtomicFixture(t)
	var calls atomic.Int32
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			event := bitbucketAtomicEvent(strings.Repeat("x", i+1))
			_, err := f.store.AcceptBitbucketWebhook(context.Background(), f.id, event.EventID, event.PayloadSHA256, func(ctx context.Context) error { calls.Add(1); return f.enqueue(ctx) })
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

func TestBitbucketConcurrentBindingsAdmitOnlyOneProject(t *testing.T) {
	f := newBitbucketAtomicFixture(t)
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
			binding := integration.Binding{ID: shared.ID("bitbucket-binding-" + randHex(t)), TenantID: f.id.TenantID, IntegrationID: shared.ID(f.id.OwnerID), ProjectID: shared.ID(projectID), ExternalKey: fmt.Sprintf("org/repo%d", i), ExternalName: "Repo", Version: 1, CreatedAt: now, UpdatedAt: now}
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

func TestBitbucketWebhookHostileTenantAndLifecycle(t *testing.T) {
	f := newBitbucketAtomicFixture(t)
	digest := bitbucketAtomicEvent("event").PayloadSHA256
	forged := f.id
	forged.TenantID = rls817TenantB
	called := false
	accepted, err := f.store.AcceptBitbucketWebhook(context.Background(), forged, "11111111-1111-1111-1111-111111111111", digest, func(context.Context) error { called = true; return nil })
	if accepted || err == nil || called {
		t.Fatalf("cross tenant accepted=%v err=%v callback=%v", accepted, err, called)
	}
	forged = f.id
	forged.OwnerID = "different-owner"
	accepted, err = f.store.AcceptBitbucketWebhook(context.Background(), forged, "11111111-1111-1111-1111-111111111111", digest, func(context.Context) error { called = true; return nil })
	if accepted || err == nil || called {
		t.Fatal("forged owner accepted")
	}
	f.assertCounts(t, 0, 0)
	owner := "bb-provision-" + randHex(t)
	public := strings.Repeat("b", 32) + randHex(t)
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,enabled,created_at,updated_at) VALUES($1,$2,'bitbucket','Lifecycle','https://bitbucket.org/lifecycle',true,now(),now())`, owner, rls817TenantB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.owner.Exec(context.Background(), "DELETE FROM inbound_webhook_endpoints WHERE public_id=$1", public)
		_, _ = f.owner.Exec(context.Background(), "DELETE FROM integrations WHERE id=$1", owner)
	})
	endpoint := ports.InboundWebhookEndpoint{PublicID: public, TenantID: rls817TenantB, OwnerKind: "integration", OwnerID: owner, Provider: "bitbucket", CurrentVersion: 1, CurrentSealed: "sealed-key-v1", Enabled: true, RatePerMinute: 60}
	accepted, err = f.store.ProvisionInboundWebhook(context.Background(), endpoint)
	if err != nil || !accepted {
		t.Fatalf("provision=%v err=%v", accepted, err)
	}
	identity := ports.InboundWebhookIdentity{PublicID: public, TenantID: rls817TenantB, OwnerKind: "integration", OwnerID: owner}
	rotated, err := f.store.RotateInboundWebhook(context.Background(), identity, 1, "sealed-key-v2", time.Now().Add(time.Hour))
	if err != nil || !rotated {
		t.Fatalf("rotate=%v err=%v", rotated, err)
	}
	stored, found, err := f.store.GetInboundWebhookForOwner(context.Background(), rls817TenantB, "integration", owner)
	if err != nil || !found || stored.CurrentVersion != 2 || stored.PreviousSealed != "sealed-key-v1" || stored.Provider != "bitbucket" {
		t.Fatalf("stored=%+v found=%v err=%v", stored, found, err)
	}
	// A tenant-A session cannot invoke the privileged mutation for tenant B.
	err = requireTenant(context.Background(), f.runtime, rls817TenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT synapse_rotate_bitbucket_inbound_webhook($1,$2,$3,$4,$5,$6)`, rls817TenantB.String(), public, owner, 2, "attacker-key", time.Now().Add(time.Hour)).Scan(&rotated)
	})
	if err != nil || rotated {
		t.Fatalf("hostile rotation=%v err=%v", rotated, err)
	}
}

// Keep the physical queue kind isolated while exercising the production SCA
// serializer and PostgreSQL enqueue transaction.
type bitbucketIsolatedSCAQueue struct {
	*JobQueue
	kind string
}

func (q bitbucketIsolatedSCAQueue) Enqueue(ctx context.Context, _ string, payload []byte) (string, error) {
	return q.JobQueue.Enqueue(ctx, q.kind, payload)
}
func TestBitbucketMultiRefScanAdmissionCommitsEveryQueuedTarget(t *testing.T) {
	f := newBitbucketAtomicFixture(t)
	ctx := shared.WithTenant(context.Background(), f.id.TenantID)
	repoURL := "https://bitbucket.org/trusted/multi-ref.git"
	if _, err := f.owner.Exec(ctx, `UPDATE engagements SET status='active',authorized_from=now()-interval '1 hour',authorized_to=now()+interval '1 hour' WHERE id=$1`, rls817EngA); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(ctx, `INSERT INTO scope_targets(id,tenant_id,engagement_id,in_scope,kind,value) VALUES($1,$2,$3,true,'repo',$4)`, "bb-scope-"+randHex(t), rls817TenantA, rls817EngA, repoURL); err != nil {
		t.Fatal(err)
	}
	jobs := NewScanJobStore(f.runtime)
	svc := scauc.NewService(NewEngagementRepository(f.runtime), nil, nil, nil, jobs, nil, nil, idgen.RandomID{}, ports.Provenance{}, ownershipWallClock{}, ciNotificationAudit{}, shared.SeverityHigh, 0, nil, nil, nil, nil, nil, nil, nil)
	svc.SetQueue(bitbucketIsolatedSCAQueue{JobQueue: f.queue, kind: f.kind})
	for _, fail := range []bool{true, false} {
		event := bitbucketAtomicEvent("multi-ref-delivery")
		accepted, err := f.store.AcceptBitbucketWebhook(ctx, f.id, event.EventID, event.PayloadSHA256, func(txCtx context.Context) error {
			for _, ref := range []string{"feature/one", "feature/two"} {
				if _, err := svc.StartQueuedScanWithOptions(txCtx, "system:bitbucket-webhook", rls817EngA, ports.AcquireRequest{Kind: ports.TargetGit, Value: repoURL, Ref: ref, Commit: strings.Repeat("a", 40)}, scauc.ScanOptions{ProjectAnalysis: true}); err != nil {
					return err
				}
			}
			if fail {
				return errors.New("failure after queuing both branches")
			}
			return nil
		})
		if fail {
			if accepted || err == nil {
				t.Fatal("failed batch committed")
			}
			f.assertCounts(t, 0, 0)
		} else {
			if !accepted || err != nil {
				t.Fatalf("valid multi-ref delivery rejected: %v", err)
			}
			f.assertCounts(t, 1, 2)
		}
	}
	var running int
	if err := f.owner.QueryRow(ctx, `SELECT count(*) FROM scan_jobs WHERE engagement_id=$1 AND status='running'`, rls817EngA).Scan(&running); err != nil || running != 0 {
		t.Fatalf("enqueue reserved scan slot: %d %v", running, err)
	}
}
