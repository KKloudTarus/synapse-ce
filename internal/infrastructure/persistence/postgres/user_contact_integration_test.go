package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/usercontacts"
	"github.com/jackc/pgx/v5"
)

type contactTestClock struct{ now time.Time }

func (c *contactTestClock) Now() time.Time { return c.now }

type contactTestMailer struct{ recipient, code string }

func (m *contactTestMailer) SendContactVerification(_ context.Context, recipient, code string, _ shared.ID) ports.NotificationSendResult {
	m.recipient, m.code = recipient, code
	return ports.NotificationSendResult{StatusCode: 250}
}

func TestUserContactVerificationDurableScopedAndSingleUse(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 180, nil)
	ctx := context.Background()
	for _, id := range []string{"contact-a", "contact-b"} {
		if _, err := db.Exec(`INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES($1,$1,'consultant',$1,'default')`, id); err != nil {
			t.Fatal(err)
		}
	}
	cipher, err := vault.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	clock := &contactTestClock{now: time.Now().UTC()}
	mailer := &contactTestMailer{}
	svc, err := usercontacts.NewService(NewUserContactStore(pool), NewUserRepository(pool), cipher, mailer, idgen.RandomID{}, clock, usercontacts.DeriveVerifierKey("test-only-master"), true)
	if err != nil {
		t.Fatal(err)
	}
	a, b := shared.ID("contact-a"), shared.ID("contact-b")
	contact, err := svc.AddEmail(ctx, shared.DefaultTenant, a, "Alice+tag@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	if contact.Value != "Alice+tag@example.com" || contact.VerifiedAt != nil {
		t.Fatalf("unsafe initial contact: %+v", contact)
	}
	others, err := svc.List(ctx, shared.DefaultTenant, b)
	if err != nil || len(others) != 0 {
		t.Fatalf("same-tenant contact disclosure: %+v %v", others, err)
	}
	if err := svc.RequestVerification(ctx, shared.DefaultTenant, b, contact.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-user challenge: %v", err)
	}
	if err := svc.RequestVerification(ctx, shared.DefaultTenant, a, contact.ID); err != nil {
		t.Fatal(err)
	}
	var job ports.QueuedJob
	if err := WithTenant(ctx, pool, shared.DefaultTenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id,tenant_id,kind,payload FROM jobs WHERE kind=$1`, usercontacts.JobKind).Scan(&job.ID, &job.TenantID, &job.Kind, &job.Payload)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(job.Payload), contact.Value) || len(job.Payload) > 120 {
		t.Fatalf("job contains destination or excessive data: %s", job.Payload)
	}
	if err := svc.HandleJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if mailer.recipient != contact.Value || len(mailer.code) != 8 {
		t.Fatalf("verification mail went to wrong recipient: %q", mailer.recipient)
	}
	if _, err := svc.Verify(ctx, shared.DefaultTenant, b, contact.ID, mailer.code); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-user verification: %v", err)
	}
	if _, err := svc.Verify(ctx, shared.DefaultTenant, a, contact.ID, "00000000"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("wrong code: %v", err)
	}
	var successes int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.Verify(ctx, shared.DefaultTenant, a, contact.ID, mailer.code); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("single-use challenge accepted %d times", successes)
	}
	if _, err := svc.Verify(ctx, shared.DefaultTenant, a, contact.ID, mailer.code); err == nil {
		t.Fatal("replayed code")
	}
	got, err := svc.List(ctx, shared.DefaultTenant, a)
	if err != nil || len(got) != 1 || got[0].VerifiedAt == nil {
		t.Fatalf("verified contact not visible to owner: %+v %v", got, err)
	}
	if err := svc.Delete(ctx, shared.DefaultTenant, b, contact.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-user delete: %v", err)
	}
	if err := svc.Delete(ctx, shared.DefaultTenant, a, contact.ID); err != nil {
		t.Fatal(err)
	}
}

func TestUserContactResendAndOIDCVersionFences(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 180, nil)
	ctx := context.Background()
	if _, err := db.Exec(`INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES('contact-oidc','OIDC','reviewer','contact-oidc-key','default')`); err != nil {
		t.Fatal(err)
	}
	cipher, err := vault.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	clock := &contactTestClock{now: time.Now().UTC()}
	mailer := &contactTestMailer{}
	svc, err := usercontacts.NewService(NewUserContactStore(pool), NewUserRepository(pool), cipher, mailer, idgen.RandomID{}, clock, usercontacts.DeriveVerifierKey("test-only-master"), true)
	if err != nil {
		t.Fatal(err)
	}
	uid := shared.ID("contact-oidc")
	c, err := svc.AddEmail(ctx, shared.DefaultTenant, uid, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RequestVerification(ctx, shared.DefaultTenant, uid, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RequestVerification(ctx, shared.DefaultTenant, uid, c.ID); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("resend interval: %v", err)
	}
	var first ports.QueuedJob
	readLatest := func() ports.QueuedJob {
		var job ports.QueuedJob
		err := WithTenant(ctx, pool, shared.DefaultTenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT id,tenant_id,kind,payload FROM jobs WHERE kind=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, usercontacts.JobKind).Scan(&job.ID, &job.TenantID, &job.Kind, &job.Payload)
		})
		if err != nil {
			t.Fatal(err)
		}
		return job
	}
	first = readLatest()
	clock.now = clock.now.Add(61 * time.Second)
	if err := svc.RequestVerification(ctx, shared.DefaultTenant, uid, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.HandleJob(ctx, first); err != nil {
		t.Fatal(err)
	}
	if mailer.code != "" {
		t.Fatal("invalidated challenge was sent")
	}
	if err := svc.HandleJob(ctx, readLatest()); err != nil {
		t.Fatal(err)
	}
	if len(mailer.code) != 8 {
		t.Fatal("latest challenge was not delivered")
	}
	if err := svc.Delete(ctx, shared.DefaultTenant, uid, c.ID); err != nil {
		t.Fatal(err)
	}
	mailer.code = ""
	if err := svc.HandleJob(ctx, readLatest()); err != nil || mailer.code != "" {
		t.Fatalf("deleted contact delivery: %q %v", mailer.code, err)
	}

	if err := svc.ImportOIDCEmail(ctx, shared.DefaultTenant, uid, "https://issuer.example", "idp@EXAMPLE.COM"); err != nil {
		t.Fatal(err)
	}
	contacts, err := svc.List(ctx, shared.DefaultTenant, uid)
	if err != nil || len(contacts) != 1 || contacts[0].Value != "idp@example.com" || contacts[0].VerifiedAt == nil || contacts[0].Version != 1 {
		t.Fatalf("OIDC import: %+v %v", contacts, err)
	}
	verifiedAt := *contacts[0].VerifiedAt
	clock.now = clock.now.Add(time.Minute)
	if err := svc.ImportOIDCEmail(ctx, shared.DefaultTenant, uid, "https://issuer.example", "idp@example.com"); err != nil {
		t.Fatal(err)
	}
	contacts, _ = svc.List(ctx, shared.DefaultTenant, uid)
	if contacts[0].Version != 1 || !contacts[0].VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("repeat OIDC login rewrote contact: %+v", contacts[0])
	}
	if err := svc.ImportOIDCEmail(ctx, shared.DefaultTenant, uid, "https://issuer.example", "new@example.com"); err != nil {
		t.Fatal(err)
	}
	contacts, _ = svc.List(ctx, shared.DefaultTenant, uid)
	if contacts[0].Value != "new@example.com" || contacts[0].Version != 2 {
		t.Fatalf("changed IdP email retained old destination: %+v", contacts[0])
	}
	if err := svc.RevokeOIDCEmail(ctx, shared.DefaultTenant, uid, "https://issuer.example"); err != nil {
		t.Fatal(err)
	}
	contacts, _ = svc.List(ctx, shared.DefaultTenant, uid)
	if contacts[0].VerifiedAt != nil || contacts[0].Version != 3 {
		t.Fatalf("unverified IdP claim retained verified contact: %+v", contacts[0])
	}
}
