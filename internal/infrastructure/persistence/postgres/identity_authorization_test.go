package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestIdentityAuthorizationCapacityAndConcurrentCreation(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.tenants(t, "authorization-capacity")
	seedAuthorizationConnection(t, f, "authorization-capacity", now)
	zero := &IdentityFoundationStore{pool: f.runtime, authorizationCapacity: 0}
	if err := zero.CreateIdentityAuthorization(context.Background(), authorizationTransaction("authorization-capacity", "zero", now, now.Add(time.Minute))); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("zero capacity create = %v", err)
	}
	first := &IdentityFoundationStore{pool: f.runtime, authorizationCapacity: 1}
	second := &IdentityFoundationStore{pool: f.runtime, authorizationCapacity: 1}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, store := range []*IdentityFoundationStore{first, second} {
		wg.Add(1)
		go func(i int, store *IdentityFoundationStore) {
			defer wg.Done()
			errs[i] = store.CreateIdentityAuthorization(context.Background(), authorizationTransaction("authorization-capacity", fmt.Sprintf("race-%d", i), now, now.Add(time.Minute)))
		}(i, store)
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		} else if !errors.Is(err, shared.ErrSaturated) {
			t.Fatalf("concurrent create = %v", err)
		}
	}
	if wins != 1 || f.adminCount(t, `SELECT count(*) FROM identity_transactions WHERE tenant_id='authorization-capacity'`) != 1 {
		t.Fatalf("capacity wins=%d", wins)
	}
}

func TestIdentityAuthorizationExpiryWrongCallerAndSingleUseRace(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.tenants(t, "authorization-consume")
	seedAuthorizationConnection(t, f, "authorization-consume", now)
	store := &IdentityFoundationStore{pool: f.runtime, authorizationCapacity: 8}
	expired := authorizationTransaction("authorization-consume", "expired", now, now.Add(time.Second))
	if err := store.CreateIdentityAuthorization(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeIdentityAuthorization(context.Background(), "authorization-consume", expired.StateDigest, expired.CallerNonceDigest, expired.ExpiresAt); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("exact expiry consumed: %v", err)
	}
	v := authorizationTransaction("authorization-consume", "race", now, now.Add(time.Minute))
	if err := store.CreateIdentityAuthorization(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeIdentityAuthorization(context.Background(), "authorization-consume", v.StateDigest, identityDigest("wrong-caller"), now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("wrong caller: %v", err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = store.ConsumeIdentityAuthorization(context.Background(), "authorization-consume", v.StateDigest, v.CallerNonceDigest, now)
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		} else if !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("consume race: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("consume wins=%d", wins)
	}
}

func TestIdentityAuthorizationCleanupIsBoundedAcrossWorkers(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.tenants(t, "authorization-cleanup")
	seedAuthorizationConnection(t, f, "authorization-cleanup", now)
	store := &IdentityFoundationStore{pool: f.runtime, authorizationCapacity: 8}
	for i := 0; i < 3; i++ {
		if err := store.CreateIdentityAuthorization(context.Background(), authorizationTransaction("authorization-cleanup", fmt.Sprintf("expired-%d", i), now.Add(-2*time.Minute), now.Add(time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.runtimeExec("authorization-cleanup", `UPDATE identity_transactions SET expires_at=$2 WHERE tenant_id=$1`, "authorization-cleanup", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	counts := make([]int, 2)
	errs := make([]error, 2)
	for i := range counts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			counts[i], errs[i] = (&IdentityFoundationStore{pool: f.runtime, authorizationCapacity: 8}).CleanupIdentityAuthorizations(context.Background(), "authorization-cleanup", now, 1)
		}(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || counts[0]+counts[1] != 2 || f.adminCount(t, `SELECT count(*) FROM identity_transactions WHERE tenant_id='authorization-cleanup'`) != 1 {
		t.Fatalf("cleanup counts=%v errs=%v", counts, errs)
	}
}

func authorizationTransaction(tenant, id string, created, expires time.Time) ports.IdentityAuthorizationTransaction {
	return ports.IdentityAuthorizationTransaction{ID: shared.ID(id), TenantID: shared.ID(tenant), Purpose: ports.IdentityAuthorizationLogin, ConnectionID: "authorization-connection", ConnectionRevision: 1, StateDigest: identityDigest("state-" + id), NonceDigest: identityDigest("nonce-" + id), CallerNonceDigest: identityDigest("caller-" + id), PKCEVerifierSealed: "sealed", ContextSealed: "context", CreatedAt: created, ExpiresAt: expires}
}

func seedAuthorizationConnection(t *testing.T, f *identityFixture, tenant string, now time.Time) {
	t.Helper()
	if err := f.runtimeExec(tenant, `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name) VALUES($1,'authorization-connection','oidc',$2,'Authorization')`, tenant, "https://authorization-"+tenant); err != nil {
		t.Fatal(err)
	}
	if err := f.runtimeExec(tenant, `INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor,created_at) VALUES($1,'authorization-connection',1,'{}','test',$2)`, tenant, now); err != nil {
		t.Fatal(err)
	}
}
