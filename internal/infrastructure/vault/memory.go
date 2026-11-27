package vault

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MemoryVault is an in-memory ports.CredentialVault for dev/tests. It still ENCRYPTS at
// rest (the map holds ciphertext, not plaintext) so behaviour matches Postgres and a
// heap dump never leaks secrets. Like the Postgres vault it refuses a context without a
// tenant and keys every secret by the caller's tenant, so a test that forgets to bind one
// fails here as it would in production. Not durable across restarts.
type MemoryVault struct {
	cipher *Cipher
	clock  func() time.Time
	mu     sync.RWMutex
	m      map[string]memEntry // key: tenant\x1fengagementID\x1fname
}

type memEntry struct {
	ciphertext string
	created    time.Time
	updated    time.Time
}

var _ ports.CredentialVault = (*MemoryVault)(nil)

// NewMemoryVault builds an in-memory vault over the cipher. clock may be nil (uses
// time.Now); injected in tests for deterministic timestamps.
func NewMemoryVault(cipher *Cipher, clock func() time.Time) *MemoryVault {
	if clock == nil {
		clock = time.Now
	}
	return &MemoryVault{cipher: cipher, clock: clock, m: map[string]memEntry{}}
}

func memKey(tenant, engagementID shared.ID, name string) string {
	return tenant.String() + "\x1f" + engagementID.String() + "\x1f" + name
}

func memTenant(ctx context.Context) (shared.ID, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return "", fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return tenant, nil
}

func (v *MemoryVault) Put(ctx context.Context, engagementID shared.ID, name string, secret []byte) error {
	tenant, err := memTenant(ctx)
	if err != nil {
		return err
	}
	if err := validateName(name); err != nil {
		return err
	}
	ct, err := v.cipher.Seal(secret, aad(engagementID, name))
	if err != nil {
		return err
	}
	now := v.clock().UTC()
	v.mu.Lock()
	defer v.mu.Unlock()
	k := memKey(tenant, engagementID, name)
	e := memEntry{ciphertext: ct, created: now, updated: now}
	if prev, ok := v.m[k]; ok {
		e.created = prev.created // preserve the original creation time on upsert
	}
	v.m[k] = e
	return nil
}

func (v *MemoryVault) Resolve(ctx context.Context, engagementID shared.ID, name string) ([]byte, error) {
	tenant, err := memTenant(ctx)
	if err != nil {
		return nil, err
	}
	v.mu.RLock()
	e, ok := v.m[memKey(tenant, engagementID, name)]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("credential %q: %w", name, shared.ErrNotFound)
	}
	return v.cipher.Open(e.ciphertext, aad(engagementID, name))
}

func (v *MemoryVault) List(ctx context.Context, engagementID shared.ID) ([]ports.CredentialMeta, error) {
	tenant, err := memTenant(ctx)
	if err != nil {
		return nil, err
	}
	prefix := tenant.String() + "\x1f" + engagementID.String() + "\x1f"
	v.mu.RLock()
	defer v.mu.RUnlock()
	var out []ports.CredentialMeta
	for k, e := range v.m {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			out = append(out, ports.CredentialMeta{Name: k[len(prefix):], CreatedAt: e.created, UpdatedAt: e.updated})
		}
	}
	sortMetaByName(out)
	return out, nil
}

func (v *MemoryVault) Delete(ctx context.Context, engagementID shared.ID, name string) error {
	tenant, err := memTenant(ctx)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	k := memKey(tenant, engagementID, name)
	if _, ok := v.m[k]; !ok {
		return fmt.Errorf("credential %q: %w", name, shared.ErrNotFound)
	}
	delete(v.m, k)
	return nil
}
